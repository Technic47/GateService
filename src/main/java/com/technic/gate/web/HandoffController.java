package com.technic.gate.web;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.service.AccessVerifier;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Optional;
import java.util.regex.Pattern;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.HtmlUtils;

/**
 * Gate Auth, direct mode (§6 спецификации): вход в приложение, открытое из LAN.
 *
 * Приложение отправляет браузер сюда, гейт проверяет сессию (или показывает форму входа)
 * и доступ, а ответ возвращает браузером же — автоотправляемой формой POST на callback
 * приложения. Домашнему серверу не нужно ходить на VPS: обе стороны видит только браузер.
 *
 * Главное правило: на незарегистрированный redirect_uri не уходит ничего, даже ошибка —
 * иначе гейт превратился бы в открытый редирект с подписанными токенами.
 */
@Controller
public class HandoffController {

    private static final Pattern STATE_OR_NONCE = Pattern.compile("[A-Za-z0-9_-]{16,128}");
    private static final String AUTO_SUBMIT_SCRIPT = "document.forms[0].submit();";
    private static final String AUTO_SUBMIT_HASH = sha256Base64(AUTO_SUBMIT_SCRIPT);

    private final ProtectedServiceRepository serviceRepository;
    private final AccessVerifier accessVerifier;
    private final GateTokenService tokenService;
    private final ActivityService activityService;

    public HandoffController(ProtectedServiceRepository serviceRepository,
                             AccessVerifier accessVerifier,
                             GateTokenService tokenService,
                             ActivityService activityService) {
        this.serviceRepository = serviceRepository;
        this.accessVerifier = accessVerifier;
        this.tokenService = tokenService;
        this.activityService = activityService;
    }

    @GetMapping("/auth/handoff")
    public String handoff(@RequestParam(name = "response_type", required = false) String responseType,
                          @RequestParam(name = "response_mode", required = false) String responseMode,
                          @RequestParam(name = "client_id", required = false) String clientId,
                          @RequestParam(name = "redirect_uri", required = false) String redirectUri,
                          @RequestParam(required = false) String state,
                          @RequestParam(required = false) String nonce,
                          @RequestParam(required = false) String prompt,
                          HttpServletRequest request,
                          HttpServletResponse response,
                          Model model) throws IOException {

        // 1. Запрос и получатель. Пока redirect_uri не подтверждён, отвечаем только страницей гейта.
        if (!tokenService.enabled()) {
            return errorPage(model, response, 503, "Вход из локальной сети пока не настроен на гейте.");
        }
        if (!"id_token".equals(responseType) || !"form_post".equals(responseMode)) {
            return errorPage(model, response, 400, "Неверный запрос на вход.");
        }
        Optional<ProtectedService> found = clientId == null ? Optional.empty()
                : serviceRepository.findByNameIgnoreCase(clientId);
        if (found.isEmpty() || !found.get().isEnabled() || !found.get().isDirectEnabled()) {
            denied(clientId, null, "Сервис не найден, отключён или вход из LAN для него выключен", request);
            return errorPage(model, response, 400, "Это приложение не настроено для входа через гейт.");
        }
        ProtectedService service = found.get();
        if (!service.isRegisteredRedirectUri(redirectUri)) {
            denied(service.getName(), null, "Незарегистрированный redirect_uri: " + redirectUri, request);
            return errorPage(model, response, 400,
                    "Адрес возврата не зарегистрирован для приложения " + service.getDisplayName() + ".");
        }
        if (state == null || nonce == null
                || !STATE_OR_NONCE.matcher(state).matches() || !STATE_OR_NONCE.matcher(nonce).matches()) {
            return errorPage(model, response, 400, "Неверный запрос на вход.");
        }
        boolean silent = "none".equals(prompt);

        // 2. Кто пришёл. Нет сессии — на форму входа с возвратом сюда же; при prompt=none формы нет.
        String username = currentUsername();
        AccessVerifier.Decision decision = username == null ? null : accessVerifier.decide(username, service.getName());
        if (decision == null || decision.outcome() == AccessVerifier.Outcome.UNAUTHENTICATED) {
            if (silent) {
                postBack(response, redirectUri, "error", "login_required", state);
                return null;
            }
            // Адрес возврата собирается из уже проверенных параметров, а не из сырого query string:
            // посторонние параметры не переезжают через форму входа.
            String back = "/auth/handoff?response_type=id_token&response_mode=form_post"
                    + "&client_id=" + enc(service.getName())
                    + "&redirect_uri=" + enc(redirectUri)
                    + "&state=" + enc(state)
                    + "&nonce=" + enc(nonce);
            return "redirect:/login?redirect=" + enc(back);
        }

        // 3. Есть ли доступ. Блокировка, отзыв доступа, режим обслуживания — всё это access_denied:
        //    на ответ при повторной проверке приложение закрывает свою сессию в LAN.
        if (!decision.allowed()) {
            denied(service.getName(), decision, decision.reason(), request);
            postBack(response, redirectUri, "error", "access_denied", state);
            return null;
        }

        String token = tokenService.handoff(decision.user(), service, nonce, request);
        activityService.event(ActivityType.HANDOFF_ISSUED)
                .user(decision.user())
                .service(service.getName())
                .from(request)
                .detail((silent ? "Повторная проверка, " : "Вход из LAN, ") + redirectUri)
                .save();
        postBack(response, redirectUri, "id_token", token, state);
        return null;
    }

    /**
     * Страница с одной формой, отправляемой скриптом сразу после загрузки (OAuth 2.0 Form Post
     * Response Mode). Токен уходит телом POST, а не в URL: не оседает в истории, логах и Referer.
     * CSP разрешает ровно этот скрипт (по хешу) и отправку формы только на origin приложения.
     */
    private void postBack(HttpServletResponse response, String redirectUri, String field, String value, String state)
            throws IOException {
        String origin = origin(redirectUri);
        response.setStatus(200);
        response.setContentType("text/html;charset=UTF-8");
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma", "no-cache");
        response.setHeader("Referrer-Policy", "no-referrer");
        response.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'sha256-" + AUTO_SUBMIT_HASH
                + "'; style-src 'unsafe-inline'; form-action " + origin + "; base-uri 'none'; frame-ancestors 'none'");
        response.getWriter().write("<!DOCTYPE html><html lang=\"ru\"><head><meta charset=\"utf-8\">"
                + "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Вход…</title></head>"
                + "<body style=\"font:15px system-ui,sans-serif;text-align:center;padding:15vh 16px\">"
                + "<form method=\"post\" action=\"" + HtmlUtils.htmlEscape(redirectUri) + "\">"
                + "<input type=\"hidden\" name=\"" + field + "\" value=\"" + HtmlUtils.htmlEscape(value) + "\">"
                + "<input type=\"hidden\" name=\"state\" value=\"" + HtmlUtils.htmlEscape(state) + "\">"
                + "<p>Возвращаемся в приложение…</p><button type=\"submit\">Продолжить</button></form>"
                + "<script>" + AUTO_SUBMIT_SCRIPT + "</script></body></html>");
    }

    private String errorPage(Model model, HttpServletResponse response, int status, String message) {
        response.setStatus(status);
        model.addAttribute("message", message);
        return "handoff-error";
    }

    private void denied(String serviceName, AccessVerifier.Decision decision, String reason, HttpServletRequest request) {
        var event = activityService.event(ActivityType.HANDOFF_DENIED)
                .service(serviceName)
                .failed()
                .from(request)
                .detail(reason);
        if (decision != null && decision.user() != null) {
            event.user(decision.user());
        }
        event.save();
    }

    private static String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()
                || auth.getAuthorities().stream().anyMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()))) {
            return null;
        }
        return auth.getName();
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** scheme://host[:port] зарегистрированного адреса — для CSP form-action. */
    static String origin(String uri) {
        URI u = URI.create(uri);
        return u.getScheme() + "://" + u.getHost() + (u.getPort() == -1 ? "" : ":" + u.getPort());
    }

    private static String sha256Base64(String text) {
        try {
            return Base64.getEncoder().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
