package com.technic.gate.web;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.service.AccessVerifier;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateSettingsService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Эндпоинт для Nginx auth_request.
 *
 * Nginx дёргает его перед каждым проксируемым запросом, поэтому ответ должен быть без тела
 * и без редиректов: 200 — пропустить, 401 — отправить на логин, 403 — показать отказ.
 * Решение о том, что делать с 401 и 403, принимает Nginx через error_page.
 *
 * Имя сервиса берётся из заголовка (по умолчанию X-Service-Name); имя заголовка настраивается,
 * потому что менять его в конфиге Nginx проще, чем пересобирать сервис.
 */
@RestController
public class VerifyController {

    private final AccessVerifier accessVerifier;
    private final ActivityService activityService;
    private final GateSettingsService settingsService;

    public VerifyController(AccessVerifier accessVerifier,
                            ActivityService activityService,
                            GateSettingsService settingsService) {
        this.accessVerifier = accessVerifier;
        this.activityService = activityService;
        this.settingsService = settingsService;
    }

    @RequestMapping("/verify")
    public ResponseEntity<Void> verify(@RequestParam(name = "service", required = false) String serviceParam,
                                       HttpServletRequest request) {

        String headerName = settingsService.get().serviceHeaderName();
        String serviceName = request.getHeader(headerName);
        if (serviceName == null || serviceName.isBlank()) {
            serviceName = serviceParam;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = (auth == null || !auth.isAuthenticated() || isAnonymous(auth))
                ? null : auth.getName();

        AccessVerifier.Decision decision = accessVerifier.decide(username, serviceName);

        if (decision.allowed()) {
            if (settingsService.get().logAllowedVerifies()) {
                // По умолчанию выключено: Nginx дёргает /verify на каждый запрос,
                // включая статику, и журнал заполнится за считанные минуты.
                activityService.event(ActivityType.VERIFY_ALLOWED)
                        .user(decision.user())
                        .service(serviceName)
                        .from(request)
                        .detail(originalUri(request))
                        .save();
            }
            return ResponseEntity.ok()
                    .header("X-Gate-User", decision.user().getUsername())
                    .header("X-Gate-Role", decision.user().getRole().name())
                    .build();
        }

        activityService.event(ActivityType.VERIFY_DENIED)
                .user(decision.user())
                .service(serviceName)
                .failed()
                .from(request)
                .detail(decision.reason() + " | " + originalUri(request))
                .save();

        return ResponseEntity.status(
                        decision.status() == 401 ? HttpStatus.UNAUTHORIZED : HttpStatus.FORBIDDEN)
                .header("X-Gate-Reason", asciiSafe(decision.reason()))
                .build();
    }

    private String originalUri(HttpServletRequest request) {
        String uri = request.getHeader("X-Original-URI");
        return uri == null ? "" : uri;
    }

    /**
     * В заголовок HTTP нельзя положить кириллицу: Tomcat кодирует значения в ISO-8859-1,
     * и русский текст причины превратился бы в мусор. В заголовок уходит только ASCII,
     * полная причина остаётся в журнале.
     */
    private String asciiSafe(String value) {
        if (value == null) {
            return "denied";
        }
        String cleaned = value.replaceAll("[^\\x20-\\x7E]", "");
        return cleaned.isBlank() ? "denied" : cleaned;
    }

    private static boolean isAnonymous(Authentication auth) {
        return auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()));
    }
}
