package com.technic.gate.security;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateSettingsService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

/**
 * Что происходит сразу после успешного входа.
 *
 * Куда вести дальше решает не этот обработчик, а PortalController: правило
 * «один сервис — сразу в него, несколько — показать выбор» должно жить в одном месте,
 * иначе оно разъедется между входом и заходом на портал руками.
 * Исключение — возврат на исходный URL, с которого Nginx отбил пользователя на логин.
 */
@Component
public class GateAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final LoginAttemptService loginAttemptService;
    private final ActivityService activityService;
    private final GateSettingsService settingsService;
    private final ProtectedServiceRepository serviceRepository;

    public GateAuthenticationSuccessHandler(LoginAttemptService loginAttemptService,
                                            ActivityService activityService,
                                            GateSettingsService settingsService,
                                            ProtectedServiceRepository serviceRepository) {
        this.loginAttemptService = loginAttemptService;
        this.activityService = activityService;
        this.settingsService = settingsService;
        this.serviceRepository = serviceRepository;
        setDefaultTargetUrl("/portal");
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String username = authentication.getName();
        loginAttemptService.registerSuccess(username);

        HttpSession session = request.getSession(false);
        if (session != null) {
            int minutes = settingsService.get().sessionTimeoutMinutes();
            if (minutes > 0) {
                session.setMaxInactiveInterval(minutes * 60);
            }
        }

        Long userId = (authentication.getPrincipal() instanceof GateUserDetails details)
                ? details.getId() : null;
        activityService.event(ActivityType.LOGIN_SUCCESS)
                .user(username, userId)
                .from(request)
                .save();

        String target = safeRedirect(request.getParameter("redirect"));
        if (target != null) {
            getRedirectStrategy().sendRedirect(request, response, target);
            return;
        }
        super.onAuthenticationSuccess(request, response, authentication);
    }

    /**
     * Защита от open redirect: принимаем только собственные относительные пути
     * и адреса внутри публичных URL зарегистрированных сервисов. Всё остальное игнорируем
     * и уходим на портал — параметр redirect приходит из URL, им можно управлять снаружи.
     * Как именно сравниваются адреса и почему не строками — в {@link RedirectTargets}.
     */
    private String safeRedirect(String candidate) {
        if (candidate == null || candidate.isBlank()) {
            return null;
        }
        String value = candidate.trim();

        if (RedirectTargets.isLocalPath(value)) {
            return value.startsWith("/login") ? null : value;
        }

        boolean known = serviceRepository.findAll().stream()
                .filter(s -> s.isEnabled())
                .map(s -> s.targetUrl())
                .anyMatch(url -> url != null && !url.isBlank() && RedirectTargets.isWithin(value, url));
        return known ? value : null;
    }
}
