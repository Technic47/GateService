package com.technic.gate.security;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.User;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.ClientInfo;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

/**
 * Неудачный вход: считаем попытку, пишем в журнал, возвращаем на форму с кодом причины.
 *
 * Причина передаётся кодом, а не текстом: сообщение рисует шаблон, и в URL не утекает
 * ничего, что можно подставить снаружи.
 */
@Component
public class GateAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final LoginAttemptService loginAttemptService;
    private final ActivityService activityService;

    public GateAuthenticationFailureHandler(LoginAttemptService loginAttemptService,
                                            ActivityService activityService) {
        this.loginAttemptService = loginAttemptService;
        this.activityService = activityService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String username = request.getParameter("username");
        String ip = ClientInfo.ip(request);

        Optional<User> user = loginAttemptService.registerFailure(username, ip);

        String reason = reasonCode(exception, user.orElse(null));
        activityService.event(ActivityType.LOGIN_FAILURE)
                .user(username, user.map(User::getId).orElse(null))
                .failed()
                .from(request)
                .detail(describe(reason, exception))
                .save();

        String redirect = request.getParameter("redirect");
        StringBuilder target = new StringBuilder("/login?error=").append(reason);
        if (redirect != null && !redirect.isBlank()) {
            target.append("&redirect=")
                    .append(URLEncoder.encode(redirect, StandardCharsets.UTF_8));
        }
        getRedirectStrategy().sendRedirect(request, response, target.toString());
    }

    private String reasonCode(AuthenticationException exception, User user) {
        if (exception instanceof LockedException) {
            return "locked";
        }
        if (exception instanceof DisabledException) {
            // isEnabled() ложно и при ручной блокировке, и при неодобренном аккаунте —
            // различаем по самому пользователю, чтобы показать осмысленный текст.
            if (user != null && !user.isApproved()) {
                return "pending";
            }
            return "blocked";
        }
        if (user != null && user.isTemporarilyLocked()) {
            return "locked";
        }
        return "bad";
    }

    private String describe(String reason, AuthenticationException exception) {
        return switch (reason) {
            case "locked" -> "Временная блокировка после неудачных попыток";
            case "blocked" -> "Аккаунт заблокирован администратором";
            case "pending" -> "Аккаунт ещё не одобрен администратором";
            default -> "Неверный логин или пароль (" + exception.getClass().getSimpleName() + ")";
        };
    }
}
