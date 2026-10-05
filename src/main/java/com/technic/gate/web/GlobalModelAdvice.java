package com.technic.gate.web;

import com.technic.gate.security.GateUserDetails;
import com.technic.gate.security.RedirectTargets;
import com.technic.gate.service.GateException;
import com.technic.gate.service.GateSettingsService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Общие для всех страниц атрибуты модели и обработка ожидаемых ошибок.
 *
 * Имя пользователя и признак админа кладутся в модель явно, вместо thymeleaf-extras-springsecurity:
 * лишняя зависимость с собственной привязкой к версии Spring Security, а нужны из неё ровно
 * два значения.
 */
@ControllerAdvice
public class GlobalModelAdvice {

    private static final Logger log = LoggerFactory.getLogger(GlobalModelAdvice.class);

    private final GateSettingsService settingsService;

    public GlobalModelAdvice(GateSettingsService settingsService) {
        this.settingsService = settingsService;
    }

    @ModelAttribute("currentUsername")
    public String currentUsername() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || isAnonymous(auth)) {
            return null;
        }
        return auth.getName();
    }

    @ModelAttribute("currentIsAdmin")
    public boolean currentIsAdmin() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || isAnonymous(auth)) {
            return false;
        }
        return auth.getPrincipal() instanceof GateUserDetails details && details.isAdmin();
    }

    @ModelAttribute("maintenanceMode")
    public boolean maintenanceMode() {
        return settingsService.get().maintenanceMode();
    }

    /**
     * Ошибки бизнес-правил показываем пользователю текстом и возвращаем на ту же страницу.
     * Referer тут — источник удобства, а не безопасности: используем его только как
     * относительный путь внутри приложения.
     */
    @ExceptionHandler(GateException.class)
    public String handleGateException(GateException exception,
                                      HttpServletRequest request,
                                      RedirectAttributes redirectAttributes) {
        log.debug("Отклонено бизнес-правилом: {}", exception.getMessage());
        redirectAttributes.addFlashAttribute("errorMessage", exception.getMessage());
        return "redirect:" + backTo(request);
    }

    private String backTo(HttpServletRequest request) {
        String referer = request.getHeader("Referer");
        String path = null;
        if (referer != null) {
            int schemeEnd = referer.indexOf("://");
            if (schemeEnd > 0) {
                int pathStart = referer.indexOf('/', schemeEnd + 3);
                if (pathStart > 0) {
                    path = referer.substring(pathStart);
                }
            } else {
                path = referer;
            }
        }
        // Вырезанный путь тоже проверяется: из "https://x//evil.com" получился бы "//evil.com".
        return RedirectTargets.isLocalPath(path) ? path : "/portal";
    }

    private static boolean isAnonymous(Authentication auth) {
        return auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()));
    }

    /** Признак, что форму регистрации вообще надо показывать. */
    @ModelAttribute("registrationOpen")
    public boolean registrationOpen() {
        return settingsService.get().registrationOpen();
    }
}
