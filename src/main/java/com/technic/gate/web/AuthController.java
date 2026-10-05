package com.technic.gate.web;

import com.technic.gate.service.GateSettingsService;
import com.technic.gate.service.UserAdminService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** Вход и регистрация — одна страница с двумя формами. */
@Controller
public class AuthController {

    private final UserAdminService userAdminService;
    private final GateSettingsService settingsService;

    public AuthController(UserAdminService userAdminService,
                          GateSettingsService settingsService) {
        this.userAdminService = userAdminService;
        this.settingsService = settingsService;
    }

    @GetMapping("/login")
    public String login(@RequestParam(required = false) String error,
                        @RequestParam(required = false) String logout,
                        @RequestParam(required = false) String registered,
                        @RequestParam(required = false) String pending,
                        @RequestParam(required = false) String redirect,
                        @RequestParam(required = false) String tab,
                        Model model) {

        if (isAuthenticated()) {
            return "redirect:/portal";
        }

        model.addAttribute("errorText", errorText(error));
        model.addAttribute("logout", logout != null);
        model.addAttribute("registered", registered != null);
        model.addAttribute("pending", pending != null);
        model.addAttribute("redirect", redirect);
        // При закрытой регистрации вкладку register не отдаём даже по прямой ссылке —
        // иначе на странице не было бы ни одной формы.
        boolean wantsRegister = "register".equals(tab) && settingsService.get().registrationOpen();
        model.addAttribute("activeTab", wantsRegister ? "register" : "login");
        model.addAttribute("passwordMinLength", settingsService.get().passwordMinLength());
        model.addAttribute("registrationMode", settingsService.get().registrationMode());
        return "login";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username,
                           @RequestParam String password,
                           @RequestParam String confirmPassword,
                           @RequestParam(required = false) String redirect,
                           RedirectAttributes redirectAttributes) {

        // GateException ловится в GlobalModelAdvice и возвращает пользователя сюда же
        // с текстом ошибки — здесь обрабатывается только успешный путь.
        boolean activeNow = userAdminService.register(username, password, confirmPassword);

        StringBuilder target = new StringBuilder("redirect:/login?");
        target.append(activeNow ? "registered=1" : "pending=1");
        if (redirect != null && !redirect.isBlank()) {
            redirectAttributes.addAttribute("redirect", redirect);
        }
        return target.toString();
    }

    /**
     * Подтверждение выхода по обычной ссылке.
     *
     * Пользователь с одним сервисом портал не видит — после входа его сразу уводит в сервис,
     * и кнопки «Выйти» из шапки гейта у него перед глазами нет. Эта страница открывается
     * ссылкой (закладка, кнопка, встроенная Nginx в страницы сервиса), а сам выход — POST
     * на тот же адрес, его обрабатывает LogoutFilter Spring Security.
     */
    @GetMapping("/logout")
    public String logoutPage() {
        return isAuthenticated() ? "logout" : "redirect:/login";
    }

    /** Страница «доступа нет» — сюда Nginx уводит при 403 от /verify. */
    @GetMapping("/denied")
    public String denied(@RequestParam(required = false) String service, Model model) {
        model.addAttribute("serviceName", service);
        return "denied";
    }

    private boolean isAuthenticated() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        return auth != null
                && auth.isAuthenticated()
                && auth.getAuthorities().stream()
                        .noneMatch(a -> "ROLE_ANONYMOUS".equals(a.getAuthority()));
    }

    private String errorText(String code) {
        if (code == null) {
            return null;
        }
        return switch (code) {
            case "locked" -> "Слишком много неудачных попыток. Аккаунт временно заблокирован — "
                    + "попробуйте позже.";
            case "blocked" -> "Аккаунт заблокирован администратором.";
            case "pending" -> "Аккаунт ещё не одобрен администратором.";
            default -> "Неверный логин или пароль.";
        };
    }
}
