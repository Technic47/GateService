package com.technic.gate.web;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.AccessVerifier;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateException;
import jakarta.servlet.http.HttpServletRequest;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Портал — выбор сервиса после входа.
 *
 * Правило «один сервис — сразу в него» живёт только здесь, чтобы вход через форму
 * и заход на /portal руками вели себя одинаково.
 *
 * Админа не перебрасываем автоматически: сервис у него сейчас ровно один, и на редиректе
 * он бы никогда не увидел ссылку на админку. Принудительно показать список может кто угодно
 * через /portal?choose=1.
 */
@Controller
public class PortalController {

    private final AccessVerifier accessVerifier;
    private final ActivityService activityService;

    public PortalController(AccessVerifier accessVerifier, ActivityService activityService) {
        this.accessVerifier = accessVerifier;
        this.activityService = activityService;
    }

    @GetMapping({"/", "/portal"})
    public String portal(@AuthenticationPrincipal GateUserDetails principal,
                         @RequestParam(required = false) String choose,
                         HttpServletRequest request,
                         Model model) {

        List<ProtectedService> services = accessVerifier.accessibleServices(principal.getUsername());

        boolean autoOpen = services.size() == 1
                && choose == null
                && !principal.isAdmin();
        if (autoOpen) {
            ProtectedService only = services.get(0);
            logOpened(principal, only, request);
            return "redirect:" + only.targetUrl();
        }

        model.addAttribute("services", services);
        return "portal";
    }

    /** Явный переход в сервис с портала — нужен, чтобы зафиксировать вход в журнале. */
    @GetMapping("/go/{name}")
    public String open(@PathVariable String name,
                       @AuthenticationPrincipal GateUserDetails principal,
                       HttpServletRequest request) {

        AccessVerifier.Decision decision = accessVerifier.decide(principal.getUsername(), name);
        if (!decision.allowed()) {
            activityService.event(ActivityType.VERIFY_DENIED)
                    .user(principal.getUsername(), principal.getId())
                    .service(name)
                    .failed()
                    .from(request)
                    .detail(decision.reason())
                    .save();
            throw new GateException("Нет доступа к сервису: " + decision.reason());
        }

        logOpened(principal, decision.service(), request);
        return "redirect:" + decision.service().targetUrl();
    }

    private void logOpened(GateUserDetails principal, ProtectedService service,
                           HttpServletRequest request) {
        activityService.event(ActivityType.SERVICE_OPENED)
                .user(principal.getUsername(), principal.getId())
                .service(service.getName())
                .from(request)
                .detail("Переход в " + service.targetUrl())
                .save();
    }
}
