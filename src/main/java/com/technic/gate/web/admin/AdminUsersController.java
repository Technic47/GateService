package com.technic.gate.web.admin;

import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.ServiceCatalogService;
import com.technic.gate.service.UserAdminService;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** CRUD по пользователям, блокировка и выдача доступа к сервисам. */
@Controller
@RequestMapping("/admin/users")
@PreAuthorize("hasRole('ADMIN')")
public class AdminUsersController {

    private final UserAdminService userAdminService;
    private final ServiceCatalogService serviceCatalog;

    public AdminUsersController(UserAdminService userAdminService,
                                ServiceCatalogService serviceCatalog) {
        this.userAdminService = userAdminService;
        this.serviceCatalog = serviceCatalog;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("users", userAdminService.findAll());
        model.addAttribute("allServices", serviceCatalog.findAll());
        model.addAttribute("activePage", "users");
        return "admin/users";
    }

    @GetMapping("/new")
    public String createForm(Model model) {
        model.addAttribute("user", null);
        model.addAttribute("appRoles", Map.of());
        model.addAttribute("allServices", serviceCatalog.findAll());
        model.addAttribute("roles", Role.values());
        model.addAttribute("activePage", "users");
        return "admin/user-form";
    }

    @GetMapping("/{id}")
    public String editForm(@PathVariable Long id, Model model) {
        User user = userAdminService.require(id);
        model.addAttribute("user", user);
        model.addAttribute("grantedIds", user.getServices().stream().map(s -> s.getId()).toList());
        model.addAttribute("appRoles", userAdminService.appRoles(id));
        model.addAttribute("allServices", serviceCatalog.findAll());
        model.addAttribute("roles", Role.values());
        model.addAttribute("activePage", "users");
        return "admin/user-form";
    }

    @PostMapping
    public String create(@RequestParam String username,
                         @RequestParam String password,
                         @RequestParam Role role,
                         @RequestParam(defaultValue = "false") boolean approved,
                         @RequestParam(required = false) Set<Long> serviceIds,
                         @RequestParam Map<String, String> params,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {

        userAdminService.create(username, password, role, approved, serviceIds, appRoles(params),
                actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Пользователь " + username + " создан");
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}")
    public String update(@PathVariable Long id,
                         @RequestParam Role role,
                         @RequestParam(defaultValue = "false") boolean approved,
                         @RequestParam(required = false) Set<Long> serviceIds,
                         @RequestParam Map<String, String> params,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {

        userAdminService.update(id, role, approved, serviceIds, appRoles(params), actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Изменения сохранены");
        return "redirect:/admin/users";
    }

    /** Выдача/отзыв доступа к одному сервису — быстрые чекбоксы прямо в списке. */
    @PostMapping("/{id}/access")
    public String toggleAccess(@PathVariable Long id,
                               @RequestParam(required = false) Set<Long> serviceIds,
                               @AuthenticationPrincipal GateUserDetails actor,
                               RedirectAttributes redirectAttributes) {

        User user = userAdminService.require(id);
        // Роли в приложениях не трогаем (null): в списке есть только чекбоксы доступа.
        userAdminService.update(id, user.getRole(), user.isApproved(), serviceIds, null,
                actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage",
                "Доступы пользователя " + user.getUsername() + " обновлены");
        return "redirect:/admin/users";
    }

    /** Поля формы appRole_<id сервиса> → карта id сервиса → роль. */
    private static Map<Long, String> appRoles(Map<String, String> params) {
        Map<Long, String> roles = new HashMap<>();
        params.forEach((name, value) -> {
            if (name.startsWith("appRole_")) {
                try {
                    roles.put(Long.parseLong(name.substring("appRole_".length())), value);
                } catch (NumberFormatException ignored) {
                    // чужое поле — пропускаем
                }
            }
        });
        return roles;
    }

    @PostMapping("/{id}/block")
    public String setBlocked(@PathVariable Long id,
                             @RequestParam boolean blocked,
                             @AuthenticationPrincipal GateUserDetails actor,
                             RedirectAttributes redirectAttributes) {

        userAdminService.setBlocked(id, blocked, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage",
                blocked ? "Пользователь заблокирован" : "Пользователь разблокирован");
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}/password")
    public String resetPassword(@PathVariable Long id,
                                @RequestParam String newPassword,
                                @AuthenticationPrincipal GateUserDetails actor,
                                RedirectAttributes redirectAttributes) {

        userAdminService.resetPassword(id, newPassword, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Пароль сброшен");
        return "redirect:/admin/users";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable Long id,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {

        userAdminService.delete(id, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Пользователь удалён");
        return "redirect:/admin/users";
    }
}
