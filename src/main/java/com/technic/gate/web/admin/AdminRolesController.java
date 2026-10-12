package com.technic.gate.web.admin;

import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.RoleCatalogService;
import com.technic.gate.service.ServiceCatalogService;
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

/**
 * Справочник ролей приложений (Gate Auth §4.5): глобальные роли и роли отдельных сервисов.
 * Приложения получают свой список по {@code /.well-known/gate/apps/{app}/roles}; что роль разрешает,
 * решает само приложение.
 */
@Controller
@RequestMapping("/admin/roles")
@PreAuthorize("hasRole('ADMIN')")
public class AdminRolesController {

    private final RoleCatalogService roleCatalog;
    private final ServiceCatalogService serviceCatalog;

    public AdminRolesController(RoleCatalogService roleCatalog, ServiceCatalogService serviceCatalog) {
        this.roleCatalog = roleCatalog;
        this.serviceCatalog = serviceCatalog;
    }

    @GetMapping
    public String list(Model model) {
        model.addAttribute("rows", roleCatalog.allForAdmin());
        model.addAttribute("version", roleCatalog.version());
        model.addAttribute("activePage", "roles");
        return "admin/roles";
    }

    @GetMapping("/new")
    public String createForm(@RequestParam(required = false) Long serviceId, Model model) {
        model.addAttribute("role", null);
        model.addAttribute("serviceId", serviceId);
        model.addAttribute("allServices", serviceCatalog.findAll());
        model.addAttribute("activePage", "roles");
        return "admin/role-form";
    }

    @GetMapping("/{id}")
    public String editForm(@PathVariable Long id, Model model) {
        var role = roleCatalog.require(id);
        model.addAttribute("role", role);
        model.addAttribute("serviceId", role.getServiceId());
        model.addAttribute("allServices", serviceCatalog.findAll());
        model.addAttribute("activePage", "roles");
        return "admin/role-form";
    }

    @PostMapping
    public String create(@RequestParam String code,
                         @RequestParam String name,
                         @RequestParam(required = false) String description,
                         @RequestParam(required = false) Long serviceId,
                         @RequestParam(defaultValue = "0") int sortOrder,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {
        var role = roleCatalog.create(code, name, description, serviceId, sortOrder, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Роль " + role.getCode() + " создана");
        return "redirect:/admin/roles";
    }

    @PostMapping("/{id}")
    public String update(@PathVariable Long id,
                         @RequestParam String name,
                         @RequestParam(required = false) String description,
                         @RequestParam(defaultValue = "0") int sortOrder,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {
        var role = roleCatalog.update(id, name, description, sortOrder, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Роль " + role.getCode() + " сохранена");
        return "redirect:/admin/roles";
    }

    @PostMapping("/{id}/archive")
    public String setArchived(@PathVariable Long id,
                              @RequestParam boolean archived,
                              @AuthenticationPrincipal GateUserDetails actor,
                              RedirectAttributes redirectAttributes) {
        roleCatalog.setArchived(id, archived, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", archived ? "Роль в архиве" : "Роль возвращена из архива");
        return "redirect:/admin/roles";
    }
}
