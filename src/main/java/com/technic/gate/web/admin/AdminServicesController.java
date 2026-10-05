package com.technic.gate.web.admin;

import com.technic.gate.domain.ProtectedService;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.HealthProbe;
import com.technic.gate.service.ServiceCatalogService;
import java.util.LinkedHashMap;
import java.util.Map;
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

/** Управление списком защищаемых сервисов: адреса, публичные URL, доступность. */
@Controller
@RequestMapping("/admin/services")
@PreAuthorize("hasRole('ADMIN')")
public class AdminServicesController {

    private final ServiceCatalogService serviceCatalog;
    private final HealthProbe healthProbe;

    public AdminServicesController(ServiceCatalogService serviceCatalog, HealthProbe healthProbe) {
        this.serviceCatalog = serviceCatalog;
        this.healthProbe = healthProbe;
    }

    @GetMapping
    public String list(@RequestParam(required = false) String probe, Model model) {
        var services = serviceCatalog.findAll();
        model.addAttribute("services", services);

        // Проверка портов идёт только по явной кнопке: каждый TCP-коннект — до 1.5 секунды,
        // и делать её на каждой отрисовке списка означало бы вешать страницу на ровном месте.
        if (probe != null) {
            Map<Long, HealthProbe.Result> health = new LinkedHashMap<>();
            for (ProtectedService service : services) {
                health.put(service.getId(), healthProbe.check(service));
            }
            model.addAttribute("health", health);
        }
        model.addAttribute("activePage", "services");
        return "admin/services";
    }

    @GetMapping("/new")
    public String createForm(Model model) {
        model.addAttribute("service", null);
        model.addAttribute("activePage", "services");
        return "admin/service-form";
    }

    @GetMapping("/{id}")
    public String editForm(@PathVariable Long id, Model model) {
        model.addAttribute("service", serviceCatalog.require(id));
        model.addAttribute("activePage", "services");
        return "admin/service-form";
    }

    @PostMapping
    public String save(@RequestParam(required = false) Long id,
                       @RequestParam String name,
                       @RequestParam String displayName,
                       @RequestParam(required = false) String description,
                       @RequestParam(defaultValue = "http") String scheme,
                       @RequestParam String host,
                       @RequestParam int port,
                       @RequestParam(required = false) String publicUrl,
                       @RequestParam(defaultValue = "false") boolean enabled,
                       @RequestParam(required = false) String icon,
                       @RequestParam(defaultValue = "0") int sortOrder,
                       @AuthenticationPrincipal GateUserDetails actor,
                       RedirectAttributes redirectAttributes) {

        serviceCatalog.save(id, name, displayName, description, scheme, host, port, publicUrl,
                enabled, icon, sortOrder, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Сервис " + name + " сохранён");
        return "redirect:/admin/services";
    }

    @PostMapping("/{id}/delete")
    public String delete(@PathVariable Long id,
                         @AuthenticationPrincipal GateUserDetails actor,
                         RedirectAttributes redirectAttributes) {

        serviceCatalog.delete(id, actor.getUsername());
        redirectAttributes.addFlashAttribute("successMessage", "Сервис удалён");
        return "redirect:/admin/services";
    }
}
