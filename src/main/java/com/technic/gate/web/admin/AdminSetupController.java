package com.technic.gate.web.admin;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.RegistrationMode;
import com.technic.gate.domain.Role;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.DatabaseStatusService;
import com.technic.gate.service.GateSettings;
import com.technic.gate.service.GateSettingsService;
import com.technic.gate.service.NginxConfigGenerator;
import com.technic.gate.service.ServiceCatalogService;
import java.lang.management.ManagementFactory;
import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Страница настройки гейта.
 *
 * Собирает то, ради чего иначе пришлось бы лезть на VPS по ssh: политику регистрации,
 * параметры блокировки и сессий, срок хранения журнала, режим обслуживания, состояние
 * PostgreSQL с репликацией и готовый к вставке конфиг Nginx под текущий список сервисов.
 */
@Controller
@RequestMapping("/admin/setup")
@PreAuthorize("hasRole('ADMIN')")
public class AdminSetupController {

    private final GateSettingsService settingsService;
    private final ServiceCatalogService serviceCatalog;
    private final NginxConfigGenerator nginxConfigGenerator;
    private final DatabaseStatusService databaseStatus;
    private final ActivityService activityService;
    private final int serverPort;

    public AdminSetupController(GateSettingsService settingsService,
                                ServiceCatalogService serviceCatalog,
                                NginxConfigGenerator nginxConfigGenerator,
                                DatabaseStatusService databaseStatus,
                                ActivityService activityService,
                                @Value("${server.port}") int serverPort) {
        this.settingsService = settingsService;
        this.serviceCatalog = serviceCatalog;
        this.nginxConfigGenerator = nginxConfigGenerator;
        this.databaseStatus = databaseStatus;
        this.activityService = activityService;
        this.serverPort = serverPort;
    }

    @GetMapping
    public String setup(Model model) {
        GateSettings settings = settingsService.get();
        model.addAttribute("settings", settings);
        model.addAttribute("registrationModes", RegistrationMode.values());
        model.addAttribute("roles", Role.values());
        model.addAttribute("services", serviceCatalog.findAll());
        model.addAttribute("nginxConfig",
                nginxConfigGenerator.generate(serviceCatalog.findEnabled(), settings.publicUrl()));
        model.addAttribute("db", databaseStatus.status());
        model.addAttribute("serverPort", serverPort);
        model.addAttribute("uptime", formatUptime());
        model.addAttribute("heapUsedMb", usedHeapMb());
        model.addAttribute("activePage", "setup");
        return "admin/setup";
    }

    @PostMapping
    public String save(@RequestParam RegistrationMode registrationMode,
                       @RequestParam Role defaultRole,
                       @RequestParam(required = false, defaultValue = "") String autoGrantServices,
                       @RequestParam int maxFailedAttempts,
                       @RequestParam int lockoutMinutes,
                       @RequestParam int passwordMinLength,
                       @RequestParam int sessionTimeoutMinutes,
                       @RequestParam int rememberMeDays,
                       @RequestParam int activityRetentionDays,
                       @RequestParam(defaultValue = "false") boolean logAllowedVerifies,
                       @RequestParam(defaultValue = "false") boolean maintenanceMode,
                       @RequestParam(defaultValue = "false") boolean adminBypassesAccess,
                       @RequestParam(required = false, defaultValue = "") String publicUrl,
                       @RequestParam(required = false, defaultValue = "X-Service-Name") String serviceHeaderName,
                       @AuthenticationPrincipal GateUserDetails actor,
                       RedirectAttributes redirectAttributes) {

        GateSettings updated = new GateSettings(
                registrationMode,
                defaultRole,
                autoGrantServices.trim(),
                clamp(maxFailedAttempts, 0, 100),
                clamp(lockoutMinutes, 1, 1440),
                clamp(passwordMinLength, 4, 128),
                clamp(sessionTimeoutMinutes, 5, 10080),
                clamp(rememberMeDays, 1, 365),
                clamp(activityRetentionDays, 0, 3650),
                logAllowedVerifies,
                maintenanceMode,
                adminBypassesAccess,
                publicUrl.trim(),
                serviceHeaderName.isBlank() ? "X-Service-Name" : serviceHeaderName.trim());

        settingsService.save(updated);

        activityService.event(ActivityType.SETTINGS_UPDATED)
                .user(actor.getUsername(), actor.getId())
                .detail("Обновлены настройки гейта")
                .save();

        redirectAttributes.addFlashAttribute("successMessage", "Настройки сохранены");
        return "redirect:/admin/setup";
    }

    /** Ручная чистка журнала по текущему сроку хранения. */
    @PostMapping("/purge-activity")
    public String purgeActivity(RedirectAttributes redirectAttributes) {
        int removed = activityService.purgeOlderThan(settingsService.get().activityRetentionDays());
        redirectAttributes.addFlashAttribute("successMessage",
                "Удалено записей журнала: " + removed);
        return "redirect:/admin/setup";
    }

    private static int clamp(int value, int min, int max) {
        return Math.max(min, Math.min(max, value));
    }

    private String formatUptime() {
        Duration up = Duration.ofMillis(ManagementFactory.getRuntimeMXBean().getUptime());
        long days = up.toDays();
        long hours = up.toHours() % 24;
        long minutes = up.toMinutes() % 60;
        if (days > 0) {
            return days + " д " + hours + " ч " + minutes + " мин";
        }
        return hours > 0 ? hours + " ч " + minutes + " мин" : minutes + " мин";
    }

    private long usedHeapMb() {
        Runtime runtime = Runtime.getRuntime();
        return (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024);
    }
}
