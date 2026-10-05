package com.technic.gate.web.admin;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.ServiceCatalogService;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * Журнал активности с фильтрами.
 *
 * Страница администратора, а не «просмотрщик логов»: контейнерные логи Dozzle покажет лучше,
 * а здесь нужен срез именно по пользователям и доступам — кто заходил, кому отказали и почему.
 */
@Controller
@RequestMapping("/admin/activity")
@PreAuthorize("hasRole('ADMIN')")
public class AdminActivityController {

    private static final int PAGE_SIZE = 50;

    private final ActivityService activityService;
    private final ServiceCatalogService serviceCatalog;

    public AdminActivityController(ActivityService activityService,
                                   ServiceCatalogService serviceCatalog) {
        this.activityService = activityService;
        this.serviceCatalog = serviceCatalog;
    }

    /**
     * Даты принимаются строками, а не LocalDate.
     *
     * Пустой <input type="date"> отправляется как from=&to=, и связывание пустой строки
     * с LocalDate роняет запрос с ошибкой конвертации — то есть форма фильтра ломалась бы
     * ровно в самом частом случае, когда даты не заданы.
     */
    @GetMapping
    public String activity(@RequestParam(required = false) String username,
                           @RequestParam(required = false) ActivityType type,
                           @RequestParam(required = false) ActivityType.Category category,
                           @RequestParam(required = false) String service,
                           @RequestParam(defaultValue = "false") boolean onlyFailures,
                           @RequestParam(required = false) String from,
                           @RequestParam(required = false) String to,
                           @RequestParam(defaultValue = "0") int page,
                           Model model) {

        LocalDate fromDate = parseDate(from);
        LocalDate toDate = parseDate(to);

        ZoneId zone = ZoneId.systemDefault();
        Instant fromInstant = fromDate == null ? null : fromDate.atStartOfDay(zone).toInstant();
        // Верхняя граница включает весь указанный день целиком.
        Instant toInstant = toDate == null
                ? null : toDate.atTime(LocalTime.MAX).atZone(zone).toInstant();

        var filter = new ActivityService.ActivityFilter(
                username, type, category, service, onlyFailures, fromInstant, toInstant);

        Page<com.technic.gate.domain.ActivityLog> result = activityService.search(
                filter,
                PageRequest.of(Math.max(0, page), PAGE_SIZE, Sort.by(Sort.Direction.DESC, "at")));

        model.addAttribute("entries", result.getContent());
        model.addAttribute("page", result.getNumber());
        model.addAttribute("totalPages", result.getTotalPages());
        model.addAttribute("totalElements", result.getTotalElements());

        model.addAttribute("filterUsername", username);
        model.addAttribute("filterType", type);
        model.addAttribute("filterCategory", category);
        model.addAttribute("filterService", service);
        model.addAttribute("filterOnlyFailures", onlyFailures);
        // В модель возвращаются исходные строки — они же уходят обратно в value полей
        // и в ссылки постраничной навигации.
        model.addAttribute("filterFrom", fromDate == null ? "" : fromDate.toString());
        model.addAttribute("filterTo", toDate == null ? "" : toDate.toString());

        model.addAttribute("allTypes", ActivityType.values());
        model.addAttribute("allCategories", ActivityType.Category.values());
        model.addAttribute("allServices", serviceCatalog.findAll());

        Instant dayAgo = Instant.now().minus(24, ChronoUnit.HOURS);
        model.addAttribute("eventsLast24h", activityService.countSince(dayAgo));
        model.addAttribute("failuresLast24h", activityService.countFailuresSince(dayAgo));
        model.addAttribute("activePage", "activity");
        return "admin/activity";
    }

    /** Пустая или неразборчивая дата трактуется как «фильтра нет», а не как ошибка запроса. */
    private static LocalDate parseDate(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDate.parse(value.trim());
        } catch (DateTimeParseException e) {
            return null;
        }
    }
}
