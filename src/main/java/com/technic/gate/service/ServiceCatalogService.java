package com.technic.gate.service;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.repo.ProtectedServiceRepository;
import java.util.List;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** CRUD по защищаемым сервисам. */
@Service
public class ServiceCatalogService {

    /** Имя уходит в заголовок X-Service-Name и в конфиг Nginx — только безопасные символы. */
    private static final Pattern NAME = Pattern.compile("^[a-z0-9][a-z0-9_-]{1,63}$");

    private final ProtectedServiceRepository repository;
    private final ActivityService activityService;

    public ServiceCatalogService(ProtectedServiceRepository repository,
                                 ActivityService activityService) {
        this.repository = repository;
        this.activityService = activityService;
    }

    @Transactional(readOnly = true)
    public List<ProtectedService> findAll() {
        return repository.findAllByOrderBySortOrderAscDisplayNameAsc();
    }

    @Transactional(readOnly = true)
    public List<ProtectedService> findEnabled() {
        return repository.findByEnabledTrueOrderBySortOrderAscDisplayNameAsc();
    }

    @Transactional(readOnly = true)
    public ProtectedService require(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new GateException("Сервис не найден"));
    }

    @Transactional
    public ProtectedService save(Long id, String name, String displayName, String description,
                                 String scheme, String host, int port, String publicUrl,
                                 boolean enabled, String icon, int sortOrder, String actor) {
        validate(name, scheme, port);

        ProtectedService service;
        boolean creating = (id == null);
        if (creating) {
            if (repository.existsByNameIgnoreCase(name)) {
                throw new GateException("Сервис с именем " + name + " уже существует");
            }
            service = new ProtectedService(name, displayName, host, port);
        } else {
            service = require(id);
            repository.findByNameIgnoreCase(name)
                    .filter(other -> !other.getId().equals(id))
                    .ifPresent(other -> {
                        throw new GateException("Сервис с именем " + name + " уже существует");
                    });
            service.setName(name);
            service.setDisplayName(displayName);
            service.setHost(host);
            service.setPort(port);
        }

        service.setDescription(blankToNull(description));
        service.setScheme(scheme);
        service.setPublicUrl(blankToNull(publicUrl));
        service.setEnabled(enabled);
        service.setIcon(blankToNull(icon));
        service.setSortOrder(sortOrder);
        ProtectedService saved = repository.save(service);

        activityService.event(creating ? ActivityType.SERVICE_CREATED : ActivityType.SERVICE_UPDATED)
                .user(actor, null)
                .service(saved.getName())
                .detail((creating ? "Создан сервис " : "Изменён сервис ") + saved.getName()
                        + " (" + saved.upstreamUrl() + ")")
                .save();
        return saved;
    }

    @Transactional
    public void delete(Long id, String actor) {
        ProtectedService service = require(id);
        String name = service.getName();
        // Связи в user_service_access уходят каскадом на уровне схемы (ON DELETE CASCADE).
        repository.delete(service);

        activityService.event(ActivityType.SERVICE_DELETED)
                .user(actor, null)
                .service(name)
                .detail("Удалён сервис " + name)
                .save();
    }

    private void validate(String name, String scheme, int port) {
        if (name == null || !NAME.matcher(name).matches()) {
            throw new GateException(
                    "Имя сервиса: 2-64 символа, строчная латиница, цифры, дефис, подчёркивание");
        }
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new GateException("Схема должна быть http или https");
        }
        if (port < 1 || port > 65535) {
            throw new GateException("Порт должен быть в диапазоне 1-65535");
        }
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
