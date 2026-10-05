package com.technic.gate.service;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.repo.ProtectedServiceRepository;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** CRUD по защищаемым сервисам. */
@Service
public class ServiceCatalogService {

    /** Имя уходит в заголовок X-Service-Name и в конфиг Nginx — только безопасные символы. */
    private static final Pattern NAME = Pattern.compile("^[a-z0-9][a-z0-9_-]{1,63}$");

    /** Путь API, который подставляется в location Nginx. */
    private static final Pattern API_PREFIX = Pattern.compile("^/([A-Za-z0-9._~-]+/)*$");

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
                                 boolean enabled, String icon, int sortOrder,
                                 boolean directEnabled, String redirectUris, String apiPrefix,
                                 String actor) {
        validate(name, scheme, port);
        String normalizedRedirectUris = normalizeRedirectUris(redirectUris);
        if (directEnabled && normalizedRedirectUris == null) {
            throw new GateException("Для входа из локальной сети нужен хотя бы один адрес возврата (callback)");
        }
        String normalizedApiPrefix = normalizeApiPrefix(apiPrefix);

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
        service.setDirectEnabled(directEnabled);
        service.setRedirectUris(normalizedRedirectUris);
        service.setApiPrefix(normalizedApiPrefix);
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

    /**
     * Адреса callback-ов direct mode (§6.1 спецификации), по одному на строку.
     * Гейт сравнивает их с redirect_uri побайтово, поэтому здесь отсекается всё, что потом
     * могло бы стать дырой: не-https (кроме localhost для отладки), логин в адресе, query, фрагмент.
     */
    static String normalizeRedirectUris(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        List<String> lines = value.lines().map(String::trim).filter(l -> !l.isEmpty()).distinct().toList();
        if (lines.size() > 10) {
            throw new GateException("Не больше 10 адресов возврата");
        }
        for (String line : lines) {
            URI uri;
            try {
                uri = new URI(line);
            } catch (URISyntaxException e) {
                throw new GateException("Адрес возврата не разбирается: " + line);
            }
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = uri.getHost();
            boolean local = "localhost".equals(host) || "127.0.0.1".equals(host);
            if (!uri.isAbsolute() || host == null || !(scheme.equals("https") || (scheme.equals("http") && local))) {
                throw new GateException("Адрес возврата должен быть абсолютным https://… : " + line);
            }
            if (uri.getRawUserInfo() != null || uri.getRawFragment() != null || uri.getRawQuery() != null) {
                throw new GateException("В адресе возврата не должно быть логина, query и #фрагмента: " + line);
            }
            if (uri.getRawPath() == null || !uri.getRawPath().startsWith("/")) {
                throw new GateException("В адресе возврата нужен путь, например /auth/callback: " + line);
            }
        }
        String joined = String.join("\n", lines);
        if (joined.length() > 2048) {
            throw new GateException("Адреса возврата длиннее 2048 символов");
        }
        return joined;
    }

    /** Путь API для Nginx: попадает в конфиг как есть, поэтому только безопасные символы. */
    static String normalizeApiPrefix(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String v = value.trim();
        if (!API_PREFIX.matcher(v).matches()) {
            throw new GateException("Путь API: начинается и заканчивается на /, например /api/");
        }
        return v;
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
