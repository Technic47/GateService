package com.technic.gate.service;

import com.technic.gate.domain.GateSetting;
import com.technic.gate.domain.RegistrationMode;
import com.technic.gate.domain.Role;
import com.technic.gate.repo.GateSettingRepository;
import jakarta.annotation.PostConstruct;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Чтение и запись настроек гейта.
 *
 * Настройки читаются на каждом запросе к /verify, поэтому текущий снимок держится
 * в памяти и перечитывается из БД только при сохранении. Ценой служит то, что при
 * нескольких экземплярах сервиса они разъедутся — но гейт разворачивается в одном.
 */
@Service
public class GateSettingsService {

    private static final Logger log = LoggerFactory.getLogger(GateSettingsService.class);

    private final GateSettingRepository repository;
    private volatile GateSettings current = GateSettings.defaults();

    public GateSettingsService(GateSettingRepository repository) {
        this.repository = repository;
    }

    @PostConstruct
    public void init() {
        reload();
    }

    public GateSettings get() {
        return current;
    }

    @Transactional(readOnly = true)
    public void reload() {
        Map<String, String> raw = new HashMap<>();
        repository.findAll().forEach(s -> raw.put(s.getKey(), s.getValue()));
        current = fromMap(raw);
        log.debug("Настройки гейта перечитаны: {} ключей", raw.size());
    }

    @Transactional
    public void save(GateSettings settings) {
        put(GateSettings.K_REGISTRATION_MODE, settings.registrationMode().name());
        put(GateSettings.K_DEFAULT_ROLE, settings.defaultRole().name());
        put(GateSettings.K_AUTO_GRANT, settings.autoGrantServices());
        put(GateSettings.K_MAX_FAILED, String.valueOf(settings.maxFailedAttempts()));
        put(GateSettings.K_LOCKOUT_MINUTES, String.valueOf(settings.lockoutMinutes()));
        put(GateSettings.K_PASSWORD_MIN_LENGTH, String.valueOf(settings.passwordMinLength()));
        put(GateSettings.K_SESSION_TIMEOUT, String.valueOf(settings.sessionTimeoutMinutes()));
        put(GateSettings.K_REMEMBER_ME_DAYS, String.valueOf(settings.rememberMeDays()));
        put(GateSettings.K_RETENTION_DAYS, String.valueOf(settings.activityRetentionDays()));
        put(GateSettings.K_LOG_ALLOWED, String.valueOf(settings.logAllowedVerifies()));
        put(GateSettings.K_MAINTENANCE, String.valueOf(settings.maintenanceMode()));
        put(GateSettings.K_ADMIN_BYPASS, String.valueOf(settings.adminBypassesAccess()));
        put(GateSettings.K_PUBLIC_URL, settings.publicUrl());
        put(GateSettings.K_SERVICE_HEADER, settings.serviceHeaderName());
        current = settings;
    }

    private void put(String key, String value) {
        GateSetting setting = repository.findById(key).orElseGet(() -> new GateSetting(key, value));
        setting.setValue(value);
        repository.save(setting);
    }

    private GateSettings fromMap(Map<String, String> raw) {
        GateSettings d = GateSettings.defaults();
        return new GateSettings(
                parseEnum(raw.get(GateSettings.K_REGISTRATION_MODE), RegistrationMode.class, d.registrationMode()),
                parseEnum(raw.get(GateSettings.K_DEFAULT_ROLE), Role.class, d.defaultRole()),
                raw.getOrDefault(GateSettings.K_AUTO_GRANT, d.autoGrantServices()),
                parseInt(raw.get(GateSettings.K_MAX_FAILED), d.maxFailedAttempts()),
                parseInt(raw.get(GateSettings.K_LOCKOUT_MINUTES), d.lockoutMinutes()),
                parseInt(raw.get(GateSettings.K_PASSWORD_MIN_LENGTH), d.passwordMinLength()),
                parseInt(raw.get(GateSettings.K_SESSION_TIMEOUT), d.sessionTimeoutMinutes()),
                parseInt(raw.get(GateSettings.K_REMEMBER_ME_DAYS), d.rememberMeDays()),
                parseInt(raw.get(GateSettings.K_RETENTION_DAYS), d.activityRetentionDays()),
                parseBool(raw.get(GateSettings.K_LOG_ALLOWED), d.logAllowedVerifies()),
                parseBool(raw.get(GateSettings.K_MAINTENANCE), d.maintenanceMode()),
                parseBool(raw.get(GateSettings.K_ADMIN_BYPASS), d.adminBypassesAccess()),
                raw.getOrDefault(GateSettings.K_PUBLIC_URL, d.publicUrl()),
                raw.getOrDefault(GateSettings.K_SERVICE_HEADER, d.serviceHeaderName()));
    }

    private static int parseInt(String value, int fallback) {
        try {
            return value == null ? fallback : Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }

    private static boolean parseBool(String value, boolean fallback) {
        return value == null ? fallback : Boolean.parseBoolean(value.trim());
    }

    private static <E extends Enum<E>> E parseEnum(String value, Class<E> type, E fallback) {
        try {
            return value == null ? fallback : Enum.valueOf(type, value.trim());
        } catch (IllegalArgumentException e) {
            return fallback;
        }
    }
}
