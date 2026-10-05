package com.technic.gate.service;

import com.technic.gate.domain.RegistrationMode;
import com.technic.gate.domain.Role;

/**
 * Типизированный снимок настроек гейта.
 *
 * Иммутабельный: GateSettingsService держит текущий экземпляр в памяти и заменяет
 * его целиком при сохранении, так что читатели никогда не видят полуприменённый набор.
 */
public record GateSettings(
        RegistrationMode registrationMode,
        Role defaultRole,
        String autoGrantServices,
        int maxFailedAttempts,
        int lockoutMinutes,
        int passwordMinLength,
        int sessionTimeoutMinutes,
        int rememberMeDays,
        int activityRetentionDays,
        boolean logAllowedVerifies,
        boolean maintenanceMode,
        boolean adminBypassesAccess,
        String publicUrl,
        String serviceHeaderName) {

    // Ключи в таблице gate_settings.
    public static final String K_REGISTRATION_MODE = "registration.mode";
    public static final String K_DEFAULT_ROLE = "registration.defaultRole";
    public static final String K_AUTO_GRANT = "registration.autoGrantServices";
    public static final String K_MAX_FAILED = "security.maxFailedAttempts";
    public static final String K_LOCKOUT_MINUTES = "security.lockoutMinutes";
    public static final String K_PASSWORD_MIN_LENGTH = "security.passwordMinLength";
    public static final String K_SESSION_TIMEOUT = "session.timeoutMinutes";
    public static final String K_REMEMBER_ME_DAYS = "session.rememberMeDays";
    public static final String K_RETENTION_DAYS = "activity.retentionDays";
    public static final String K_LOG_ALLOWED = "activity.logAllowedVerifies";
    public static final String K_MAINTENANCE = "gate.maintenanceMode";
    public static final String K_ADMIN_BYPASS = "gate.adminBypassesAccess";
    public static final String K_PUBLIC_URL = "gate.publicUrl";
    public static final String K_SERVICE_HEADER = "gate.serviceHeaderName";

    public static GateSettings defaults() {
        return new GateSettings(
                RegistrationMode.APPROVAL,
                Role.USER,
                "",
                5,
                15,
                8,
                480,
                14,
                90,
                false,
                false,
                true,
                "",
                "X-Service-Name");
    }

    /** Имена сервисов, выдаваемых новому пользователю автоматически. */
    public java.util.List<String> autoGrantServiceNames() {
        if (autoGrantServices == null || autoGrantServices.isBlank()) {
            return java.util.List.of();
        }
        return java.util.Arrays.stream(autoGrantServices.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    public boolean registrationOpen() {
        return registrationMode != RegistrationMode.CLOSED;
    }
}
