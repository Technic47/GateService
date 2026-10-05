package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * Запись журнала активности.
 *
 * Имя пользователя хранится строкой, а не ссылкой на User: журнал должен переживать
 * удаление пользователя и фиксировать попытки входа под несуществующим логином.
 * userId — подсказка для ссылок в админке, может указывать в никуда.
 */
@Entity
@Table(name = "activity_log", indexes = {
        @Index(name = "idx_activity_at", columnList = "occurred_at DESC"),
        @Index(name = "idx_activity_username", columnList = "username"),
        @Index(name = "idx_activity_type", columnList = "type")
})
public class ActivityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Колонка occurred_at, а не at: AT — ключевое слово SQL, не хочется его цитировать везде. */
    @Column(name = "occurred_at", nullable = false)
    private Instant at = Instant.now();

    @Column(length = 64)
    private String username;

    @Column(name = "user_id")
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private ActivityType type;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private ActivityType.Category category;

    /** Успешным считается событие, не являющееся отказом/ошибкой. Для быстрой фильтрации. */
    @Column(nullable = false)
    private boolean success = true;

    @Column(name = "service_name", length = 64)
    private String serviceName;

    @Column(length = 64)
    private String ip;

    @Column(name = "user_agent", length = 256)
    private String userAgent;

    /** Человекочитаемая подробность: что именно изменилось, причина отказа и т.п. */
    @Column(length = 512)
    private String detail;

    protected ActivityLog() {
    }

    public ActivityLog(ActivityType type, String username, Long userId) {
        this.type = type;
        this.category = type.getCategory();
        this.username = username;
        this.userId = userId;
    }

    public Long getId() { return id; }

    public Instant getAt() { return at; }
    public void setAt(Instant at) { this.at = at; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public ActivityType getType() { return type; }

    public void setType(ActivityType type) {
        this.type = type;
        this.category = type.getCategory();
    }

    public ActivityType.Category getCategory() { return category; }

    public boolean isSuccess() { return success; }
    public void setSuccess(boolean success) { this.success = success; }

    public String getServiceName() { return serviceName; }
    public void setServiceName(String serviceName) { this.serviceName = serviceName; }

    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }

    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }

    public String getDetail() { return detail; }
    public void setDetail(String detail) { this.detail = detail; }
}
