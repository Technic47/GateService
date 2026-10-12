package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;

/**
 * Роль приложения (Gate Auth §4.4–4.5): то, что уходит в claim {@code roles} токена. Определяется только в гейте.
 *
 * Глобальная роль ({@code serviceId == null}) — одно определение для всех приложений; выдаётся всё равно на пару
 * пользователь+приложение. Код ({@code code}) после создания не меняется: приложения проверяют его в своём коде.
 * Вместо удаления — архив. Не путать с {@link Role} — ролью самого гейта (ADMIN/USER).
 */
@Entity
@Table(name = "roles")
public class AppRole {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 32, updatable = false)
    private String code;

    @Column(nullable = false, length = 100)
    private String name;

    @Column(length = 500)
    private String description;

    /** Приложение (сервис) роли; {@code null} — глобальная. Не меняется после создания. */
    @Column(name = "service_id", updatable = false)
    private Long serviceId;

    @Column(name = "sort_order", nullable = false)
    private int sortOrder;

    @Column(name = "archived_at")
    private Instant archivedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    protected AppRole() {
    }

    public AppRole(String code, String name, String description, Long serviceId, int sortOrder, Instant now) {
        this.code = Objects.requireNonNull(code, "code");
        this.serviceId = serviceId;
        this.createdAt = now;
        describe(name, description, sortOrder, now);
    }

    /** Меняет то, что можно менять: название, описание, порядок. */
    public void describe(String name, String description, int sortOrder, Instant now) {
        this.name = Objects.requireNonNull(name, "name").strip();
        this.description = description == null || description.isBlank() ? null : description.strip();
        this.sortOrder = sortOrder;
        this.updatedAt = now;
    }

    public void archive(Instant now) {
        if (archivedAt == null) {
            archivedAt = now;
            updatedAt = now;
        }
    }

    public void restore(Instant now) {
        if (archivedAt != null) {
            archivedAt = null;
            updatedAt = now;
        }
    }

    public boolean isGlobal() {
        return serviceId == null;
    }

    public boolean isArchived() {
        return archivedAt != null;
    }

    /** Можно ли выдать роль в этом приложении: глобальная или своя, и не в архиве. */
    public boolean assignableTo(Long serviceId) {
        return !isArchived() && (isGlobal() || this.serviceId.equals(serviceId));
    }

    public Long getId() { return id; }

    public String getCode() { return code; }

    public String getName() { return name; }

    public String getDescription() { return description; }

    public Long getServiceId() { return serviceId; }

    public int getSortOrder() { return sortOrder; }

    public Instant getArchivedAt() { return archivedAt; }

    public Instant getCreatedAt() { return createdAt; }

    public Instant getUpdatedAt() { return updatedAt; }

    @Override
    public boolean equals(Object o) {
        return o instanceof AppRole other && id != null && id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return AppRole.class.hashCode();
    }
}
