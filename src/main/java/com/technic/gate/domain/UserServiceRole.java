package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * Роль пользователя внутри одного приложения — уходит в claim {@code roles} токена Gate Auth.
 *
 * Отдельная сущность, а не колонка в user_service_access: связь пользователь↔сервис там
 * замаплена как {@code @ManyToMany}, а лишнюю колонку в join-таблице Hibernate не видит
 * и при пересоздании коллекции потеряет.
 */
@Entity
@Table(name = "user_service_role")
public class UserServiceRole {

    @EmbeddedId
    private Key id;

    @Column(nullable = false, length = 32)
    private String role;

    protected UserServiceRole() {
    }

    public UserServiceRole(Long userId, Long serviceId, String role) {
        this.id = new Key(userId, serviceId);
        this.role = role;
    }

    public Key getId() { return id; }

    public Long getUserId() { return id.userId; }

    public Long getServiceId() { return id.serviceId; }

    public String getRole() { return role; }
    public void setRole(String role) { this.role = role; }

    @Embeddable
    public static class Key implements Serializable {

        @Column(name = "user_id")
        private Long userId;

        @Column(name = "service_id")
        private Long serviceId;

        protected Key() {
        }

        public Key(Long userId, Long serviceId) {
            this.userId = userId;
            this.serviceId = serviceId;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Key k && Objects.equals(userId, k.userId) && Objects.equals(serviceId, k.serviceId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, serviceId);
        }
    }
}
