package com.technic.gate.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.persistence.EmbeddedId;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.io.Serializable;
import java.util.Objects;

/**
 * Роль, выданная пользователю внутри одного приложения — уходит в claim {@code roles} токена Gate Auth.
 * На пару пользователь+приложение их может быть несколько (с V3, gate-auth 0.2.0); сама роль — {@link AppRole}.
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

    protected UserServiceRole() {
    }

    public UserServiceRole(Long userId, Long serviceId, Long roleId) {
        this.id = new Key(userId, serviceId, roleId);
    }

    public Key getId() { return id; }

    public Long getUserId() { return id.userId; }

    public Long getServiceId() { return id.serviceId; }

    public Long getRoleId() { return id.roleId; }

    @Embeddable
    public static class Key implements Serializable {

        @Column(name = "user_id")
        private Long userId;

        @Column(name = "service_id")
        private Long serviceId;

        @Column(name = "role_id")
        private Long roleId;

        protected Key() {
        }

        public Key(Long userId, Long serviceId, Long roleId) {
            this.userId = userId;
            this.serviceId = serviceId;
            this.roleId = roleId;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Key k && Objects.equals(userId, k.userId) && Objects.equals(serviceId, k.serviceId)
                    && Objects.equals(roleId, k.roleId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(userId, serviceId, roleId);
        }
    }
}
