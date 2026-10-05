package com.technic.gate.security;

import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

/**
 * Пользователь в терминах Spring Security.
 *
 * Хранит только id/имя/роль — состояние доступа к сервисам сюда сознательно не кладётся:
 * оно живёт в сессии и не увидело бы отзыв доступа до перелогина. Доступы проверяются
 * запросом к БД в момент проверки.
 */
public class GateUserDetails implements UserDetails {

    private final Long id;
    private final String username;
    private final String passwordHash;
    private final Role role;
    private final boolean blocked;
    private final boolean approved;
    private final boolean temporarilyLocked;

    public GateUserDetails(User user) {
        this.id = user.getId();
        this.username = user.getUsername();
        this.passwordHash = user.getPasswordHash();
        this.role = user.getRole();
        this.blocked = user.isBlocked();
        this.approved = user.isApproved();
        this.temporarilyLocked = user.isTemporarilyLocked();
    }

    public Long getId() {
        return id;
    }

    public Role getRole() {
        return role;
    }

    public boolean isAdmin() {
        return role == Role.ADMIN;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.authority()));
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return username;
    }

    /** Ручная блокировка админом и неодобренный аккаунт трактуются как отключённый. */
    @Override
    public boolean isEnabled() {
        return !blocked && approved;
    }

    /** Временная блокировка после серии неудачных попыток входа. */
    @Override
    public boolean isAccountNonLocked() {
        return !temporarilyLocked;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }
}
