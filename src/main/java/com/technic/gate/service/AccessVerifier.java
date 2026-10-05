package com.technic.gate.service;

import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.User;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Решение о доступе — общая точка для Nginx auth_request и для страницы портала.
 *
 * Состояние пользователя и его доступы читаются из БД на каждой проверке, а не берутся
 * из сессии. Это лишний запрос на каждый проксируемый запрос, но зато отзыв доступа
 * и блокировка действуют мгновенно, а не после перелогина — для гейта это важнее.
 * Запрос идёт по уникальному индексу username, нагрузка при десятке пользователей
 * пренебрежимо мала.
 */
@Service
public class AccessVerifier {

    public enum Outcome {
        /** Доступ есть. */
        ALLOWED(200),
        /** Не аутентифицирован — надо отправить на форму входа. */
        UNAUTHENTICATED(401),
        /** Аутентифицирован, но доступа к этому сервису нет. */
        FORBIDDEN(403);

        private final int status;

        Outcome(int status) {
            this.status = status;
        }

        public int getStatus() {
            return status;
        }
    }

    public record Decision(Outcome outcome, String reason, User user, ProtectedService service) {

        public boolean allowed() {
            return outcome == Outcome.ALLOWED;
        }

        public int status() {
            return outcome.getStatus();
        }
    }

    private final UserRepository userRepository;
    private final ProtectedServiceRepository serviceRepository;
    private final GateSettingsService settingsService;

    public AccessVerifier(UserRepository userRepository,
                          ProtectedServiceRepository serviceRepository,
                          GateSettingsService settingsService) {
        this.userRepository = userRepository;
        this.serviceRepository = serviceRepository;
        this.settingsService = settingsService;
    }

    @Transactional(readOnly = true)
    public Decision decide(String username, String serviceName) {
        if (username == null || username.isBlank()) {
            return new Decision(Outcome.UNAUTHENTICATED, "Нет аутентификации", null, null);
        }

        Optional<User> found = userRepository.findWithServicesByUsernameIgnoreCase(username);
        if (found.isEmpty()) {
            // Сессия ссылается на пользователя, которого уже удалили.
            return new Decision(Outcome.UNAUTHENTICATED, "Пользователь не найден", null, null);
        }
        User user = found.get();

        if (user.isBlocked()) {
            return new Decision(Outcome.FORBIDDEN, "Аккаунт заблокирован", user, null);
        }
        if (!user.isApproved()) {
            return new Decision(Outcome.FORBIDDEN, "Аккаунт не одобрен", user, null);
        }

        GateSettings settings = settingsService.get();
        if (settings.maintenanceMode() && !user.isAdmin()) {
            return new Decision(Outcome.FORBIDDEN, "Режим обслуживания", user, null);
        }

        if (serviceName == null || serviceName.isBlank()) {
            // Без имени сервиса решение принять нельзя. Почти всегда это значит, что в Nginx
            // забыли proxy_set_header X-Service-Name — отказываем и говорим об этом прямо.
            return new Decision(Outcome.FORBIDDEN,
                    "Не передано имя сервиса (заголовок " + settings.serviceHeaderName() + ")",
                    user, null);
        }

        Optional<ProtectedService> service = serviceRepository.findByNameIgnoreCase(serviceName);
        if (service.isEmpty()) {
            return new Decision(Outcome.FORBIDDEN, "Неизвестный сервис: " + serviceName, user, null);
        }
        ProtectedService target = service.get();
        if (!target.isEnabled()) {
            return new Decision(Outcome.FORBIDDEN, "Сервис отключён", user, target);
        }

        if (user.isAdmin() && settings.adminBypassesAccess()) {
            return new Decision(Outcome.ALLOWED, "Администратор", user, target);
        }

        boolean hasAccess = user.getServices().stream()
                .anyMatch(s -> s.getId().equals(target.getId()));
        return hasAccess
                ? new Decision(Outcome.ALLOWED, "Доступ выдан", user, target)
                : new Decision(Outcome.FORBIDDEN, "Нет доступа к сервису", user, target);
    }

    /**
     * Сервисы, доступные пользователю. Используется страницей портала.
     * Админ с включённым adminBypassesAccess видит все включённые сервисы —
     * иначе он не смог бы зайти в сервис, не выдав доступ сам себе.
     */
    @Transactional(readOnly = true)
    public List<ProtectedService> accessibleServices(String username) {
        Optional<User> found = userRepository.findWithServicesByUsernameIgnoreCase(username);
        if (found.isEmpty()) {
            return List.of();
        }
        User user = found.get();
        if (!user.isActive()) {
            return List.of();
        }
        if (user.isAdmin() && settingsService.get().adminBypassesAccess()) {
            return serviceRepository.findByEnabledTrueOrderBySortOrderAscDisplayNameAsc();
        }
        return user.getServices().stream()
                .filter(ProtectedService::isEnabled)
                .sorted((a, b) -> {
                    int bySort = Integer.compare(a.getSortOrder(), b.getSortOrder());
                    return bySort != 0 ? bySort : a.getDisplayName().compareToIgnoreCase(b.getDisplayName());
                })
                .toList();
    }
}
