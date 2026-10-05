package com.technic.gate.security;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.User;
import com.technic.gate.repo.UserRepository;
import com.technic.gate.service.ActivityService;
import com.technic.gate.service.GateSettingsService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Счётчик неудачных входов и временная блокировка.
 *
 * Состояние хранится в БД, а не в памяти: гейт может перезапуститься, и подбор пароля
 * не должен обнуляться вместе с процессом. Считаются только попытки по существующему
 * логину — иначе таблица росла бы от перебора случайных имён.
 */
@Service
public class LoginAttemptService {

    private final UserRepository userRepository;
    private final GateSettingsService settingsService;
    private final ActivityService activityService;

    public LoginAttemptService(UserRepository userRepository,
                               GateSettingsService settingsService,
                               ActivityService activityService) {
        this.userRepository = userRepository;
        this.settingsService = settingsService;
        this.activityService = activityService;
    }

    /** Неудачная попытка входа. Возвращает пользователя, если такой логин существует. */
    @Transactional
    public Optional<User> registerFailure(String username, String ip) {
        if (username == null || username.isBlank()) {
            return Optional.empty();
        }
        Optional<User> found = userRepository.findByUsernameIgnoreCase(username);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        User user = found.get();
        int max = settingsService.get().maxFailedAttempts();
        int attempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(attempts);

        if (max > 0 && attempts >= max) {
            int minutes = settingsService.get().lockoutMinutes();
            user.setLockedUntil(Instant.now().plus(minutes, ChronoUnit.MINUTES));
            user.setFailedAttempts(0);
            userRepository.save(user);
            activityService.event(ActivityType.ACCOUNT_LOCKED)
                    .user(user)
                    .failed()
                    .ip(ip)
                    .detail("Аккаунт заблокирован на " + minutes + " мин после " + max + " неудачных попыток")
                    .save();
            return Optional.of(user);
        }

        userRepository.save(user);
        return Optional.of(user);
    }

    /** Успешный вход: сбрасываем счётчик, снимаем лок, отмечаем время входа. */
    @Transactional
    public void registerSuccess(String username) {
        userRepository.findByUsernameIgnoreCase(username).ifPresent(user -> {
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
            user.setLastLoginAt(Instant.now());
            userRepository.save(user);
        });
    }
}
