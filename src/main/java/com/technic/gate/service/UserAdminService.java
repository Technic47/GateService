package com.technic.gate.service;

import com.technic.gate.domain.ActivityType;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.RegistrationMode;
import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserRepository;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Создание, изменение и удаление пользователей, а также выдача доступа к сервисам.
 *
 * Здесь же живёт инвариант «последний администратор неприкосновенен»: его нельзя
 * удалить, заблокировать или понизить до USER. Без этого гейт легко превратить
 * в систему, в админку которой больше никто не войдёт, а чинить это пришлось бы
 * руками в psql.
 */
@Service
public class UserAdminService {

    private static final Pattern USERNAME = Pattern.compile("^[a-zA-Z0-9._-]{3,64}$");

    private final UserRepository userRepository;
    private final ProtectedServiceRepository serviceRepository;
    private final PasswordEncoder passwordEncoder;
    private final GateSettingsService settingsService;
    private final ActivityService activityService;

    public UserAdminService(UserRepository userRepository,
                            ProtectedServiceRepository serviceRepository,
                            PasswordEncoder passwordEncoder,
                            GateSettingsService settingsService,
                            ActivityService activityService) {
        this.userRepository = userRepository;
        this.serviceRepository = serviceRepository;
        this.passwordEncoder = passwordEncoder;
        this.settingsService = settingsService;
        this.activityService = activityService;
    }

    @Transactional(readOnly = true)
    public List<User> findAll() {
        return userRepository.findAllWithServices();
    }

    @Transactional(readOnly = true)
    public User require(Long id) {
        return userRepository.findWithServicesById(id)
                .orElseThrow(() -> new GateException("Пользователь не найден"));
    }

    /**
     * Самостоятельная регистрация с формы.
     * Возвращает true, если аккаунт активен сразу, false — если ждёт одобрения.
     */
    @Transactional
    public boolean register(String username, String password, String confirmPassword) {
        GateSettings settings = settingsService.get();
        if (settings.registrationMode() == RegistrationMode.CLOSED) {
            throw new GateException("Регистрация закрыта. Обратитесь к администратору.");
        }
        if (!password.equals(confirmPassword)) {
            throw new GateException("Пароли не совпадают");
        }
        validateUsername(username);
        validatePassword(password);

        boolean approved = settings.registrationMode() == RegistrationMode.OPEN;
        User user = persistNew(username, password, settings.defaultRole(), approved);

        // Автовыдача сервисов новому пользователю, если она настроена.
        List<String> autoGrant = settings.autoGrantServiceNames();
        if (!autoGrant.isEmpty()) {
            Set<ProtectedService> granted = new LinkedHashSet<>();
            for (String name : autoGrant) {
                serviceRepository.findByNameIgnoreCase(name).ifPresent(granted::add);
            }
            user.setServices(granted);
            userRepository.save(user);
        }

        activityService.event(ActivityType.REGISTER)
                .user(user)
                .detail(approved ? "Аккаунт активен сразу" : "Ожидает одобрения администратора")
                .save();
        return approved;
    }

    /** Создание пользователя администратором. */
    @Transactional
    public User create(String username, String password, Role role, boolean approved,
                       Set<Long> serviceIds, String actor) {
        validateUsername(username);
        validatePassword(password);
        User user = persistNew(username, password, role, approved);
        applyAccess(user, serviceIds);
        userRepository.save(user);

        activityService.event(ActivityType.USER_CREATED)
                .user(actor, null)
                .detail("Создан пользователь " + username + " с ролью " + role)
                .save();
        return user;
    }

    @Transactional
    public void update(Long id, Role role, boolean approved, Set<Long> serviceIds, String actor) {
        User user = require(id);

        if (user.getRole() == Role.ADMIN && role != Role.ADMIN) {
            requireAnotherAdminExists(user, "Нельзя снять роль администратора с последнего админа");
        }

        Set<String> before = serviceNames(user);
        user.setRole(role);
        user.setApproved(approved);
        applyAccess(user, serviceIds);
        userRepository.save(user);
        Set<String> after = serviceNames(user);

        activityService.event(ActivityType.USER_UPDATED)
                .user(actor, null)
                .detail("Изменён " + user.getUsername() + ": роль=" + role + ", одобрен=" + approved)
                .save();

        logAccessDiff(user, before, after, actor);
    }

    @Transactional
    public void setBlocked(Long id, boolean blocked, String actor) {
        User user = require(id);
        if (blocked && user.getRole() == Role.ADMIN) {
            requireAnotherAdminExists(user, "Нельзя заблокировать последнего администратора");
        }
        user.setBlocked(blocked);
        if (!blocked) {
            // Разблокировка вручную снимает и временный лок от неудачных попыток.
            user.setFailedAttempts(0);
            user.setLockedUntil(null);
        }
        userRepository.save(user);

        activityService.event(blocked ? ActivityType.USER_BLOCKED : ActivityType.USER_UNBLOCKED)
                .user(actor, null)
                .detail((blocked ? "Заблокирован " : "Разблокирован ") + user.getUsername())
                .save();
    }

    @Transactional
    public void resetPassword(Long id, String newPassword, String actor) {
        validatePassword(newPassword);
        User user = require(id);
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setFailedAttempts(0);
        user.setLockedUntil(null);
        userRepository.save(user);

        activityService.event(ActivityType.PASSWORD_RESET)
                .user(actor, null)
                .detail("Сброшен пароль пользователя " + user.getUsername())
                .save();
    }

    @Transactional
    public void delete(Long id, String actor) {
        User user = require(id);
        if (user.getRole() == Role.ADMIN) {
            requireAnotherAdminExists(user, "Нельзя удалить последнего администратора");
        }
        if (user.getUsername().equalsIgnoreCase(actor)) {
            throw new GateException("Нельзя удалить собственный аккаунт");
        }
        String username = user.getUsername();
        userRepository.delete(user);

        activityService.event(ActivityType.USER_DELETED)
                .user(actor, null)
                .detail("Удалён пользователь " + username)
                .save();
    }

    private User persistNew(String username, String password, Role role, boolean approved) {
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new GateException("Логин уже занят: " + username);
        }
        User user = new User(username, passwordEncoder.encode(password), role);
        user.setApproved(approved);
        return userRepository.save(user);
    }

    private void applyAccess(User user, Set<Long> serviceIds) {
        Set<ProtectedService> services = new LinkedHashSet<>();
        if (serviceIds != null && !serviceIds.isEmpty()) {
            services.addAll(serviceRepository.findAllById(serviceIds));
        }
        user.setServices(services);
    }

    private Set<String> serviceNames(User user) {
        Set<String> names = new LinkedHashSet<>();
        user.getServices().forEach(s -> names.add(s.getName()));
        return names;
    }

    private void logAccessDiff(User user, Set<String> before, Set<String> after, String actor) {
        after.stream().filter(n -> !before.contains(n)).forEach(name ->
                activityService.event(ActivityType.ACCESS_GRANTED)
                        .user(actor, null)
                        .service(name)
                        .detail("Выдан доступ к " + name + " для " + user.getUsername())
                        .save());
        before.stream().filter(n -> !after.contains(n)).forEach(name ->
                activityService.event(ActivityType.ACCESS_REVOKED)
                        .user(actor, null)
                        .service(name)
                        .detail("Отозван доступ к " + name + " у " + user.getUsername())
                        .save());
    }

    private void requireAnotherAdminExists(User candidate, String message) {
        long admins = userRepository.countByRole(Role.ADMIN);
        if (admins <= 1 && candidate.getRole() == Role.ADMIN) {
            throw new GateException(message);
        }
    }

    private void validateUsername(String username) {
        if (username == null || !USERNAME.matcher(username).matches()) {
            throw new GateException(
                    "Логин: 3-64 символа, только латиница, цифры, точка, дефис, подчёркивание");
        }
    }

    private void validatePassword(String password) {
        int min = settingsService.get().passwordMinLength();
        if (password == null || password.length() < min) {
            throw new GateException("Пароль должен быть не короче " + min + " символов");
        }
    }
}
