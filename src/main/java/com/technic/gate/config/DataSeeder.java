package com.technic.gate.config;

import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserRepository;
import java.security.SecureRandom;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Первичное наполнение: администратор и сервис по умолчанию.
 *
 * Пароль админа берётся из GATE_ADMIN_PASSWORD. Если переменная не задана, генерируется
 * случайный и один раз печатается в лог — так гейт не поднимается с предсказуемым паролем,
 * даже если про переменную забыли. Оба действия выполняются только при пустой базе:
 * повторный старт ничего не перезаписывает и пароль не сбрасывает.
 */
@Component
public class DataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final UserRepository userRepository;
    private final ProtectedServiceRepository serviceRepository;
    private final PasswordEncoder passwordEncoder;
    private final String adminUsername;
    private final String adminPassword;
    private final boolean seedDefaultService;

    public DataSeeder(UserRepository userRepository,
                      ProtectedServiceRepository serviceRepository,
                      PasswordEncoder passwordEncoder,
                      @Value("${gate.admin.username:admin}") String adminUsername,
                      @Value("${gate.admin.password:}") String adminPassword,
                      @Value("${gate.seed-default-service:true}") boolean seedDefaultService) {
        this.userRepository = userRepository;
        this.serviceRepository = serviceRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminUsername = adminUsername;
        this.adminPassword = adminPassword;
        this.seedDefaultService = seedDefaultService;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedAdmin();
        seedService();
    }

    private void seedAdmin() {
        if (userRepository.countByRole(Role.ADMIN) > 0) {
            return;
        }
        String password = adminPassword;
        boolean generated = false;
        if (password == null || password.isBlank()) {
            password = generatePassword();
            generated = true;
        }

        User admin = new User(adminUsername, passwordEncoder.encode(password), Role.ADMIN);
        admin.setApproved(true);
        userRepository.save(admin);

        if (generated) {
            log.warn("""

                    ==========================================================
                     Создан администратор: {}
                     Временный пароль:     {}
                     Пароль сгенерирован, потому что не задан GATE_ADMIN_PASSWORD.
                     Смените его после первого входа — в лог он больше не попадёт.
                    ==========================================================""",
                    adminUsername, password);
        } else {
            log.info("Создан администратор {} с паролем из GATE_ADMIN_PASSWORD", adminUsername);
        }
    }

    private void seedService() {
        if (!seedDefaultService || serviceRepository.count() > 0) {
            return;
        }
        ProtectedService fashionmark = new ProtectedService(
                "fashionmark", "FashionMark", "127.0.0.1", 8080);
        fashionmark.setScheme("https");
        fashionmark.setDescription("Сервис на домашнем сервере через reverse SSH-туннель");
        fashionmark.setIcon("👗");
        serviceRepository.save(fashionmark);
        log.info("Создан сервис по умолчанию: fashionmark -> {}", fashionmark.upstreamUrl());
    }

    private String generatePassword() {
        byte[] bytes = new byte[18];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
