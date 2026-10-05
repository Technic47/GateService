package com.technic.gate.security;

import com.technic.gate.service.GateSettingsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final GateAuthenticationSuccessHandler successHandler;
    private final GateAuthenticationFailureHandler failureHandler;
    private final GateLogoutHandler logoutHandler;
    private final GateUserDetailsService userDetailsService;
    private final GateSettingsService settingsService;

    /**
     * Ключ подписи remember-me. Обязан задаваться снаружи и быть постоянным:
     * случайный ключ при каждом старте разлогинит всех при перезапуске,
     * а общеизвестный позволит подделать токен.
     */
    private final String rememberMeKey;

    /** Имя cookie сессии из application.yml (GATESESSION), а не servlet-овый дефолт JSESSIONID. */
    private final String sessionCookieName;

    public SecurityConfig(GateAuthenticationSuccessHandler successHandler,
                          GateAuthenticationFailureHandler failureHandler,
                          GateLogoutHandler logoutHandler,
                          GateUserDetailsService userDetailsService,
                          GateSettingsService settingsService,
                          @Value("${gate.remember-me-key}") String rememberMeKey,
                          @Value("${server.servlet.session.cookie.name:JSESSIONID}") String sessionCookieName) {
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.logoutHandler = logoutHandler;
        this.userDetailsService = userDetailsService;
        this.settingsService = settingsService;
        this.rememberMeKey = rememberMeKey;
        this.sessionCookieName = sessionCookieName;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // Сила 10 — компромисс для 1 vCPU на VPS: ~50-80 мс на хеш.
        return new BCryptPasswordEncoder(10);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        int rememberMeSeconds = Math.max(1, settingsService.get().rememberMeDays()) * 24 * 60 * 60;

        http
                .authorizeHttpRequests(auth -> auth
                        // Эндпоинт для auth_request: свой ответ 200/401/403, без редиректа на логин.
                        .requestMatchers("/verify").permitAll()
                        .requestMatchers("/login", "/register", "/denied", "/error").permitAll()
                        // Gate Auth: публичные ключи и вход из LAN. /auth/handoff сам решает,
                        // что делать без сессии: при prompt=none — ответить login_required
                        // приложению, а не показывать форму входа.
                        .requestMatchers("/.well-known/jwks.json", "/auth/handoff").permitAll()
                        .requestMatchers("/css/**", "/js/**", "/favicon.ico").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .requestMatchers("/actuator/**").hasRole("ADMIN")
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .usernameParameter("username")
                        .passwordParameter("password")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll())
                .rememberMe(rm -> rm
                        .key(rememberMeKey)
                        .rememberMeParameter("remember-me")
                        .tokenValiditySeconds(rememberMeSeconds)
                        .userDetailsService(userDetailsService))
                // POST /logout — выход (LogoutFilter), GET /logout — страница подтверждения
                // в AuthController: при включённом CSRF LogoutFilter GET не перехватывает.
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .addLogoutHandler(logoutHandler)
                        .logoutSuccessUrl("/login?logout")
                        .deleteCookies(sessionCookieName)
                        .invalidateHttpSession(true)
                        .permitAll())
                .exceptionHandling(ex -> ex.accessDeniedPage("/denied"));

        return http.build();
    }
}
