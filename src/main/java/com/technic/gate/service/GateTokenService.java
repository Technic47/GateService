package com.technic.gate.service;

import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.User;
import com.technic.gate.domain.UserServiceRole;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserServiceRoleRepository;
import io.github.technic47.gateauth.core.Base64Url;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateKeySet;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.TokenSigner;
import io.github.technic47.gateauth.core.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Выпуск токенов Gate Auth v1 (../gate-auth/docs/gate-auth-spec-v1.md):
 * assertion для каждого разрешённого /verify (edge mode) и handoff для входа из LAN (direct mode).
 *
 * Ключ подписи — приватный JWK Ed25519 из GATE_SIGNING_KEY или файла GATE_SIGNING_KEY_FILE
 * (сгенерировать: KeyTool из gate-auth-core). Без ключа гейт работает как раньше, просто без токенов: так новую версию
 * можно выкатить до того, как ключ разложен по приложениям.
 */
@Service
public class GateTokenService {

    private static final Logger log = LoggerFactory.getLogger(GateTokenService.class);

    /** Assertion переиспользуется, пока ему осталось жить не меньше этого (§5.1 спецификации). */
    private static final long REUSE_MIN_REMAINING_SECONDS = 30;
    private static final int CACHE_MAX = 2000;

    private final TokenSigner signer;
    private final GateKeySet publicKeys;
    private final String issuer;
    private final UserServiceRoleRepository roleRepository;
    private final ProtectedServiceRepository serviceRepository;
    private final GateSettingsService settingsService;
    private final Clock clock;
    private final Map<String, Cached> assertionCache = new ConcurrentHashMap<>();

    @Autowired
    public GateTokenService(@Value("${gate.auth.signing-key:}") String signingKey,
                            @Value("${gate.auth.signing-key-file:}") String signingKeyFile,
                            @Value("${gate.auth.issuer:gate}") String issuer,
                            UserServiceRoleRepository roleRepository,
                            ProtectedServiceRepository serviceRepository,
                            GateSettingsService settingsService) {
        this(loadKey(signingKey, signingKeyFile), issuer, roleRepository, serviceRepository, settingsService,
                Clock.systemUTC());
    }

    GateTokenService(GateSigningKey key, String issuer, UserServiceRoleRepository roleRepository,
                     ProtectedServiceRepository serviceRepository, GateSettingsService settingsService,
                     Clock clock) {
        this.signer = key == null ? null : new TokenSigner(key);
        this.publicKeys = key == null ? null : GateKeySet.of(key.publicKey());
        this.issuer = issuer;
        this.roleRepository = roleRepository;
        this.serviceRepository = serviceRepository;
        this.settingsService = settingsService;
        this.clock = clock;
        if (key == null) {
            log.warn("Gate Auth: ключ подписи не задан (GATE_SIGNING_KEY / GATE_SIGNING_KEY_FILE) — токены не выдаются, "
                    + "X-Gate-Assertion и /auth/handoff отключены");
        } else {
            log.info("Gate Auth: ключ подписи загружен, kid={}", key.kid());
        }
    }

    public boolean enabled() {
        return signer != null;
    }

    /** JWKS для {@code /.well-known/jwks.json}; пусто, если ключа нет. */
    public Optional<String> jwks() {
        return publicKeys == null ? Optional.empty() : Optional.of(publicKeys.toJwks());
    }

    /**
     * Edge mode: подписанное утверждение для разрешённого запроса к сервису.
     * Пользователь должен быть загружен вместе с сервисами (как его отдаёт AccessVerifier).
     */
    public String assertion(User user, ProtectedService service, HttpServletRequest request) {
        requireEnabled();
        String sid = sessionHash(request);
        String cacheKey = user.getId() + "|" + service.getId() + "|" + sid;
        long now = clock.instant().getEpochSecond();

        Cached cached = assertionCache.get(cacheKey);
        if (cached != null && cached.expiresAt - now >= REUSE_MIN_REMAINING_SECONDS) {
            return cached.token;
        }
        GateClaims claims = base(user, service, sid).build(TokenType.ASSERTION);
        String token = signer.sign(TokenType.ASSERTION, claims);

        if (assertionCache.size() > CACHE_MAX) {
            assertionCache.values().removeIf(c -> c.expiresAt <= now);
        }
        assertionCache.put(cacheKey, new Cached(token, claims.expiresAt()));
        return token;
    }

    /** Direct mode: одноразовый токен для callback-а приложения, привязанный к nonce приложения. */
    public String handoff(User user, ProtectedService service, String nonce, HttpServletRequest request) {
        requireEnabled();
        GateClaims claims = base(user, service, sessionHash(request))
                .nonce(nonce)
                .authTime(user.getLastLoginAt())
                .build(TokenType.HANDOFF);
        return signer.sign(TokenType.HANDOFF, claims);
    }

    /**
     * Сброс кеша. Роли и доступы и так подхватятся не позже чем через ~30 с, но после правки
     * в админке незачем ждать и этого.
     */
    public void evictCache() {
        assertionCache.clear();
    }

    private GateClaims.Builder base(User user, ProtectedService service, String sid) {
        return GateClaims.builder()
                .issuer(issuer)
                .subject(String.valueOf(user.getId()))
                .preferredUsername(user.getUsername())
                .audience(service.getName())
                .gateRole(user.getRole().name())
                .roles(rolesFor(user, service))
                .services(accessibleServiceNames(user))
                .issuedAt(Instant.now(clock))
                .sessionId(sid);
    }

    private List<String> rolesFor(User user, ProtectedService service) {
        return roleRepository.findById(new UserServiceRole.Key(user.getId(), service.getId()))
                .map(r -> List.of(r.getRole()))
                .orElse(List.of());
    }

    /** То же правило, что у портала: админ при adminBypassesAccess видит все включённые сервисы. */
    private List<String> accessibleServiceNames(User user) {
        if (user.isAdmin() && settingsService.get().adminBypassesAccess()) {
            return serviceRepository.findByEnabledTrueOrderBySortOrderAscDisplayNameAsc().stream()
                    .map(ProtectedService::getName).toList();
        }
        return user.getServices().stream()
                .filter(ProtectedService::isEnabled)
                .map(ProtectedService::getName)
                .sorted()
                .toList();
    }

    /**
     * Хеш id сессии, а не сам id (§4.2): по claim sid приложения сопоставляют логи,
     * но id сессии в токене годился бы для её угона.
     */
    static String sessionHash(HttpServletRequest request) {
        HttpSession session = request.getSession(false);
        if (session == null) {
            return null;
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(session.getId().getBytes(StandardCharsets.UTF_8));
            return Base64Url.encode(hash).substring(0, 22);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void requireEnabled() {
        if (signer == null) {
            throw new IllegalStateException("Gate Auth disabled: no signing key");
        }
    }

    /**
     * Ключ — приватный JWK одной строкой: либо прямо в GATE_SIGNING_KEY (так он едет из локального
     * .env при деплое через docker context, как остальные секреты), либо файлом GATE_SIGNING_KEY_FILE.
     */
    private static GateSigningKey loadKey(String inline, String file) {
        if (inline != null && !inline.isBlank()) {
            try {
                return GateSigningKey.fromPrivateJwk(inline);
            } catch (RuntimeException e) {
                throw new IllegalStateException("GATE_SIGNING_KEY не похож на приватный JWK Ed25519: " + e.getMessage(), e);
            }
        }
        if (file == null || file.isBlank()) {
            return null;
        }
        try {
            return GateSigningKey.fromPrivateJwk(Files.readString(Path.of(file.trim()), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            // Ключ задан, но не читается — это ошибка конфигурации, а не «работаем без токенов»:
            // молча стартовать без подписи значило бы сломать вход во все приложения.
            throw new IllegalStateException("Не удалось прочитать ключ подписи из " + file + ": " + e.getMessage(), e);
        }
    }

    private record Cached(String token, long expiresAt) {
    }
}
