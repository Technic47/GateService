package com.technic.gate.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.domain.UserServiceRole;
import com.technic.gate.repo.ProtectedServiceRepository;
import com.technic.gate.repo.UserServiceRoleRepository;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateKeySet;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.TokenVerifier;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class GateTokenServiceTest {

    private final GateSigningKey key = GateSigningKey.generate();
    private final UserServiceRoleRepository roles = mock(UserServiceRoleRepository.class);
    private final ProtectedServiceRepository services = mock(ProtectedServiceRepository.class);
    private final GateSettingsService settings = mock(GateSettingsService.class);

    private GateTokenService tokens;
    private ProtectedService bikeservice;
    private ProtectedService fashionmark;
    private User alice;

    @BeforeEach
    void setUp() throws Exception {
        when(settings.get()).thenReturn(GateSettings.defaults());
        tokens = new GateTokenService(key, "gate", roles, services, settings, java.time.Clock.systemUTC());

        bikeservice = service(10L, "bikeservice");
        fashionmark = service(11L, "fashionmark");
        alice = new User("alice", "x", Role.USER);
        setId(alice, 42L);
        alice.setLastLoginAt(Instant.parse("2026-10-05T10:00:00Z"));
        alice.setServices(Set.of(bikeservice, fashionmark));
        when(roles.findById(any())).thenReturn(Optional.empty());
        when(roles.findById(new UserServiceRole.Key(42L, 10L)))
                .thenReturn(Optional.of(new UserServiceRole(42L, 10L, "member")));
    }

    @Test
    void assertionCarriesUserAppRolesAndServices() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        String token = tokens.assertion(alice, bikeservice, request);

        GateClaims c = verifier("bikeservice").verifyAssertion(token);
        assertThat(c.subject()).isEqualTo("42");
        assertThat(c.preferredUsername()).isEqualTo("alice");
        assertThat(c.gateRole()).isEqualTo("USER");
        assertThat(c.roles()).containsExactly("member");
        assertThat(c.services()).containsExactly("bikeservice", "fashionmark");
        assertThat(c.sessionId()).hasSize(22).isNotEqualTo(request.getSession().getId());
    }

    @Test
    void assertionIsReusedWithinTheSameSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        assertThat(tokens.assertion(alice, bikeservice, request))
                .isEqualTo(tokens.assertion(alice, bikeservice, request));
        tokens.evictCache();
        // новый токен после сброса кеша (другой jti)
        assertThat(tokens.assertion(alice, fashionmark, request)).isNotEqualTo(tokens.assertion(alice, bikeservice, request));
    }

    @Test
    void handoffIsBoundToNonceAndCarriesAuthTime() throws Exception {
        String token = tokens.handoff(alice, bikeservice, "nonce-nonce-nonce-1", new MockHttpServletRequest());
        GateClaims c = verifier("bikeservice").verifyHandoff(token, "nonce-nonce-nonce-1");
        assertThat(c.authTime()).isEqualTo(Instant.parse("2026-10-05T10:00:00Z").getEpochSecond());
        assertThat(c.roles()).containsExactly("member");
    }

    @Test
    void adminWithBypassSeesAllEnabledServices() throws Exception {
        User admin = new User("root", "x", Role.ADMIN);
        setId(admin, 1L);
        when(services.findByEnabledTrueOrderBySortOrderAscDisplayNameAsc()).thenReturn(List.of(bikeservice, fashionmark));
        String token = tokens.assertion(admin, bikeservice, new MockHttpServletRequest());
        GateClaims c = verifier("bikeservice").verifyAssertion(token);
        assertThat(c.gateRole()).isEqualTo("ADMIN");
        assertThat(c.roles()).isEmpty();
        assertThat(c.services()).containsExactly("bikeservice", "fashionmark");
    }

    @Test
    void jwksPublishesOnlyThePublicKey() {
        String jwks = tokens.jwks().orElseThrow();
        assertThat(GateKeySet.parse(jwks).asMap()).containsOnlyKeys(key.kid());
        assertThat(jwks).doesNotContain("\"d\"");
    }

    @Test
    void withoutKeyTokensAreDisabled() {
        GateTokenService disabled = new GateTokenService(null, "gate", roles, services, settings,
                java.time.Clock.systemUTC());
        assertThat(disabled.enabled()).isFalse();
        assertThat(disabled.jwks()).isEmpty();
    }

    private TokenVerifier verifier(String app) {
        return new TokenVerifier(GateKeySet.of(key.publicKey()), "gate", app);
    }

    private static ProtectedService service(Long id, String name) throws Exception {
        ProtectedService s = new ProtectedService(name, name, "127.0.0.1", 8080);
        setId(s, id);
        return s;
    }

    private static void setId(Object entity, Long id) throws Exception {
        Field f = entity.getClass().getDeclaredField("id");
        f.setAccessible(true);
        f.set(entity, id);
    }
}
