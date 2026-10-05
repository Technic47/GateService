package com.technic.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.repo.UserRepository;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.ServiceCatalogService;
import com.technic.gate.service.UserAdminService;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateKeySet;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.TokenVerifier;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Gate Auth на настоящем PostgreSQL 16 (та же мажорная версия, что на VPS): миграция V2 + validate,
 * /verify с X-Gate-Assertion, JWKS и /auth/handoff. Токены проверяются тем же кодом, что и в приложениях.
 */
@SpringBootTest
@Testcontainers
class GateAuthIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    private static final GateSigningKey KEY = GateSigningKey.generate();
    private static final String CALLBACK = "https://192.168.1.50:8443/auth/callback";
    private static final String STATE = "state-state-state-state-1";
    private static final String NONCE = "nonce-nonce-nonce-nonce-1";

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("gate.auth.signing-key", KEY::toPrivateJwk);
        r.add("gate.remember-me-key", () -> "test-only-remember-me-key");
        r.add("gate.admin.password", () -> "admin-password-1");
        r.add("server.servlet.session.cookie.secure", () -> "false");
    }

    @Autowired
    WebApplicationContext context;
    @Autowired
    ServiceCatalogService serviceCatalog;
    @Autowired
    UserAdminService userAdmin;
    @Autowired
    UserRepository userRepository;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        if (userRepository.findByUsernameIgnoreCase("alice").isPresent()) {
            return;
        }
        var bike = serviceCatalog.save(null, "bikeservice", "Bike", null, "https", "127.0.0.1", 8081,
                "https://144.31.187.7:8845", true, null, 0, true, CALLBACK, "/api/", "test");
        serviceCatalog.save(null, "nodirect", "No direct", null, "http", "127.0.0.1", 8082,
                null, true, null, 0, false, null, null, "test");
        userAdmin.create("alice", "alice-password-1", Role.USER, true, Set.of(bike.getId()),
                Map.of(bike.getId(), "Member"), "test");
        userAdmin.create("bob", "bob-password-1", Role.USER, true, Set.of(), Map.of(), "test");
    }

    // ------------------------------------------------------------------ edge: /verify

    @Test
    void verifyReturnsSignedAssertionForTheService() throws Exception {
        MockHttpServletResponse res = mvc.perform(get("/verify").header("X-Service-Name", "bikeservice").with(as("alice")))
                .andExpect(status().isOk()).andReturn().getResponse();

        GateClaims c = verifier("bikeservice").verifyAssertion(res.getHeader("X-Gate-Assertion"));
        assertThat(c.preferredUsername()).isEqualTo("alice");
        assertThat(c.subject()).isEqualTo(String.valueOf(id("alice")));
        assertThat(c.roles()).containsExactly("member"); // приведена к нижнему регистру
        assertThat(c.services()).containsExactly("bikeservice");
        assertThat(res.getHeader("X-Gate-User")).isEqualTo("alice"); // старый заголовок остался
    }

    @Test
    void deniedVerifyHasNoAssertion() throws Exception {
        MockHttpServletResponse res = mvc.perform(get("/verify").header("X-Service-Name", "bikeservice").with(as("bob")))
                .andExpect(status().isForbidden()).andReturn().getResponse();
        assertThat(res.getHeader("X-Gate-Assertion")).isNull();
    }

    @Test
    void jwksIsPublic() throws Exception {
        String body = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(GateKeySet.parse(body).asMap()).containsOnlyKeys(KEY.kid());
    }

    // ------------------------------------------------------------------ direct: /auth/handoff

    @Test
    void handoffWithoutSessionGoesToLoginAndComesBack() throws Exception {
        MockHttpServletResponse res = mvc.perform(handoff("bikeservice", CALLBACK, null))
                .andExpect(status().is3xxRedirection()).andReturn().getResponse();
        String location = URLDecoder.decode(res.getRedirectedUrl(), StandardCharsets.UTF_8);
        assertThat(location).startsWith("/login?redirect=/auth/handoff?");
        assertThat(location).contains("client_id=bikeservice");
        // после входа обработчик успеха должен принять этот адрес как свой относительный путь
        String back = location.substring("/login?redirect=".length());
        assertThat(com.technic.gate.security.RedirectTargets.isLocalPath(back)).isTrue();
    }

    @Test
    void silentHandoffWithoutSessionAnswersLoginRequired() throws Exception {
        MockHttpServletResponse res = mvc.perform(handoff("bikeservice", CALLBACK, "none"))
                .andExpect(status().isOk()).andReturn().getResponse();
        Map<String, String> form = form(res.getContentAsString());
        assertThat(form).containsEntry("error", "login_required").containsEntry("state", STATE);
        assertThat(action(res.getContentAsString())).isEqualTo(CALLBACK);
    }

    @Test
    void handoffIssuesNonceBoundTokenInAutoPostForm() throws Exception {
        MockHttpServletResponse res = mvc.perform(handoff("bikeservice", CALLBACK, null).with(as("alice")))
                .andExpect(status().isOk()).andReturn().getResponse();

        String html = res.getContentAsString();
        assertThat(action(html)).isEqualTo(CALLBACK);
        Map<String, String> form = form(html);
        assertThat(form).containsEntry("state", STATE);
        GateClaims c = verifier("bikeservice").verifyHandoff(form.get("id_token"), NONCE);
        assertThat(c.preferredUsername()).isEqualTo("alice");
        assertThat(c.roles()).containsExactly("member");

        String csp = res.getHeader("Content-Security-Policy");
        assertThat(csp).contains("form-action https://192.168.1.50:8443").contains("script-src 'sha256-");
        assertThat(res.getHeader("Cache-Control")).contains("no-store");
    }

    @Test
    void handoffForUserWithoutAccessAnswersAccessDenied() throws Exception {
        String html = mvc.perform(handoff("bikeservice", CALLBACK, null).with(as("bob")))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertThat(form(html)).containsEntry("error", "access_denied").doesNotContainKey("id_token");
    }

    @Test
    void unregisteredRedirectUriNeverReceivesAnything() throws Exception {
        String evil = "https://evil.example/auth/callback";
        String html = mvc.perform(handoff("bikeservice", evil, null).with(as("alice")))
                .andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsString();
        assertThat(html).doesNotContain("evil.example").doesNotContain("id_token");
    }

    @Test
    void serviceWithoutDirectModeIsRefused() throws Exception {
        mvc.perform(handoff("nodirect", CALLBACK, null).with(as("alice"))).andExpect(status().isBadRequest());
        mvc.perform(handoff("unknown", CALLBACK, null).with(as("alice"))).andExpect(status().isBadRequest());
    }

    @Test
    void malformedRequestIsRefused() throws Exception {
        mvc.perform(get("/auth/handoff").param("response_type", "code").param("response_mode", "form_post")
                        .param("client_id", "bikeservice").param("redirect_uri", CALLBACK)
                        .param("state", STATE).param("nonce", NONCE).with(as("alice")))
                .andExpect(status().isBadRequest());
        mvc.perform(get("/auth/handoff").param("response_type", "id_token").param("response_mode", "form_post")
                        .param("client_id", "bikeservice").param("redirect_uri", CALLBACK)
                        .param("state", "short").param("nonce", NONCE).with(as("alice")))
                .andExpect(status().isBadRequest());
    }

    // ------------------------------------------------------------------ helpers

    private MockHttpServletRequestBuilder handoff(String clientId, String redirectUri, String prompt) {
        MockHttpServletRequestBuilder b = get("/auth/handoff")
                .param("response_type", "id_token").param("response_mode", "form_post")
                .param("client_id", clientId).param("redirect_uri", redirectUri)
                .param("state", STATE).param("nonce", NONCE);
        return prompt == null ? b : b.param("prompt", prompt);
    }

    private RequestPostProcessor as(String username) {
        User u = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        return user(new GateUserDetails(u));
    }

    private Long id(String username) {
        return userRepository.findByUsernameIgnoreCase(username).orElseThrow().getId();
    }

    private static TokenVerifier verifier(String app) {
        return new TokenVerifier(GateKeySet.of(KEY.publicKey()), "gate", app);
    }

    private static String action(String html) {
        Matcher m = Pattern.compile("<form method=\"post\" action=\"([^\"]+)\"").matcher(html);
        assertThat(m.find()).isTrue();
        return m.group(1).replace("&amp;", "&");
    }

    private static Map<String, String> form(String html) {
        Map<String, String> fields = new java.util.LinkedHashMap<>();
        Matcher m = Pattern.compile("<input type=\"hidden\" name=\"([^\"]+)\" value=\"([^\"]*)\">").matcher(html);
        while (m.find()) {
            fields.put(m.group(1), m.group(2));
        }
        return fields;
    }
}
