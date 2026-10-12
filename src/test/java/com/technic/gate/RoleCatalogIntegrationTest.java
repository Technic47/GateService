package com.technic.gate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.technic.gate.domain.AppRole;
import com.technic.gate.domain.ProtectedService;
import com.technic.gate.domain.Role;
import com.technic.gate.domain.User;
import com.technic.gate.repo.UserRepository;
import com.technic.gate.security.GateUserDetails;
import com.technic.gate.service.GateException;
import com.technic.gate.service.RoleCatalogService;
import com.technic.gate.service.ServiceCatalogService;
import com.technic.gate.service.UserAdminService;
import io.github.technic47.gateauth.core.GateClaims;
import io.github.technic47.gateauth.core.GateKeySet;
import io.github.technic47.gateauth.core.GateSigningKey;
import io.github.technic47.gateauth.core.RoleCatalog;
import io.github.technic47.gateauth.core.TokenVerifier;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;

/**
 * Справочник ролей (Gate Auth §4.4–4.5) на настоящем PostgreSQL 16: глобальные роли и роли сервиса, несколько
 * ролей на пару пользователь+приложение, rv в токене, подписанный каталог, правила архива и кодов.
 */
@SpringBootTest
@Testcontainers
class RoleCatalogIntegrationTest {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:16");

    private static final GateSigningKey KEY = GateSigningKey.generate();

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
    RoleCatalogService roles;
    @Autowired
    UserAdminService userAdmin;
    @Autowired
    UserRepository userRepository;

    MockMvc mvc;
    ProtectedService bike;
    ProtectedService fashion;
    AppRole viewer;
    AppRole editor;

    @BeforeEach
    void setUp() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        if (userRepository.findByUsernameIgnoreCase("carol").isPresent()) {
            bike = serviceCatalog.findAll().stream().filter(s -> s.getName().equals("bike2")).findFirst().orElseThrow();
            fashion = serviceCatalog.findAll().stream().filter(s -> s.getName().equals("fashion2")).findFirst().orElseThrow();
            return;
        }
        bike = serviceCatalog.save(null, "bike2", "Bike", null, "https", "127.0.0.1", 8081,
                null, true, null, 0, false, null, "/api/", "test");
        fashion = serviceCatalog.save(null, "fashion2", "Fashion", null, "http", "127.0.0.1", 8080,
                null, true, null, 0, false, null, null, "test");
        viewer = roles.create("viewer", "Viewer", "Read everything", null, 0, "test");
        editor = roles.create("editor", "Editor", null, bike.getId(), 1, "test");
        roles.create("measurer", "Measurer", null, fashion.getId(), 0, "test");
        userAdmin.create("carol", "carol-password-1", Role.USER, true, Set.of(bike.getId()),
                Map.of(bike.getId(), Set.of(viewer.getId(), editor.getId())), "test");
    }

    @Test
    void tokenCarriesAllRolesOfTheGrantAndTheCatalogVersion() throws Exception {
        String assertion = mvc.perform(get("/verify").header("X-Service-Name", "bike2").with(as("carol")))
                .andExpect(status().isOk()).andReturn().getResponse().getHeader("X-Gate-Assertion");
        GateClaims c = verifier("bike2").verifyAssertion(assertion);
        assertThat(c.roles()).containsExactly("editor", "viewer");
        assertThat(c.roleVersion()).isEqualTo(roles.version());
    }

    @Test
    void catalogIsSignedAndHoldsGlobalAndOwnRolesOnly() throws Exception {
        String body = mvc.perform(get("/.well-known/gate/apps/bike2/roles"))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/jwt"))
                .andReturn().getResponse().getContentAsString();
        RoleCatalog catalog = verifier("bike2").verifyRoleCatalog(body);
        assertThat(catalog.roles()).extracting(RoleCatalog.Role::code).startsWith("viewer", "editor"); // by sort order; other tests add roles
        assertThat(catalog.find("viewer").global()).isTrue();
        assertThat(catalog.find("viewer").description()).isEqualTo("Read everything");
        assertThat(catalog.find("measurer")).isNull(); // another service's role
        assertThat(catalog.catalogVersion()).isEqualTo(roles.version());

        mvc.perform(get("/.well-known/gate/apps/nope/roles")).andExpect(status().isNotFound());
    }

    @Test
    void everyChangeRaisesTheVersionAndArchiveNeedsAnUnusedRole() {
        AppRole temp = roles.create("temp", "Temp", null, bike.getId(), 9, "test");
        long v1 = roles.version();
        roles.update(temp.getId(), "Temporary", "for a test", 9, "test");
        assertThat(roles.version()).isGreaterThan(v1);

        AppRole assigned = roles.allForAdmin().stream().map(RoleCatalogService.RoleRow::role)
                .filter(r -> r.getCode().equals("editor")).findFirst().orElseThrow();
        assertThatThrownBy(() -> roles.setArchived(assigned.getId(), true, "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("выдана");

        long v2 = roles.version();
        roles.setArchived(temp.getId(), true, "test");
        assertThat(roles.version()).isGreaterThan(v2);
        assertThat(roles.assignable(bike.getId())).extracting(AppRole::getCode).doesNotContain("temp");
        assertThatThrownBy(() -> userAdmin.update(userRepository.findByUsernameIgnoreCase("carol").orElseThrow().getId(),
                Role.USER, true, Set.of(bike.getId()), Map.of(bike.getId(), Set.of(temp.getId())), "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("архиве");
    }

    @Test
    void codesNeverCollideWithinAnApp() {
        assertThatThrownBy(() -> roles.create("viewer", "Viewer 2", null, bike.getId(), 0, "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("глобальная");
        assertThatThrownBy(() -> roles.create("measurer", "Measurer", null, null, 0, "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("одного из сервисов");
        assertThatThrownBy(() -> roles.create("Bad Code", "x", null, null, 0, "test"))
                .isInstanceOf(GateException.class);
        // a role of another app can't be given here
        AppRole measurer = roles.assignable(fashion.getId()).stream()
                .filter(r -> r.getCode().equals("measurer")).findFirst().orElseThrow();
        assertThatThrownBy(() -> userAdmin.update(userRepository.findByUsernameIgnoreCase("carol").orElseThrow().getId(),
                Role.USER, true, Set.of(bike.getId()), Map.of(bike.getId(), Set.of(measurer.getId())), "test"))
                .isInstanceOf(GateException.class);
    }

    @Test
    void scopeCanChangeWhenNothingBreaks() {
        // an app role becomes global: assignments stay, other apps can now use it
        AppRole reviewer = roles.create("reviewer", "Reviewer", null, bike.getId(), 5, "test");
        long v = roles.version();
        roles.changeScope(reviewer.getId(), null, "test");
        assertThat(roles.require(reviewer.getId()).isGlobal()).isTrue();
        assertThat(roles.version()).isGreaterThan(v);
        assertThat(roles.assignable(fashion.getId())).extracting(AppRole::getCode).contains("reviewer");

        // ...and back to one app, as long as it isn't given in another app
        roles.changeScope(reviewer.getId(), fashion.getId(), "test");
        assertThat(roles.assignable(bike.getId())).extracting(AppRole::getCode).doesNotContain("reviewer");

        // the same code in two apps can't become one global role
        AppRole a = roles.create("tester", "Tester", null, bike.getId(), 6, "test");
        roles.create("tester", "Tester", null, fashion.getId(), 6, "test");
        assertThatThrownBy(() -> roles.changeScope(a.getId(), null, "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("другом сервисе");

        // a global role given in bike2 can't become a fashion2-only role
        AppRole globalViewer = roles.assignable(bike.getId()).stream()
                .filter(r -> r.getCode().equals("viewer")).findFirst().orElseThrow();
        assertThatThrownBy(() -> roles.changeScope(globalViewer.getId(), fashion.getId(), "test"))
                .isInstanceOf(GateException.class).hasMessageContaining("выдана в других");
    }

    @Test
    void adminPagesRender() throws Exception {
        User admin = userRepository.findByUsernameIgnoreCase("admin").orElseThrow();
        RequestPostProcessor asAdmin = user(new GateUserDetails(admin));
        mvc.perform(get("/admin/roles").with(asAdmin)).andExpect(status().isOk());
        mvc.perform(get("/admin/roles/new").with(asAdmin)).andExpect(status().isOk());
        Long carol = userRepository.findByUsernameIgnoreCase("carol").orElseThrow().getId();
        String form = mvc.perform(get("/admin/users/" + carol).with(asAdmin)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertThat(form).contains("appRole_" + bike.getId()).contains("checked");
    }

    private RequestPostProcessor as(String username) {
        User u = userRepository.findByUsernameIgnoreCase(username).orElseThrow();
        return user(new GateUserDetails(u));
    }

    private static TokenVerifier verifier(String app) {
        return new TokenVerifier(GateKeySet.of(KEY.publicKey()), "gate", app);
    }
}
