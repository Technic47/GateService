package com.technic.gate.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.technic.gate.domain.ProtectedService;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Валидация настроек Gate Auth у сервиса и то, что из них генерируется для Nginx. */
class GateAuthConfigTest {

    @Test
    void redirectUrisAreNormalizedOnePerLine() {
        assertThat(ServiceCatalogService.normalizeRedirectUris(
                "  https://192.168.1.50:8443/auth/callback \n\nhttp://localhost:8080/auth/callback\n"))
                .isEqualTo("https://192.168.1.50:8443/auth/callback\nhttp://localhost:8080/auth/callback");
        assertThat(ServiceCatalogService.normalizeRedirectUris("  ")).isNull();
    }

    @Test
    void dangerousRedirectUrisAreRejected() {
        for (String bad : List.of(
                "http://192.168.1.50/auth/callback",                 // http не на localhost
                "https://user@192.168.1.50/auth/callback",           // логин в адресе
                "https://192.168.1.50/auth/callback#x",               // фрагмент
                "https://192.168.1.50/auth/callback?x=1",             // query
                "/auth/callback",                                     // не абсолютный
                "javascript:alert(1)",
                "https://192.168.1.50")) {                            // без пути
            assertThatThrownBy(() -> ServiceCatalogService.normalizeRedirectUris(bad))
                    .as(bad).isInstanceOf(GateException.class);
        }
    }

    @Test
    void redirectUriMatchIsExact() {
        ProtectedService s = new ProtectedService("bikeservice", "Bike", "127.0.0.1", 8081);
        s.setRedirectUris("https://192.168.1.50:8443/auth/callback");
        assertThat(s.isRegisteredRedirectUri("https://192.168.1.50:8443/auth/callback")).isTrue();
        assertThat(s.isRegisteredRedirectUri("https://192.168.1.50:8443/auth/callback/")).isFalse();
        assertThat(s.isRegisteredRedirectUri("https://192.168.1.50:8443/auth/callback/../x")).isFalse();
        assertThat(s.isRegisteredRedirectUri("HTTPS://192.168.1.50:8443/auth/callback")).isFalse();
        assertThat(s.isRegisteredRedirectUri(null)).isFalse();
    }

    @Test
    void apiPrefixMustBeASafePath() {
        assertThat(ServiceCatalogService.normalizeApiPrefix(" /api/ ")).isEqualTo("/api/");
        assertThat(ServiceCatalogService.normalizeApiPrefix("/api/v1/")).isEqualTo("/api/v1/");
        assertThat(ServiceCatalogService.normalizeApiPrefix("")).isNull();
        for (String bad : List.of("api/", "/api", "/api/; return 200;", "/a pi/", "/api/{x}/")) {
            assertThatThrownBy(() -> ServiceCatalogService.normalizeApiPrefix(bad))
                    .as(bad).isInstanceOf(GateException.class);
        }
    }

    @Test
    void nginxConfigForwardsAssertionAndAnswersApiWithJson() {
        ProtectedService s = new ProtectedService("bikeservice", "Bike", "127.0.0.1", 8081);
        s.setApiPrefix("/api/");
        String conf = new NginxConfigGenerator(9000).generate(List.of(s), "https://144.31.187.7");

        assertThat(conf).contains("location /api/ {");
        assertThat(conf).contains("auth_request_set $gate_assertion $upstream_http_x_gate_assertion;");
        assertThat(conf).contains("proxy_set_header X-Gate-Assertion $gate_assertion;");
        assertThat(conf).contains("error_page 401 = @gate_api_401;");
        assertThat(conf).contains("\"login_url\":\"https://144.31.187.7/login\"");
        // HTML-страницы по-прежнему уходят на форму входа
        assertThat(conf).contains("error_page 401 = @gate_login;");
        // и в обоих location — одна и та же пара заголовков
        assertThat(conf.split("proxy_set_header X-Gate-Assertion", -1)).hasSize(3);
    }

    @Test
    void nginxConfigWithoutApiPrefixHasNoApiBlock() {
        ProtectedService s = new ProtectedService("fashionmark", "FM", "127.0.0.1", 8080);
        String conf = new NginxConfigGenerator(9000).generate(List.of(s), "https://144.31.187.7");
        assertThat(conf).doesNotContain("@gate_api_401");
        assertThat(conf).contains("proxy_set_header X-Gate-Assertion $gate_assertion;");
    }
}
