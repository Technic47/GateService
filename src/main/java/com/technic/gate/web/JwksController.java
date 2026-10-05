package com.technic.gate.web;

import com.technic.gate.service.GateTokenService;
import java.time.Duration;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Публичные ключи гейта (§3 спецификации). Без аутентификации: это открытые ключи.
 * Приложения хранят ключ у себя статически, отсюда его удобно взять и сверить.
 */
@RestController
public class JwksController {

    private static final MediaType JWK_SET = MediaType.parseMediaType("application/jwk-set+json");

    private final GateTokenService tokenService;

    public JwksController(GateTokenService tokenService) {
        this.tokenService = tokenService;
    }

    @GetMapping("/.well-known/jwks.json")
    public ResponseEntity<String> jwks() {
        return tokenService.jwks()
                .map(body -> ResponseEntity.ok()
                        .contentType(JWK_SET)
                        .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                        .body(body))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
