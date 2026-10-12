package com.technic.gate.web;

import com.technic.gate.service.RoleCatalogService;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

/**
 * Каталог ролей приложения (Gate Auth §4.5): какие роли гейт может выдать этому приложению.
 * Без аутентификации: коды и названия ролей не секрет, а ответ подписан ключом гейта — приложение
 * проверяет подпись тем же открытым ключом, что и токены.
 */
@RestController
public class RoleCatalogController {

    private static final MediaType JWT = MediaType.parseMediaType("application/jwt");

    private final RoleCatalogService roleCatalog;

    public RoleCatalogController(RoleCatalogService roleCatalog) {
        this.roleCatalog = roleCatalog;
    }

    @GetMapping("/.well-known/gate/apps/{app}/roles")
    public ResponseEntity<String> roles(@PathVariable String app) {
        return roleCatalog.catalogFor(app)
                .map(token -> ResponseEntity.ok()
                        .contentType(JWT)
                        .cacheControl(CacheControl.noCache())
                        .body(token))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
