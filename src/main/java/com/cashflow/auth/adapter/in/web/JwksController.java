package com.cashflow.auth.adapter.in.web;

import com.cashflow.auth.config.SigningKeys;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.util.Map;

/**
 * {@code GET /.well-known/jwks.json} - conjunto de chaves PUBLICAS. E so isso que os outros
 * servicos precisam para validar os tokens (offline, sem chamar o cashflow-auth por request).
 * Ver ./docs/especificacao.md secao 4 e ./docs/migracao-hs256-rs256.md.
 *
 * <p>Endpoint publico e cacheavel. Os clientes (Nimbus {@code RemoteJWKSet}, o
 * {@code ConfigurationManager} do .NET) respeitam o {@code Cache-Control} e so rebuscam quando
 * veem um {@code kid} desconhecido.</p>
 */
@RestController
public class JwksController {

    private final SigningKeys signingKeys;

    public JwksController(SigningKeys signingKeys) {
        this.signingKeys = signingKeys;
    }

    @GetMapping(path = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> jwks() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(Duration.ofHours(1)).cachePublic())
                .body(signingKeys.publicJwks());
    }
}
