package com.cashflow.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuracao do emissor (prefixo {@code auth.*} em application.yml). Ver ./docs/especificacao.md secoes 3 e 5.
 */
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        String issuer,
        int tokenTtlMinutes,
        String activeKid,
        String privateKeyPem,
        String additionalJwks,
        boolean devGenerateKey
) {

    public Duration tokenTtl() {
        return Duration.ofMinutes(tokenTtlMinutes);
    }

    public boolean hasConfiguredPrivateKey() {
        return privateKeyPem != null && !privateKeyPem.isBlank();
    }

    public boolean hasAdditionalJwks() {
        return additionalJwks != null && !additionalJwks.isBlank();
    }
}
