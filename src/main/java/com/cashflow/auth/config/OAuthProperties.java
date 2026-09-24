package com.cashflow.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuracao do login social (prefixo {@code auth.oauth.*} em application.yml).
 * Ver ./docs/especificacao.md secao 6.
 */
@ConfigurationProperties(prefix = "auth.oauth")
public record OAuthProperties(Google google, Microsoft microsoft) {

    /** @param clientId client ID do app registrado no Google Cloud Console - valida a claim {@code aud}. */
    public record Google(String clientId) {
    }

    /**
     * @param clientId client ID (Application ID) do app registrado no Microsoft Entra ID.
     * @param tenantId tenant ID do Microsoft Entra ID. Suporta apenas single-tenant por enquanto -
     *                 ver comentario em {@code MicrosoftIdTokenValidatorAdapter} sobre multi-tenant.
     */
    public record Microsoft(String clientId, String tenantId) {
    }
}
