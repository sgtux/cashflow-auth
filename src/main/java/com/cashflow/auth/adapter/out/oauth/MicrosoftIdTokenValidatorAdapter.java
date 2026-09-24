package com.cashflow.auth.adapter.out.oauth;

import com.cashflow.auth.application.port.out.ValidateMicrosoftIdTokenOutputPort;
import com.cashflow.auth.config.OAuthProperties;
import com.cashflow.auth.domain.InvalidProviderTokenException;
import com.cashflow.auth.domain.OAuthProvider;
import com.cashflow.auth.domain.ProviderIdentity;
import com.cashflow.auth.domain.TokenExpiredException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Set;

/**
 * Valida o ID token (JWT OIDC) do Microsoft Entra ID. Mesmo mecanismo do
 * {@link GoogleIdTokenValidatorAdapter} (JWKSourceBuilder do Nimbus), issuer e
 * JWKS montados a
 * partir do {@code tenant-id} configurado. Ver ./docs/especificacao.md secao 6.
 *
 * <p>
 * <strong>Limitacao conhecida (divida proposital):</strong> so suporta um
 * tenant fixo
 * ({@code auth.oauth.microsoft.tenant-id}). Um app multi-tenant (endpoint
 * {@code /common/}) tem
 * um {@code iss} diferente por tenant (guid do tenant no path) - validar isso
 * exigiria trocar a
 * comparacao exata de issuer por um padrao/prefixo, o que nao foi feito aqui de
 * proposito
 * (YAGNI ate existir um cliente multi-tenant de verdade).
 * </p>
 *
 * <p>
 * O claim {@code email} so vem preenchido se o app registration pedir o
 * optional claim
 * "email" no Entra ID; por isso o fallback para {@code preferred_username} (o
 * UPN da conta, que
 * normalmente e um email valido para contas corporativas/escolares).
 * </p>
 */
@Component
public class MicrosoftIdTokenValidatorAdapter implements ValidateMicrosoftIdTokenOutputPort {

    private static final Set<String> REQUIRED_CLAIMS = Set.of("sub", "exp");

    private final ConfigurableJWTProcessor<SecurityContext> processor;

    public MicrosoftIdTokenValidatorAdapter(OAuthProperties properties) {
        this.processor = buildProcessor(properties.microsoft());
    }

    @Override
    public ProviderIdentity validate(String idToken) {
        try {
            JWTClaimsSet claims = processor.process(idToken, null);

            String email = firstNonBlank(claims.getStringClaim("email"), claims.getStringClaim("preferred_username"));
            if (email == null) {
                throw new InvalidProviderTokenException();
            }
            return new ProviderIdentity(claims.getSubject(), email, OAuthProvider.MICROSOFT);
        } catch (InvalidProviderTokenException e) {
            throw e;
        } catch (BadJWTException e) {
            if (e.getMessage().contains("Expired JWT")) {
                throw new TokenExpiredException(e);
            }
            throw new InvalidProviderTokenException(e);
        } catch (Exception e) {
            throw new InvalidProviderTokenException(e);
        }
    }

    private static String firstNonBlank(String a, String b) {
        if (a != null && !a.isBlank()) {
            return a;
        }
        return (b != null && !b.isBlank()) ? b : null;
    }

    private static ConfigurableJWTProcessor<SecurityContext> buildProcessor(OAuthProperties.Microsoft config) {
        String tenantId = config.tenantId();
        String issuer = "https://login.microsoftonline.com/" + tenantId + "/v2.0";
        String jwksUri = "https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys";
        try {
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource = JWKSourceBuilder
                    .create(URI.create(jwksUri).toURL())
                    .build();
            jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource));

            JWTClaimsSet exactMatch = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .audience(config.clientId())
                    .build();
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(exactMatch, REQUIRED_CLAIMS));
            return jwtProcessor;
        } catch (MalformedURLException e) {
            throw new IllegalStateException(
                    "URL do JWKS do Microsoft invalida (auth.oauth.microsoft.tenant-id configurado?)", e);
        }
    }
}
