package com.cashflow.auth.adapter.out.oauth;

import com.cashflow.auth.application.port.out.ValidateGoogleIdTokenOutputPort;
import com.cashflow.auth.config.OAuthProperties;
import com.cashflow.auth.domain.InvalidProviderTokenException;
import com.cashflow.auth.domain.OAuthProvider;
import com.cashflow.auth.domain.ProviderIdentity;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URI;
import java.util.Set;

/**
 * Valida o ID token (JWT OIDC) do Google Sign-In. Assinatura verificada via o JWKS publico do
 * Google (JWKSourceBuilder do Nimbus - mesma lib usada para assinar em NimbusRsaTokenSigner, so
 * que aqui pra VERIFICAR uma chave alheia; cacheado, sem round-trip por request). Issuer e audience
 * (client id) sao conferidos junto na mesma verificacao. Ver ./docs/especificacao.md secao 6.
 *
 * <p>O JWKS do Google fica em {@code https://www.googleapis.com/oauth2/v3/certs} - NAO no path
 * {@code /.well-known/jwks.json} (o Google referencia esse endpoint via {@code jwks_uri} no
 * discovery document deles, {@code https://accounts.google.com/.well-known/openid-configuration}).</p>
 */
@Component
public class GoogleIdTokenValidatorAdapter implements ValidateGoogleIdTokenOutputPort {

    private static final String JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
    private static final String ISSUER = "https://accounts.google.com";
    private static final Set<String> REQUIRED_CLAIMS = Set.of("sub", "email", "exp");

    private final ConfigurableJWTProcessor<SecurityContext> processor;

    public GoogleIdTokenValidatorAdapter(OAuthProperties properties) {
        this.processor = buildProcessor(properties.google());
    }

    @Override
    public ProviderIdentity validate(String idToken) {
        try {
            JWTClaimsSet claims = processor.process(idToken, null);

            Boolean emailVerified = claims.getBooleanClaim("email_verified");
            if (emailVerified == null || !emailVerified) {
                throw new InvalidProviderTokenException();
            }
            return new ProviderIdentity(claims.getSubject(), claims.getStringClaim("email"), OAuthProvider.GOOGLE);
        } catch (InvalidProviderTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidProviderTokenException(e);
        }
    }

    private static ConfigurableJWTProcessor<SecurityContext> buildProcessor(OAuthProperties.Google config) {
        try {
            DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
            JWKSource<SecurityContext> keySource = JWKSourceBuilder
                    .create(URI.create(JWKS_URI).toURL())
                    .build();
            jwtProcessor.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource));

            JWTClaimsSet exactMatch = new JWTClaimsSet.Builder()
                    .issuer(ISSUER)
                    .audience(config.clientId())
                    .build();
            jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(exactMatch, REQUIRED_CLAIMS));
            return jwtProcessor;
        } catch (MalformedURLException e) {
            throw new IllegalStateException("URL do JWKS do Google invalida", e);
        }
    }
}
