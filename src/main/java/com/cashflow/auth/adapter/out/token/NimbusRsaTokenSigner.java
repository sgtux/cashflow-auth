package com.cashflow.auth.adapter.out.token;

import com.cashflow.auth.application.port.out.TokenSignerOutputPort;
import com.cashflow.auth.config.AuthProperties;
import com.cashflow.auth.domain.AuthUser;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Monta e assina o JWT com RS256. Formato das claims em ./docs/especificacao.md secao 4.
 *
 * <p>Mantem a claim de URI longa {@code http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid}
 * <em>alem</em> de {@code sub} para que os consumidores atuais (que hoje leem a claim longa emitida
 * pelo .NET) continuem funcionando durante a migracao - ver ./docs/migracao-hs256-rs256.md.</p>
 */
@Component
public class NimbusRsaTokenSigner implements TokenSignerOutputPort {

    /** Claim de compatibilidade: e como o .NET escreve {@code ClaimTypes.Sid} no token hoje. */
    public static final String LEGACY_SID_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid";

    private final SigningKeys signingKeys;
    private final AuthProperties properties;

    public NimbusRsaTokenSigner(SigningKeys signingKeys, AuthProperties properties) {
        this.signingKeys = signingKeys;
        this.properties = properties;
    }

    @Override
    public String sign(AuthUser user) {
        Instant now = Instant.now();
        Instant expiry = now.plus(properties.tokenTtl());
        String subject = Long.toString(user.id());

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .subject(subject)
                .claim(LEGACY_SID_CLAIM, subject)
                .claim("email", user.email())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiry))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(signingKeys.activeSigningKey().getKeyID())
                .type(JOSEObjectType.JWT)
                .build();

        try {
            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(signingKeys.activeSigningKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao assinar o JWT", e);
        }
    }
}
