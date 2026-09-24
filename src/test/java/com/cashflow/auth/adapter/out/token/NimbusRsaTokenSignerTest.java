package com.cashflow.auth.adapter.out.token;

import com.cashflow.auth.config.AuthProperties;
import com.cashflow.auth.config.SigningKeys;
import com.cashflow.auth.domain.AuthUser;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Prova a ida-e-volta assimetrica: o signer assina com a chave PRIVADA e um consumidor qualquer
 * consegue validar so com o que sai do JWKS (chave PUBLICA), sem segredo compartilhado.
 */
class NimbusRsaTokenSignerTest {

    private final AuthProperties properties = new AuthProperties(
            "https://auth.cashflow.test", 60, "test-kid", null, null, true);

    private final SigningKeys signingKeys = new SigningKeys(properties);
    private final NimbusRsaTokenSigner signer = new NimbusRsaTokenSigner(signingKeys, properties);

    @Test
    void assina_um_jwt_rs256_verificavel_com_a_chave_publica_do_jwks() throws Exception {
        String token = signer.sign(new AuthUser(42L, "user@cashflow.test"));
        SignedJWT jwt = SignedJWT.parse(token);

        assertThat(jwt.getHeader().getAlgorithm().getName()).isEqualTo("RS256");
        assertThat(jwt.getHeader().getKeyID()).isEqualTo("test-kid");

        // Um consumidor so tem isto: o documento JWKS publico.
        RSAKey publicKey = ((RSAKey) JWKSet.parse(signingKeys.publicJwks())
                .getKeyByKeyId(jwt.getHeader().getKeyID()))
                .toPublicJWK();

        assertThat(publicKey.isPrivate()).isFalse();
        assertThat(jwt.verify(new RSASSAVerifier(publicKey))).isTrue();

        var claims = jwt.getJWTClaimsSet();
        assertThat(claims.getIssuer()).isEqualTo("https://auth.cashflow.test");
        assertThat(claims.getSubject()).isEqualTo("42");
        assertThat(claims.getStringClaim(NimbusRsaTokenSigner.LEGACY_SID_CLAIM)).isEqualTo("42");
        assertThat(claims.getStringClaim("email")).isEqualTo("user@cashflow.test");
        assertThat(claims.getJWTID()).isNotBlank();
        assertThat(claims.getExpirationTime()).isAfter(new Date());
    }

    @Test
    void jwks_publicado_nao_contem_material_privado() throws Exception {
        JWKSet published = JWKSet.parse(signingKeys.publicJwks());
        assertThat(published.getKeys()).isNotEmpty();
        assertThat(published.getKeys()).allSatisfy(jwk -> assertThat(jwk.isPrivate()).isFalse());
    }
}
