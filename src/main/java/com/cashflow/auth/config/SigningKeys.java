package com.cashflow.auth.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Guarda a chave RSA ativa (usada para assinar) e o conjunto de chaves PUBLICAS publicado em
 * {@code /.well-known/jwks.json}. Ver ./docs/especificacao.md secoes 4 e 5.
 *
 * <ul>
 *   <li>Producao: {@code auth.private-key-pem} traz a chave privada ativa (PEM PKCS#8).</li>
 *   <li>Dev: sem chave configurada e {@code auth.dev-generate-key=true} gera um par efemero.</li>
 *   <li>Rotacao: {@code auth.additional-jwks} traz chaves publicas antigas que ainda validam
 *       tokens emitidos antes da troca, mas nao assinam mais.</li>
 * </ul>
 */
@Component
public class SigningKeys {

    private static final Logger log = LoggerFactory.getLogger(SigningKeys.class);

    private final RSAKey activeSigningKey;
    private final JWKSet publicJwkSet;

    public SigningKeys(AuthProperties properties) {
        this.activeSigningKey = loadOrGenerateActiveKey(properties);

        List<JWK> publicKeys = new ArrayList<>();
        publicKeys.add(activeSigningKey.toPublicJWK());
        if (properties.hasAdditionalJwks()) {
            try {
                for (JWK jwk : JWKSet.parse(properties.additionalJwks()).getKeys()) {
                    publicKeys.add(jwk.toPublicJWK());
                }
            } catch (Exception e) {
                throw new IllegalStateException("auth.additional-jwks nao e um JWKS JSON valido", e);
            }
        }
        this.publicJwkSet = new JWKSet(publicKeys);
        log.info("JWKS publicado com {} chave(s); kid ativo = {}", publicKeys.size(), activeSigningKey.getKeyID());
    }

    /** Chave usada para assinar tokens novos (contem a parte privada). */
    public RSAKey activeSigningKey() {
        return activeSigningKey;
    }

    /** Documento JWKS: apenas chaves publicas. Serializavel direto para a resposta HTTP. */
    public Map<String, Object> publicJwks() {
        // toJSONObject(true) => forca so-publico; blindagem extra alem do toPublicJWK() acima.
        return new LinkedHashMap<>(publicJwkSet.toJSONObject(true));
    }

    private static RSAKey loadOrGenerateActiveKey(AuthProperties properties) {
        if (properties.hasConfiguredPrivateKey()) {
            return fromPkcs8Pem(properties.privateKeyPem(), properties.activeKid());
        }
        if (!properties.devGenerateKey()) {
            throw new IllegalStateException(
                    "Nenhuma chave de assinatura: defina AUTH_PRIVATE_KEY_PEM ou habilite auth.dev-generate-key (apenas dev)");
        }
        log.warn("auth.dev-generate-key=true: gerando par RSA EFEMERO (invalida todos os tokens a cada restart). Nao use em producao.");
        return generateEphemeral(properties.activeKid());
    }

    private static RSAKey fromPkcs8Pem(String pem, String kid) {
        try {
            String der = pem.replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] pkcs8 = Base64.getDecoder().decode(der);
            KeyFactory rsa = KeyFactory.getInstance("RSA");
            var privateKey = (RSAPrivateCrtKey) rsa.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
            var publicKey = (RSAPublicKey) rsa.generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("auth.private-key-pem invalida (esperado PEM PKCS#8 de chave RSA)", e);
        }
    }

    private static RSAKey generateEphemeral(String kid) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey(pair.getPrivate())
                    .keyID(kid == null || kid.isBlank() ? "dev" : kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar par RSA efemero", e);
        }
    }
}
