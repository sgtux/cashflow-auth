package com.cashflow.auth.domain.password;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Confere uma senha crua contra o hash gravado pelo Cashflow .NET no cadastro.
 *
 * <p>O .NET usa {@code BCrypt.Net.BCrypt.EnhancedVerify(senha, hash, HashType.SHA512)}
 * (ver {@code Api/Utils/CryptographyUtils.cs} do Cashflow). "Enhanced" = <strong>SHA-512 da senha,
 * depois Base64, e so entao BCrypt custo 12</strong>. Reproduzimos esse pre-processamento aqui.</p>
 *
 * <p><strong>Detalhe critico do limite de 72 bytes:</strong> o Base64 de um SHA-512 tem 88 bytes,
 * acima do maximo de 72 do bcrypt. Usamos {@link LongPasswordStrategies#truncate} (corta em 72,
 * que e o comportamento classico do bcrypt em C / OpenBSD). Se a comparacao com um hash real do
 * .NET falhar, a causa mais provavel e o .NET NAO truncar do mesmo jeito (ou usar SHA-384, cujo
 * Base64 cabe em 64 bytes e nao precisa de truncagem) - troque a estrategia aqui e no seed.</p>
 *
 * <p><strong>Verificar contra hash real antes de confiar</strong> - ha um teste {@code @Disabled}
 * em {@code EnhancedBCryptPasswordVerifierTest#valida_hash_real_do_dotnet} exatamente para isso.</p>
 */
@Component
public class EnhancedBCryptPasswordVerifier {

    private static final BCrypt.Verifyer VERIFYER =
            BCrypt.verifyer(BCrypt.Version.VERSION_2A, LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2A));

    public boolean matches(String rawPassword, String storedHash) {
        if (rawPassword == null || storedHash == null || storedHash.isBlank()) {
            return false;
        }
        byte[] sha512 = sha512(rawPassword.getBytes(StandardCharsets.UTF_8));
        char[] preHashed = Base64.getEncoder().encodeToString(sha512).toCharArray();
        return VERIFYER.verify(preHashed, storedHash.toCharArray()).verified;
    }

    private static byte[] sha512(byte[] input) {
        try {
            return MessageDigest.getInstance("SHA-512").digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-512 indisponivel na JVM", e);
        }
    }
}
