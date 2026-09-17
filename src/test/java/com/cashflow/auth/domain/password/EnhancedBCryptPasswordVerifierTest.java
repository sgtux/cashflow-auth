package com.cashflow.auth.domain.password;

import at.favre.lib.crypto.bcrypt.BCrypt;
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class EnhancedBCryptPasswordVerifierTest {

    private final EnhancedBCryptPasswordVerifier verifier = new EnhancedBCryptPasswordVerifier();

    /**
     * Reproduz o que o BCrypt.Net {@code EnhancedHashPassword(pwd, 12, SHA512)} faz (SHA-512 -> Base64
     * -> bcrypt custo 12) e confirma que {@link EnhancedBCryptPasswordVerifier} valida esse hash.
     */
    @Test
    void valida_hash_gerado_com_o_mesmo_pre_processamento_do_dotnet() throws Exception {
        String password = "Cashflow@123";
        byte[] sha512 = MessageDigest.getInstance("SHA-512").digest(password.getBytes(StandardCharsets.UTF_8));
        char[] preHashed = Base64.getEncoder().encodeToString(sha512).toCharArray();
        // Base64 do SHA-512 tem 88 bytes: precisa da mesma estrategia de truncagem (72) do verifier.
        String hash = BCrypt.with(BCrypt.Version.VERSION_2A, LongPasswordStrategies.truncate(BCrypt.Version.VERSION_2A))
                .hashToString(12, preHashed);

        assertThat(verifier.matches(password, hash)).isTrue();
        assertThat(verifier.matches("senha-errada", hash)).isFalse();
        assertThat(verifier.matches(password, null)).isFalse();
        assertThat(verifier.matches(null, hash)).isFalse();
    }

    /**
     * Blindagem de verdade contra o .NET: cole aqui um hash REAL gerado por
     * {@code CryptographyUtils.PasswordHash("Cashflow@123")} no projeto Cashflow e remova o @Disabled.
     * Se este teste passar, a compatibilidade de senha esta provada ponta a ponta.
     */
    @Test
    @Disabled("preencher HASH_DO_DOTNET com um hash real do BCrypt.Net do Cashflow")
    void valida_hash_real_do_dotnet() {
        String HASH_DO_DOTNET = "$2a$12$........................................................";
        assertThat(verifier.matches("Cashflow@123", HASH_DO_DOTNET)).isTrue();
    }
}
