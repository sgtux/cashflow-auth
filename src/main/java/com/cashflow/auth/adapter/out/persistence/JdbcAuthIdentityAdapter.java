package com.cashflow.auth.adapter.out.persistence;

import com.cashflow.auth.application.port.out.CreateAuthIdentityOutputPort;
import com.cashflow.auth.application.port.out.FindAuthIdentityByEmailOutputPort;
import com.cashflow.auth.domain.AuthUser;
import com.cashflow.auth.domain.OAuthProvider;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Le e escreve {@code auth.AuthIdentity} - schema proprio do cashflow-auth (ver
 * {@code db/migration/} e {@code spring.flyway.schemas}). Guarda os usuarios provisionados via
 * login social (Google/Microsoft): e a unica fonte de identidade do servico, e nao ha senha.
 * Ver ./docs/especificacao.md secoes 6 e 7.
 */
@Repository
public class JdbcAuthIdentityAdapter implements FindAuthIdentityByEmailOutputPort, CreateAuthIdentityOutputPort {

    private static final String BY_EMAIL = """
            SELECT Id, Email
            FROM auth.AuthIdentity
            WHERE Email = :email
            """;

    private static final String INSERT = """
            INSERT INTO auth.AuthIdentity (Email, Provider, ExternalSubject)
            OUTPUT INSERTED.Id
            VALUES (:email, :provider, :externalSubject)
            """;

    private final JdbcClient jdbcClient;

    public JdbcAuthIdentityAdapter(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Override
    public Optional<AuthUser> find(String email) {
        return jdbcClient.sql(BY_EMAIL)
                .param("email", email)
                .query((rs, rowNum) -> new AuthUser(rs.getLong("Id"), rs.getString("Email")))
                .optional();
    }

    @Override
    public AuthUser create(String email, OAuthProvider provider, String externalSubject) {
        long id = jdbcClient.sql(INSERT)
                .param("email", email)
                .param("provider", provider.name())
                .param("externalSubject", externalSubject)
                .query(Long.class)
                .single();
        return new AuthUser(id, email);
    }
}
