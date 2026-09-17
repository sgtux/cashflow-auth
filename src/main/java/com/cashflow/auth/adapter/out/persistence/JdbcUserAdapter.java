package com.cashflow.auth.adapter.out.persistence;

import com.cashflow.auth.application.port.out.LoadUserPort;
import com.cashflow.auth.domain.AuthUser;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Le a tabela {@code [User]} do banco do Cashflow (mesma engine SQL Server). SOMENTE leitura das
 * colunas de identidade/credencial - este servico nao escreve nem versiona esse schema; o dono
 * continua sendo o Cashflow .NET (cadastro, plano, limites). Ver ./docs/arquitetura.md secao 4.
 *
 * <p>{@code [User]} entre colchetes porque {@code USER} e palavra reservada no T-SQL.</p>
 */
@Repository
public class JdbcUserAdapter implements LoadUserPort {

    private static final String BY_EMAIL = """
            SELECT Id, Email, Password
            FROM [User]
            WHERE Email = :email
            """;

    private final JdbcClient jdbcClient;

    public JdbcUserAdapter(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Override
    public Optional<AuthUser> findByEmail(String email) {
        return jdbcClient.sql(BY_EMAIL)
                .param("email", email)
                .query((rs, rowNum) -> new AuthUser(
                        rs.getLong("Id"),
                        rs.getString("Email"),
                        rs.getString("Password")))
                .optional();
    }
}
