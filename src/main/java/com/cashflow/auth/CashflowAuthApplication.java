package com.cashflow.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * cashflow-auth: unico emissor de identidade do ecossistema Cashflow.
 *
 * <p>Responsabilidade unica: autenticar (email + senha contra a tabela {@code [User]} do Cashflow)
 * e devolver um JWT assinado com <strong>RS256</strong>. Os demais servicos (API .NET do Cashflow,
 * cashflow-investimentos) apenas <em>validam</em> o token com a chave publica publicada em
 * {@code GET /.well-known/jwks.json}. Ver {@code ./docs/especificacao.md}.</p>
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class CashflowAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(CashflowAuthApplication.class, args);
    }
}
