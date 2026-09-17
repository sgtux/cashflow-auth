package com.cashflow.auth.domain;

/**
 * Usuario como o cashflow-auth precisa dele: identidade + hash de senha para conferir credenciais.
 * Nao ha entidade de dominio rica aqui - este servico so autentica e emite token, nao tem regra
 * de negocio de usuario (cadastro, plano, limites) - isso continua no Cashflow .NET.
 *
 * @param id           id numerico do usuario (vira as claims {@code sub} e a de compatibilidade).
 * @param email        email do usuario (vai na claim {@code email}).
 * @param passwordHash hash BCrypt "enhanced" armazenado pelo .NET; pode ser {@code null} para
 *                     contas so-Google, que nao logam por senha.
 */
public record AuthUser(long id, String email, String passwordHash) {

    public boolean hasPassword() {
        return passwordHash != null && !passwordHash.isBlank();
    }
}
