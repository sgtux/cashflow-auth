package com.cashflow.auth.domain;

/**
 * Usuario como o cashflow-auth precisa dele: so a identidade necessaria para assinar o token.
 * Nao ha entidade de dominio rica aqui - este servico so autentica (via login social) e emite
 * token, nao tem regra de negocio de usuario (cadastro, plano, limites).
 *
 * @param id    id numerico do usuario em {@code auth.AuthIdentity} (vira as claims {@code sub} e a
 *              de compatibilidade).
 * @param email email do usuario, confirmado pelo provider (vai na claim {@code email}).
 */
public record AuthUser(long id, String email) {
}
