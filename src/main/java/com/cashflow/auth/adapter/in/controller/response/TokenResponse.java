package com.cashflow.auth.adapter.in.controller.response;

/**
 * Resposta de {@code POST /api/token/oauth}. {@code id} + {@code email} + {@code token} espelham o
 * que o cashflow-investimentos ja devolve hoje ao frontend no proxy de login; {@code expiresIn}
 * (segundos) e novo e opcional para o cliente.
 *
 * <p>Sem construtor de conveniencia aqui de proposito: a conversao a partir de {@code IssuedToken}
 * fica em {@link com.cashflow.auth.adapter.in.controller.mapper.OAuthTokenMapper} - o DTO nao
 * conhece tipo nenhum da camada de aplicacao.</p>
 */
public record TokenResponse(long id, String email, String token, long expiresIn) {
}
