package com.cashflow.auth.adapter.in.web.dto;

import com.cashflow.auth.application.port.in.IssueTokenUseCase.IssuedToken;

/**
 * Resposta de {@code POST /api/token}. {@code id} + {@code email} + {@code token} espelham o que o
 * cashflow-investimentos ja devolve hoje ao frontend no proxy de login; {@code expiresIn} (segundos)
 * e novo e opcional para o cliente.
 */
public record TokenResponse(long id, String email, String token, long expiresIn) {

    public static TokenResponse from(IssuedToken issued) {
        return new TokenResponse(issued.userId(), issued.email(), issued.token(), issued.expiresInSec());
    }
}
