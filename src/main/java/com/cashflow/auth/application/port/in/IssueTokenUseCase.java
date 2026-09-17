package com.cashflow.auth.application.port.in;

/**
 * Caso de uso unico do servico: trocar email + senha por um access token assinado.
 * Corresponde a {@code POST /api/token} (ver ./docs/especificacao.md secao 2).
 */
public interface IssueTokenUseCase {

    IssuedToken issue(IssueTokenCommand command);

    /** @param email  email informado no login. @param password senha crua informada no login. */
    record IssueTokenCommand(String email, String password) {
    }

    /**
     * @param userId       id do usuario autenticado.
     * @param email        email do usuario autenticado.
     * @param token        JWT compacto assinado com RS256.
     * @param expiresInSec tempo de vida do token, em segundos (para o cliente saber quando renovar).
     */
    record IssuedToken(long userId, String email, String token, long expiresInSec) {
    }
}
