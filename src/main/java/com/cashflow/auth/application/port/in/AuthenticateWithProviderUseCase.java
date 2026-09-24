package com.cashflow.auth.application.port.in;

import com.cashflow.auth.domain.OAuthProvider;

/**
 * Caso de uso: trocar um ID token de um provider OAuth (Google/Microsoft) por um token de
 * aplicacao, criando o usuario (na tabela propria {@code auth.AuthIdentity}) se for o primeiro
 * login com aquele email. E o unico caso de uso do servico. Corresponde a
 * {@code POST /api/token/oauth} (ver ./docs/especificacao.md secao 2 e 6).
 */
public interface AuthenticateWithProviderUseCase {

    IssuedToken authenticate(AuthenticateCommand command);

    /** @param provider qual provider emitiu o token. @param idToken ID token (JWT) recebido do frontend. */
    record AuthenticateCommand(OAuthProvider provider, String idToken) {
    }

    /**
     * @param userId       id do usuario em {@code auth.AuthIdentity} (tabela propria do cashflow-auth).
     * @param email        email confirmado pelo provider.
     * @param token        JWT compacto assinado com RS256.
     * @param expiresInSec tempo de vida do token, em segundos.
     */
    record IssuedToken(long userId, String email, String token, long expiresInSec) {
    }
}
