package com.cashflow.auth.domain;

/**
 * ID token de provider OAuth invalido: assinatura nao bate, expirado, issuer/audience errados,
 * ou faltando claim obrigatoria (email/sub). Mensagem generica de proposito - nao vale a pena
 * diferenciar os casos para quem chama (token expirado tem excecao propria, {@link
 * TokenExpiredException}). Mapeada para 401 em {@code ApiExceptionHandler}.
 */
public class InvalidProviderTokenException extends RuntimeException {

    public InvalidProviderTokenException() {
        super("Token do provider invalido");
    }

    public InvalidProviderTokenException(Throwable cause) {
        super("Token do provider invalido", cause);
    }
}
