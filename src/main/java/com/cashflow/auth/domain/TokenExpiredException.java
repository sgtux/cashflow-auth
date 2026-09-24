package com.cashflow.auth.domain;

/**
 * ID token de provider OAuth expirado: a assinatura e valida, mas a claim {@code exp} ja passou.
 * E separada de {@link InvalidProviderTokenException} porque, para quem chama, o remedio e
 * diferente - o token nao esta errado, so precisa ser renovado (novo login no provider).
 *
 * <p>Hoje so o validador da Microsoft lanca esta excecao; o do Google trata token expirado como
 * {@link InvalidProviderTokenException}. Mapeada para 401 em {@code ApiExceptionHandler}.</p>
 */
public class TokenExpiredException extends RuntimeException {

    public TokenExpiredException() {
        super("Token informado expirou");
    }

    public TokenExpiredException(Throwable cause) {
        super("Token informado expirou", cause);
    }
}
