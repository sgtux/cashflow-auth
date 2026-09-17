package com.cashflow.auth.domain;

/**
 * Email inexistente, conta sem senha, ou senha errada. Mensagem unica de proposito - nao revela
 * qual dos casos ocorreu (evita enumeracao de usuarios). Mapeada para 401 em {@code ApiExceptionHandler}.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Credenciais invalidas");
    }
}
