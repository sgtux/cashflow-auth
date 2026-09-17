package com.cashflow.auth.application.port.out;

import com.cashflow.auth.domain.AuthUser;

import java.util.Optional;

/** Busca o usuario (e o hash de senha) pela credencial de login. Implementada por um adapter de leitura. */
public interface LoadUserPort {

    Optional<AuthUser> findByEmail(String email);
}
