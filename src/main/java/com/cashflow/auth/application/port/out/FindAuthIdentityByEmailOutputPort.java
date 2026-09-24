package com.cashflow.auth.application.port.out;

import com.cashflow.auth.domain.AuthUser;

import java.util.Optional;

/**
 * Busca, pelo email, um usuario ja provisionado via login social em {@code auth.AuthIdentity},
 * tabela propria do cashflow-auth. Implementada por um adapter de leitura.
 */
public interface FindAuthIdentityByEmailOutputPort {

    Optional<AuthUser> find(String email);
}
