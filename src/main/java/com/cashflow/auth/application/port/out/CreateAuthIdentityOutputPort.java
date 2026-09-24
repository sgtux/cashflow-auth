package com.cashflow.auth.application.port.out;

import com.cashflow.auth.domain.AuthUser;
import com.cashflow.auth.domain.OAuthProvider;

/**
 * Cria um novo usuario provisionado via login social, na tabela {@code AuthIdentity} - propria
 * do cashflow-auth. Chamado apenas quando {@link FindAuthIdentityByEmailOutputPort} nao encontra
 * o email (primeiro login daquela pessoa).
 */
public interface CreateAuthIdentityOutputPort {

    AuthUser create(String email, OAuthProvider provider, String externalSubject);
}
