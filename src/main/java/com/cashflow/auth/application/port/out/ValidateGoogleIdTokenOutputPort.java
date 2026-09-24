package com.cashflow.auth.application.port.out;

import com.cashflow.auth.domain.InvalidProviderTokenException;
import com.cashflow.auth.domain.ProviderIdentity;

/** Valida um ID token (JWT OIDC) emitido pelo Google Sign-In e devolve a identidade confirmada. */
public interface ValidateGoogleIdTokenOutputPort {

    /** @throws InvalidProviderTokenException se o token for invalido, expirado, ou de outro client id. */
    ProviderIdentity validate(String idToken);
}
