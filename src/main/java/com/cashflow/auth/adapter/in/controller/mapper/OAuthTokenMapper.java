package com.cashflow.auth.adapter.in.controller.mapper;

import com.cashflow.auth.adapter.in.controller.request.OAuthLoginRequest;
import com.cashflow.auth.adapter.in.controller.response.TokenResponse;
import com.cashflow.auth.application.port.in.AuthenticateWithProviderInputPort.AuthenticateCommand;
import com.cashflow.auth.application.port.in.AuthenticateWithProviderInputPort.IssuedToken;
import org.springframework.stereotype.Component;

/**
 * Converte entre o DTO da web ({@code OAuthLoginRequest}/{@code TokenResponse}) e os tipos da
 * porta de entrada ({@code AuthenticateCommand}/{@code IssuedToken}). Mantem o
 * {@code OAuthTokenController} livre de logica de mapeamento e os DTOs livres de tipo de
 * aplicacao.
 */
@Component
public class OAuthTokenMapper {

    public AuthenticateCommand toCommand(OAuthLoginRequest request) {
        return new AuthenticateCommand(request.provider(), request.idToken());
    }

    public TokenResponse toResponse(IssuedToken issued) {
        return new TokenResponse(issued.userId(), issued.email(), issued.token(), issued.expiresInSec());
    }
}
