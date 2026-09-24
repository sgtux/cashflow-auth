package com.cashflow.auth.adapter.in.web;

import com.cashflow.auth.adapter.in.web.dto.OAuthLoginRequest;
import com.cashflow.auth.adapter.in.web.dto.TokenResponse;
import com.cashflow.auth.application.port.in.AuthenticateWithProviderUseCase;
import com.cashflow.auth.application.port.in.AuthenticateWithProviderUseCase.AuthenticateCommand;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code POST /api/token/oauth} - troca um ID token do Google/Microsoft por um token de
 * aplicacao. Cria o usuario (na tabela propria {@code AuthIdentity}) se for o primeiro login com
 * aquele email. Ver ./docs/especificacao.md secao 6.
 */
@RestController
@RequestMapping("/api/token/oauth")
public class OAuthTokenController {

    private final AuthenticateWithProviderUseCase authenticateWithProviderUseCase;

    public OAuthTokenController(AuthenticateWithProviderUseCase authenticateWithProviderUseCase) {
        this.authenticateWithProviderUseCase = authenticateWithProviderUseCase;
    }

    @PostMapping
    public TokenResponse issue(@Valid @RequestBody OAuthLoginRequest request) {
        var issued = authenticateWithProviderUseCase.authenticate(
                new AuthenticateCommand(request.provider(), request.idToken()));
        return TokenResponse.from(issued);
    }
}
