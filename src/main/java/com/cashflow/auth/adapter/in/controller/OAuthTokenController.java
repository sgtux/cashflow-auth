package com.cashflow.auth.adapter.in.controller;

import com.cashflow.auth.adapter.in.controller.mapper.OAuthTokenMapper;
import com.cashflow.auth.adapter.in.controller.request.OAuthLoginRequest;
import com.cashflow.auth.adapter.in.controller.response.TokenResponse;
import com.cashflow.auth.application.port.in.AuthenticateWithProviderInputPort;
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

    private final AuthenticateWithProviderInputPort authenticateWithProviderUseCase;
    private final OAuthTokenMapper mapper;

    public OAuthTokenController(AuthenticateWithProviderInputPort authenticateWithProviderUseCase,
                                 OAuthTokenMapper mapper) {
        this.authenticateWithProviderUseCase = authenticateWithProviderUseCase;
        this.mapper = mapper;
    }

    @PostMapping
    public TokenResponse issue(@Valid @RequestBody OAuthLoginRequest request) {
        var issued = authenticateWithProviderUseCase.authenticate(mapper.toCommand(request));
        return mapper.toResponse(issued);
    }
}
