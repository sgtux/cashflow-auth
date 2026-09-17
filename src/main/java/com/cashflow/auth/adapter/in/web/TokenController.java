package com.cashflow.auth.adapter.in.web;

import com.cashflow.auth.adapter.in.web.dto.LoginRequest;
import com.cashflow.auth.adapter.in.web.dto.TokenResponse;
import com.cashflow.auth.application.port.in.IssueTokenUseCase;
import com.cashflow.auth.application.port.in.IssueTokenUseCase.IssueTokenCommand;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * {@code POST /api/token} - unico endpoint que emite token. Recebe email + senha, devolve o JWT
 * assinado com RS256. Path e shape identicos aos que a API .NET expoe hoje, para que o
 * cashflow-investimentos passe a apontar o proxy de login para ca so trocando a base URL.
 * Ver ./docs/especificacao.md secao 2.
 */
@RestController
@RequestMapping("/api/token")
public class TokenController {

    private final IssueTokenUseCase issueTokenUseCase;

    public TokenController(IssueTokenUseCase issueTokenUseCase) {
        this.issueTokenUseCase = issueTokenUseCase;
    }

    @PostMapping
    public TokenResponse issue(@Valid @RequestBody LoginRequest request) {
        var issued = issueTokenUseCase.issue(new IssueTokenCommand(request.email(), request.password()));
        return TokenResponse.from(issued);
    }
}
