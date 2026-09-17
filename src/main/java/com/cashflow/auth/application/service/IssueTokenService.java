package com.cashflow.auth.application.service;

import com.cashflow.auth.application.port.in.IssueTokenUseCase;
import com.cashflow.auth.application.port.out.LoadUserPort;
import com.cashflow.auth.application.port.out.TokenSignerPort;
import com.cashflow.auth.config.AuthProperties;
import com.cashflow.auth.domain.AuthUser;
import com.cashflow.auth.domain.InvalidCredentialsException;
import com.cashflow.auth.domain.password.EnhancedBCryptPasswordVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orquestra o login: carrega o usuario, confere a senha, pede a assinatura do token.
 * Sem regra de negocio propria - so coordenacao. Ver ./docs/arquitetura.md secao 3.
 */
@Service
public class IssueTokenService implements IssueTokenUseCase {

    private static final Logger log = LoggerFactory.getLogger(IssueTokenService.class);

    private final LoadUserPort loadUserPort;
    private final EnhancedBCryptPasswordVerifier passwordVerifier;
    private final TokenSignerPort tokenSigner;
    private final AuthProperties properties;

    public IssueTokenService(LoadUserPort loadUserPort,
                             EnhancedBCryptPasswordVerifier passwordVerifier,
                             TokenSignerPort tokenSigner,
                             AuthProperties properties) {
        this.loadUserPort = loadUserPort;
        this.passwordVerifier = passwordVerifier;
        this.tokenSigner = tokenSigner;
        this.properties = properties;
    }

    @Override
    public IssuedToken issue(IssueTokenCommand command) {
        AuthUser user = loadUserPort.findByEmail(normalizeEmail(command.email()))
                .orElseThrow(InvalidCredentialsException::new);

        if (!user.hasPassword() || !passwordVerifier.matches(command.password(), user.passwordHash())) {
            log.debug("Login recusado para {}", user.email());
            throw new InvalidCredentialsException();
        }

        String token = tokenSigner.sign(user);
        log.debug("Token emitido para userId={}", user.id());
        return new IssuedToken(user.id(), user.email(), token, properties.tokenTtl().toSeconds());
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
