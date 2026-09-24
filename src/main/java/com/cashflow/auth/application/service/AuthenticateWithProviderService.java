package com.cashflow.auth.application.service;

import com.cashflow.auth.application.port.in.AuthenticateWithProviderInputPort;
import com.cashflow.auth.application.port.out.CreateAuthIdentityOutputPort;
import com.cashflow.auth.application.port.out.FindAuthIdentityByEmailOutputPort;
import com.cashflow.auth.application.port.out.TokenSignerOutputPort;
import com.cashflow.auth.application.port.out.ValidateGoogleIdTokenOutputPort;
import com.cashflow.auth.application.port.out.ValidateMicrosoftIdTokenOutputPort;
import com.cashflow.auth.config.AuthProperties;
import com.cashflow.auth.domain.AuthUser;
import com.cashflow.auth.domain.OAuthProvider;
import com.cashflow.auth.domain.ProviderIdentity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Orquestra o login social: valida o ID token do provider, encontra ou cria o usuario na tabela
 * propria do cashflow-auth ({@code auth.AuthIdentity}), e pede a assinatura do token de
 * aplicacao. Sem regra de negocio propria - so coordenacao. Ver ./docs/especificacao.md secao 6.
 */
@Service
public class AuthenticateWithProviderService implements AuthenticateWithProviderInputPort {

    private static final Logger log = LoggerFactory.getLogger(AuthenticateWithProviderService.class);

    private final ValidateGoogleIdTokenOutputPort googleValidator;
    private final ValidateMicrosoftIdTokenOutputPort microsoftValidator;
    private final FindAuthIdentityByEmailOutputPort findAuthIdentity;
    private final CreateAuthIdentityOutputPort createAuthIdentity;
    private final TokenSignerOutputPort tokenSigner;
    private final AuthProperties properties;

    public AuthenticateWithProviderService(ValidateGoogleIdTokenOutputPort googleValidator,
                                            ValidateMicrosoftIdTokenOutputPort microsoftValidator,
                                            FindAuthIdentityByEmailOutputPort findAuthIdentity,
                                            CreateAuthIdentityOutputPort createAuthIdentity,
                                            TokenSignerOutputPort tokenSigner,
                                            AuthProperties properties) {
        this.googleValidator = googleValidator;
        this.microsoftValidator = microsoftValidator;
        this.findAuthIdentity = findAuthIdentity;
        this.createAuthIdentity = createAuthIdentity;
        this.tokenSigner = tokenSigner;
        this.properties = properties;
    }

    @Override
    public IssuedToken authenticate(AuthenticateCommand command) {
        ProviderIdentity identity = validate(command.provider(), command.idToken());
        String email = normalizeEmail(identity.email());

        AuthUser user = findAuthIdentity.find(email)
                .orElseGet(() -> {
                    log.debug("Primeiro login via {} para {} - criando AuthIdentity", identity.provider(), email);
                    return createAuthIdentity.create(email, identity.provider(), identity.subject());
                });

        String token = tokenSigner.sign(user);
        log.debug("Token emitido (OAuth {}) para userId={}", identity.provider(), user.id());
        return new IssuedToken(user.id(), user.email(), token, properties.tokenTtl().toSeconds());
    }

    private ProviderIdentity validate(OAuthProvider provider, String idToken) {
        return switch (provider) {
            case GOOGLE -> googleValidator.validate(idToken);
            case MICROSOFT -> microsoftValidator.validate(idToken);
        };
    }

    private static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }
}
