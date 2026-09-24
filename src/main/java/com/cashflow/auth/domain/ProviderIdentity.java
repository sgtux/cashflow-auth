package com.cashflow.auth.domain;

/**
 * Identidade confirmada por um provider OAuth externo, apos validar o ID token (assinatura,
 * issuer, audience). E o resultado de {@code ValidateGoogleIdTokenOutputPort}/
 * {@code ValidateMicrosoftIdTokenOutputPort} - nao e o {@code AuthUser} ainda, porque o usuario
 * pode nao existir na tabela {@code AuthIdentity} até esse ponto.
 *
 * @param subject  claim {@code sub} do provider - identificador estavel da conta la (nao muda se
 *                 o usuario trocar o email, ao contrario do email).
 * @param email    email confirmado pelo provider.
 * @param provider qual provider emitiu essa identidade.
 */
public record ProviderIdentity(String subject, String email, OAuthProvider provider) {
}
