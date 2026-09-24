package com.cashflow.auth.domain;

/** Providers de login social suportados pelo {@code POST /api/token/oauth}. */
public enum OAuthProvider {
    GOOGLE,
    MICROSOFT
}
