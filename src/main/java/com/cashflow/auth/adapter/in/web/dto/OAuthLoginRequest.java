package com.cashflow.auth.adapter.in.web.dto;

import com.cashflow.auth.domain.OAuthProvider;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/** Corpo de {@code POST /api/token/oauth}. {@code provider} e {@code "GOOGLE"} ou {@code "MICROSOFT"}. */
public record OAuthLoginRequest(
        @NotNull OAuthProvider provider,
        @NotBlank String idToken
) {
}
