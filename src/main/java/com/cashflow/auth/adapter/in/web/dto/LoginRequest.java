package com.cashflow.auth.adapter.in.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/** Corpo de {@code POST /api/token}. Mesmo shape que a API .NET aceita hoje (email + password). */
public record LoginRequest(
        @NotBlank @Email String email,
        @NotBlank String password
) {
}
