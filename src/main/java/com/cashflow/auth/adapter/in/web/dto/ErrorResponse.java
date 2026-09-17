package com.cashflow.auth.adapter.in.web.dto;

/** Envelope de erro: JSON simples {@code {"message": "..."}}. */
public record ErrorResponse(String message) {
}
