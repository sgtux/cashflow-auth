package com.cashflow.auth.adapter.in.controller.response;

/** Envelope de erro: JSON simples {@code {"message": "..."}}. */
public record ErrorResponse(String message) {
}
