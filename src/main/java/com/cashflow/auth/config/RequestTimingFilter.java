package com.cashflow.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Loga metodo, path, status e duracao de cada requisicao HTTP.
 *
 * <p>Filter, nao AOP no controller: roda para toda requisicao que chega no servlet container,
 * inclusive as que falham antes de alcancar um controller (ex: 401 de validacao, erro de
 * roteamento). Mede o tempo real da requisicao (primeiro ao ultimo byte), nao so o metodo de
 * negocio.</p>
 *
 * <p>Como o appender de log do OpenTelemetry ja esta ativo neste servico, esta linha de log sai
 * automaticamente correlacionada com o trace da requisicao no Dynatrace (trace_id/span_id
 * injetados no log record exportado) - sem precisar de MDC manual.</p>
 */
@Component
public class RequestTimingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RequestTimingFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                     FilterChain chain) throws ServletException, IOException {
        long start = System.nanoTime();
        try {
            chain.doFilter(request, response);
        } finally {
            long durationMs = (System.nanoTime() - start) / 1_000_000;
            log.info("{} {} -> {} ({} ms)", request.getMethod(), request.getRequestURI(),
                    response.getStatus(), durationMs);
        }
    }
}
