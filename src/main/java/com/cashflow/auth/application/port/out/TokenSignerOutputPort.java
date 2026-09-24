package com.cashflow.auth.application.port.out;

import com.cashflow.auth.domain.AuthUser;

/** Constroi e assina o JWT (RS256) para um usuario ja autenticado. Ver ./docs/especificacao.md secao 4. */
public interface TokenSignerOutputPort {

    /** @return o JWT compacto (tres segmentos Base64URL separados por ponto). */
    String sign(AuthUser user);
}
