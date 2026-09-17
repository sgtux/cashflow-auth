# Migração: HMAC-SHA256 (segredo compartilhado) → RS256 (JWKS)

Como tirar o `SECRET_JWT_KEY` compartilhado de circulação e passar os dois consumidores a
validar os tokens do `cashflow-auth` com a **chave pública**, sem janela de indisponibilidade.

## Onde cada app está hoje

| App | Emite token? | Valida como |
|---|---|---|
| **cashflow** (.NET) | Sim — `TokenController` + `JwtTokenBuilder`, HS256 | `AuthenticationMiddleware`, `SymmetricSecurityKey(ASCII(SECRET_JWT_KEY))` |
| **cashflow-investimentos** (Java) | Não (faz proxy do login para o .NET) | `JwtTokenParser`, `Keys.hmacShaKeyFor(ASCII(SECRET_JWT_KEY))` |
| **cashflow-auth** | Passará a ser o único emissor — RS256 | não valida token de ninguém |

Ponto-chave: hoje **quem valida também consegue emitir** (mesmo segredo). O objetivo é que só
o `cashflow-auth` tenha a chave de assinar.

## Princípio: aceitar os dois durante a sobreposição

Cada consumidor, por uma ou duas releases, aceita **tanto** um token HS256 (segredo antigo)
**quanto** um RS256 (via JWKS). Assim emissor e consumidores podem ser cortados em deploys
separados, e o rollback de cada passo é trivial.

A ordem de tentativa no consumidor:

```
se header.alg == "RS256":  validar via JWKS (assinatura + iss + exp)
senão (HS256):             validar via segredo compartilhado  [caminho legado, a remover]
```

---

## Fase 1 — subir o cashflow-auth (nenhum consumidor muda)

1. Deploy do `cashflow-auth` com uma chave **estável** (`AUTH_PRIVATE_KEY_PEM` + `AUTH_ACTIVE_KID`
   de um secret manager — **não** a chave efêmera de dev).
2. `AUTH_ISSUER` definido com o valor definitivo (ex.: `https://auth.cashflow.example.com`).
   Anote-o: os consumidores vão exigir esse valor exato na claim `iss`.
3. `DATABASE_URL` apontando para o banco real do Cashflow (tabela `[User]`).
4. **Homologar o hash de senha** contra o BCrypt.Net real (ver `especificacao.md` §6). Se não
   fechar rápido, aplicar a **opção B** abaixo antes de seguir.
5. Sanity: `curl .../api/token` devolve um JWT; `curl .../.well-known/jwks.json` devolve a
   chave pública; o JWT valida em jwt.io contra essa chave.

Neste ponto ninguém consome os tokens do `cashflow-auth` ainda.

### Opção B (se a compatibilidade de senha não fechar) — delegar a checagem ao .NET

Em vez de `JdbcUserAdapter` + `EnhancedBCryptPasswordVerifier`, o `cashflow-auth` chama o
`POST /api/token` do .NET server-to-server só para **conferir a credencial**, ignora o token
HS256 que volta, e **re-emite** um RS256 próprio a partir do `id`/`email` da resposta. Menos
"correto" (mantém o .NET no caminho do login), mas remove o risco do hash e é reversível para
a opção A quando o hash estiver homologado. É trocar a implementação de `LoadUserPort` por um
adapter HTTP; o resto do serviço não muda.

---

## Fase 2 — consumidores passam a aceitar RS256 (além de HS256)

Deploys independentes, em qualquer ordem. Cada um continua aceitando o token HS256 atual.

### cashflow-investimentos (Java)

Menor diff: manter o `JwtAuthenticationFilter` como está e trocar só o interior do
`JwtTokenParser`, que continua expondo `Optional<Long> extractUserId(String)`.

- **pom.xml**: adicionar `com.nimbusds:nimbus-jose-jwt` (ou
  `spring-boot-starter-oauth2-resource-server`, que já o traz).
- **`JwtTokenParser`**: dois caminhos.

```java
// RS256: cache + rotação automáticos via JWKS remoto
private final ConfigurableJWTProcessor<SecurityContext> rs256 = build();

private ConfigurableJWTProcessor<SecurityContext> build() {
    var p = new DefaultJWTProcessor<SecurityContext>();
    var jwks = JWKSourceBuilder
            .create(new URL(props.auth().jwksUri()))   // ex.: https://auth.cashflow.example.com/.well-known/jwks.json
            .retrying(true)
            .build();
    p.setJWSKeySelector(new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, jwks));
    p.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
            new JWTClaimsSet.Builder().issuer(props.auth().issuer()).build(),
            Set.of("sub", "exp")));
    return p;
}

public Optional<Long> extractUserId(String token) {
    try {
        var alg = SignedJWT.parse(token).getHeader().getAlgorithm();
        Claims claims = JWSAlgorithm.RS256.equals(alg)
                ? toClaims(rs256.process(token, null))     // caminho novo
                : parseHs256(token);                        // caminho legado (código atual)
        String id = firstNonNull(claims.get("sub"), claims.get(SID_CLAIM));
        return id == null ? Optional.empty() : Optional.of(Long.valueOf(id.trim()));
    } catch (Exception e) { log.debug("JWT inválido: {}", e.getMessage()); return Optional.empty(); }
}
```

- **Config** (`application.yml` / `CashflowProperties`): adicionar
  `cashflow.auth.jwks-uri` e `cashflow.auth.issuer`. Manter `cashflow.jwt.secret` por enquanto.
- **`SECRET_JWT_KEY`** continua no ambiente até a Fase 4.

### cashflow (.NET)

- **`AuthenticationMiddleware.ValidateToken`**: montar `TokenValidationParameters` que aceite
  as duas famílias de chave.

```csharp
// carregar 1x e cachear (com refresh); em produção, ConfigurationManager<> ou um cache com TTL
var jwks = new JsonWebKeySet(await httpClient.GetStringAsync(authJwksUri));

var parameters = new TokenValidationParameters
{
    ValidateIssuerSigningKey = true,
    IssuerSigningKeys = jwks.GetSigningKeys()                       // RS256 (cashflow-auth)
        .Append(new SymmetricSecurityKey(Encoding.ASCII.GetBytes(appConfig.SecretJwtKey))), // HS256 legado
    ValidateIssuer = true,
    ValidIssuers = new[] { authIssuer },                            // só o RS256 traz iss; ver nota
    ValidateAudience = false,
    ValidateLifetime = true
};
```

> Nota: o token HS256 legado **não tem `iss`**. Com `ValidateIssuer = true` ele passa a ser
> rejeitado. Duas saídas: (a) manter `ValidateIssuer = false` durante a Fase 2–3 e só ligar na
> Fase 4; ou (b) `IssuerValidator` custom que exige `iss` apenas quando `alg == RS256`.
> Recomendado: (a), mais simples.

- **Claims**: o RS256 do `cashflow-auth` traz a claim de URI longa
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid` (além de `sub`), então o código
  que hoje lê `ClaimTypes.Sid` **continua funcionando sem mudança**.
- **Emissão**: o `TokenController` do .NET **ainda não muda** nesta fase — ele continua
  emitindo HS256 para quem chama. A troca do emissor é a Fase 3.

Ao fim da Fase 2: um token de **qualquer** dos dois emissores é aceito pelos dois consumidores.

---

## Fase 3 — virar o emissor para o cashflow-auth

1. **cashflow-investimentos**: apontar o proxy de login para o `cashflow-auth`. Hoje
   `CashflowAuthHttpAdapter` chama `POST {cashflow.api.base-url}/api/token` — basta
   `cashflow.api.base-url` (env `CASHFLOW_API_BASE_URL`) passar a ser a URL do `cashflow-auth`.
   O path (`/api/token`) e o corpo (`{email, password}`) são iguais; a resposta
   `{id, email, token, expiresIn}` é compatível com o que o adapter já procura.
2. **Frontend(s)**: a tela de login do `cashflow` (.NET, `Site/`) passa a chamar o
   `cashflow-auth` em vez do `/api/token` do próprio .NET. (O `web/` do investimentos continua
   falando com o proxy da API Java, que agora repassa para o `cashflow-auth`.)
3. **cashflow (.NET) `/api/token`**: deixar de ser chamado. Opcional: transformá-lo num proxy
   fino para o `cashflow-auth` por uma release, para não quebrar clientes esquecidos, e depois
   removê-lo.
4. Observar logs/métricas: a partir daqui os tokens novos são todos RS256. Os HS256 ainda em
   circulação expiram em no máximo `COOKIE_EXPIRES_IN_MINUTES`.

Rollback: reapontar `CASHFLOW_API_BASE_URL` e o frontend de volta para o `/api/token` do .NET.
Como os consumidores ainda aceitam HS256 (Fase 2), a volta é imediata.

---

## Fase 4 — remover o HMAC

Depois de decorrido `max(TTL do token, maior sessão possível)` desde a Fase 3 — quando não há
mais nenhum HS256 válido em circulação:

1. **cashflow-investimentos**: remover o caminho `parseHs256`, a propriedade
   `cashflow.jwt.secret` e o `JwtTokenParser` legado; ligar a validação de `iss`.
2. **cashflow (.NET)**: remover o `SymmetricSecurityKey` de `IssuerSigningKeys`, ligar
   `ValidateIssuer = true`, e **apagar** `JwtTokenBuilder` + `TokenController` (e o
   `COOKIE_EXPIRES_IN_MINUTES`).
3. **Ambientes**: apagar `SECRET_JWT_KEY` dos dois consumidores. Ele deixa de existir no
   projeto.
4. **cashflow-auth**: quando os dois consumidores estiverem lendo `sub` (e não mais a claim de
   URI longa), remover `LEGACY_SID_CLAIM` de `NimbusRsaTokenSigner` (`especificacao.md` §8).

---

## Matriz de variáveis de ambiente

| variável | cashflow (.NET) | cashflow-investimentos | cashflow-auth |
|---|---|---|---|
| `SECRET_JWT_KEY` | Fase 0–3; **removida na 4** | Fase 0–3; **removida na 4** | — (nunca) |
| `AUTH_JWKS_URI` (nome à sua escolha) | some na Fase 2 | surge na Fase 2 | — |
| `AUTH_ISSUER` / `ValidIssuer` | Fase 2 (ligado na 4) | Fase 2 (ligado na 4) | define (`AUTH_ISSUER`) |
| `CASHFLOW_API_BASE_URL` | — | repontar p/ cashflow-auth na Fase 3 | — |
| `AUTH_PRIVATE_KEY_PEM` / `AUTH_ACTIVE_KID` | — | — | Fase 1 (secret manager) |

## Checklist rápido

- [ ] cashflow-auth no ar com chave estável e `AUTH_ISSUER` definitivo
- [ ] hash de senha homologado contra BCrypt.Net **ou** opção B ativa
- [ ] consumidores aceitando RS256 **e** HS256 (Fase 2 em produção)
- [ ] login dos frontends + proxy do investimentos apontando para o cashflow-auth (Fase 3)
- [ ] decorrido o TTL máximo → HMAC e `SECRET_JWT_KEY` removidos dos dois (Fase 4)
- [ ] `JwtTokenBuilder`/`TokenController` do .NET apagados
- [ ] claim de URI longa removida do cashflow-auth
