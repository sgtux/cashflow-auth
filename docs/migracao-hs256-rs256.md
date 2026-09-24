# Migração: HMAC-SHA256 (segredo compartilhado) → RS256 (JWKS)

Como tirar o `SECRET_JWT_KEY` compartilhado de circulação e passar os dois consumidores a
validar os tokens do `cashflow-auth` com a **chave pública**, sem janela de indisponibilidade.

## Onde cada app está hoje

| App | Emite token? | Valida como |
|---|---|---|
| **cashflow** (.NET) | Sim — `TokenController` + `JwtTokenBuilder`, HS256 | `AuthenticationMiddleware`, `SymmetricSecurityKey(ASCII(SECRET_JWT_KEY))` |
| **cashflow-investimentos** (Java) | Não (faz proxy do login para o .NET) | `JwtTokenParser`, `Keys.hmacShaKeyFor(ASCII(SECRET_JWT_KEY))` |
| **cashflow-auth** | Passará a ser o único emissor — RS256, **só via login social** (Google/Microsoft), sem senha | não valida token de ninguém |

Ponto-chave: hoje **quem valida também consegue emitir** (mesmo segredo). O objetivo é que só
o `cashflow-auth` tenha a chave de assinar.

> **Consequência do "sem senha":** o `cashflow-auth` não tem login por email+senha. Enquanto o
> login por senha do .NET existir, ele continua emitindo HS256 — então a Fase 4 (remover o HMAC)
> só é possível quando **todos** os logins passarem pelo login social.

## Ponto em aberto — identidade dos usuários

O `sub`/`sid` dos tokens do `cashflow-auth` é o `Id` de `auth.AuthIdentity`, um espaço de ids
**próprio** — não é o `Id` de usuário do Cashflow .NET. Hoje os dois consumidores leem esse id
do token e o usam para achar os dados do usuário (plano, carteira, registros). Com o
`cashflow-auth`, um mesmo usuário terá **um id diferente** do que tem hoje nesses sistemas.

Isso precisa ser decidido **antes da Fase 3**. Caminhos possíveis (nenhum implementado):

- cada consumidor resolve o **seu** usuário pelo claim `email` do token, em vez de pelo `sub`;
- o `cashflow-auth` passa a guardar/emitir o id do sistema legado (exige um vínculo entre as
  duas fontes de identidade, que hoje não existe).

Enquanto isso não for resolvido, tokens emitidos pelo `cashflow-auth` não identificam
corretamente os usuários já existentes nos consumidores.

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
3. `DATABASE_URL` apontando para um SQL Server (o banco precisa existir; o Flyway cria o schema
   `auth` e a tabela `AuthIdentity` na subida — pode ser o mesmo banco do Cashflow .NET, o
   serviço não toca nas tabelas dele).
4. Configurar os providers: `AUTH_OAUTH_GOOGLE_CLIENT_ID`, `AUTH_OAUTH_MICROSOFT_CLIENT_ID` e
   `AUTH_OAUTH_MICROSOFT_TENANT_ID` (`especificacao.md` §3).
5. Sanity: `POST .../api/token/oauth` com um ID token real devolve um JWT; `curl
   .../.well-known/jwks.json` devolve a chave pública; o JWT valida em jwt.io contra essa chave.

Neste ponto ninguém consome os tokens do `cashflow-auth` ainda.

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

**Pré-requisito:** resolver o "Ponto em aberto — identidade dos usuários" acima.

O `cashflow-auth` não tem login por senha, então **não dá para só trocar a base URL** do
`POST /api/token` (email+senha) — o contrato mudou: agora é `POST /api/token/oauth` com um ID
token de provider (`especificacao.md` §2).

1. **Frontend(s)**: a tela de login passa a autenticar com o provider (Google Sign-In / MSAL) e
   a enviar o ID token para `POST {cashflow-auth}/api/token/oauth`; o token de aplicação
   devolvido substitui o que hoje vem do `/api/token` do .NET.
2. **cashflow-investimentos**: o `CashflowAuthHttpAdapter` hoje repassa email+senha para o
   `POST {cashflow.api.base-url}/api/token` do .NET. Esse proxy de senha deixa de fazer sentido;
   o frontend fala direto com o `cashflow-auth` (ou o adapter passa a repassar o ID token para
   `/api/token/oauth`).
3. **cashflow (.NET) `/api/token`**: deixar de ser chamado. Opcional: mantê-lo por uma release
   para clientes esquecidos, e depois removê-lo. Ele só pode ser removido quando **nenhum**
   fluxo depender de login por senha.
4. Observar logs/métricas: a partir daqui os tokens novos são todos RS256. Os HS256 ainda em
   circulação expiram em no máximo `COOKIE_EXPIRES_IN_MINUTES`.

Rollback: apontar o frontend de volta para o `/api/token` do .NET. Como os consumidores ainda
aceitam HS256 (Fase 2), a volta é imediata.

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
| `CASHFLOW_API_BASE_URL` | — | deixa de ser o destino do login por senha na Fase 3 (§Fase 3, item 2) | — |
| `AUTH_PRIVATE_KEY_PEM` / `AUTH_ACTIVE_KID` | — | — | Fase 1 (secret manager) |
| `AUTH_OAUTH_GOOGLE_CLIENT_ID` / `AUTH_OAUTH_MICROSOFT_*` | — | — | Fase 1 |

## Checklist rápido

- [ ] cashflow-auth no ar com chave estável, `AUTH_ISSUER` definitivo e providers configurados
- [ ] **identidade dos usuários** decidida (ponto em aberto) — id do token vs. usuários existentes
- [ ] consumidores aceitando RS256 **e** HS256 (Fase 2 em produção)
- [ ] login dos frontends via provider → `POST /api/token/oauth` (Fase 3)
- [ ] decorrido o TTL máximo → HMAC e `SECRET_JWT_KEY` removidos dos dois (Fase 4)
- [ ] `JwtTokenBuilder`/`TokenController` do .NET apagados
- [ ] claim de URI longa removida do cashflow-auth
