# cashflow-auth — arquitetura

**Como** o serviço é organizado por dentro. O **o quê** está em
[`especificacao.md`](./especificacao.md).

Mesma filosofia do cashflow-investimentos (Ports & Adapters, dependência apontando para
dentro), mas o serviço é minúsculo — um caso de uso — então a estrutura é enxuta e a seção 6
registra onde a pureza hexagonal foi afrouxada de propósito.

## 1. Camadas

```
        adapter/in/web         OAuthTokenController · JwksController · ApiExceptionHandler
              │  chama a porta de entrada
              ▼
        application            AuthenticateWithProviderUseCase (porta in)
                               AuthenticateWithProviderService (orquestração)
                               ValidateGoogleIdTokenOutputPort · ValidateMicrosoftIdTokenOutputPort
                               FindAuthIdentityByEmailOutputPort · CreateAuthIdentityOutputPort
                               TokenSignerPort                                   (portas out)
              │  usa o domínio
              ▼
        domain                 AuthUser · ProviderIdentity · OAuthProvider
                               InvalidProviderTokenException · TokenExpiredException
              ▲  implementam as portas out
              │
        adapter/out            oauth/GoogleIdTokenValidatorAdapter
                               oauth/MicrosoftIdTokenValidatorAdapter
                               persistence/JdbcAuthIdentityAdapter
                               token/NimbusRsaTokenSigner
        config                 SigningKeys · AuthProperties · OAuthProperties
                               SecurityConfig · RequestTimingFilter
```

Regra de dependência: `adapter → application → domain`. O domínio não conhece Spring, JDBC nem
Nimbus. `AuthenticateWithProviderService` conhece só as portas e o domínio.

## 2. O fluxo, ponta a ponta

```
POST /api/token/oauth {provider, idToken}
  │
  ▼  adapter/in/web — OAuthTokenController
validação Bean (provider presente, idToken não-branco)
monta AuthenticateCommand(provider, idToken)
  │
  ▼  application — AuthenticateWithProviderService.authenticate(command)
ProviderIdentity id = validator(provider).validate(idToken)   → 401 se inválido/expirado
AuthUser user = findAuthIdentity.find(email)
                  ?: createAuthIdentity.create(email, provider, subject)   (1º login)
String jwt = tokenSigner.sign(user)
return IssuedToken(user.id, user.email, jwt, ttlSeconds)
  │
  ▼  adapter/out
Google/MicrosoftIdTokenValidatorAdapter → verifica assinatura (JWKS do provider), iss, aud, exp
JdbcAuthIdentityAdapter → SELECT / INSERT em auth.AuthIdentity
NimbusRsaTokenSigner    → JWTClaimsSet + JWSHeader(kid) + RSASSASigner(chave privada ativa)
  │
  ▼  OAuthTokenController → 200 TokenResponse
```

`GET /.well-known/jwks.json` é independente: `JwksController` devolve
`SigningKeys.publicJwks()` — só as chaves públicas, com `Cache-Control`.

## 3. Domínio (`domain`)

Java puro, sem framework.

- **`AuthUser`** (`record`) — `id`, `email`. É só o necessário para assinar o token; não há
  entidade rica de usuário (cadastro, plano e limites não são deste serviço).
- **`ProviderIdentity`** (`record`) — o que um provider confirmou: `subject` (claim `sub`),
  `email`, `provider`. É o resultado da validação do ID token; ainda não é um `AuthUser`, porque
  o usuário pode não existir em `auth.AuthIdentity`.
- **`OAuthProvider`** (`enum`) — `GOOGLE`, `MICROSOFT`.
- **`InvalidProviderTokenException`** — ID token inválido; mensagem única, sem detalhar o motivo.
- **`TokenExpiredException`** — ID token expirado (hoje lançada só pelo validador da Microsoft).

## 4. Aplicação (`application`)

- **`port/in/AuthenticateWithProviderUseCase`** — a única porta de entrada. Carrega o
  `AuthenticateCommand` e o `IssuedToken` como records aninhados.
- **`port/out/ValidateGoogleIdTokenOutputPort`** e **`ValidateMicrosoftIdTokenOutputPort`** —
  `ProviderIdentity validate(String idToken)`. Duas portas, uma por provider, em vez de uma
  genérica com `Map<provider, validator>`: são só dois, e a injeção fica explícita.
- **`port/out/FindAuthIdentityByEmailOutputPort`** — `Optional<AuthUser> find(String email)`.
- **`port/out/CreateAuthIdentityOutputPort`** — `AuthUser create(email, provider, subject)`.
  Uma porta por operação, cada uma com o que o caso de uso realmente usa.
- **`port/out/TokenSignerPort`** — `String sign(AuthUser)`. Abstrai a lib de JWT: o service não
  sabe que é Nimbus nem que é RS256.
- **`service/AuthenticateWithProviderService`** — orquestra os passos acima. Sem regra própria
  além de normalizar o email e coordenar. `@Service`.

## 5. Adaptadores e config

### 5.1 `adapter/in/web`

- **`OAuthTokenController`** (`POST /api/token/oauth`) — JSON ↔ command, chama a porta, mapeia
  para `TokenResponse`. Os nomes de campo do contrato (`id`, `token`, `expiresIn`) vivem no DTO.
- **`JwksController`** (`GET /.well-known/jwks.json`) — serializa `SigningKeys.publicJwks()`.
- **`ApiExceptionHandler`** — `@RestControllerAdvice`: `InvalidProviderTokenException`→401,
  `TokenExpiredException`→401, `MethodArgumentNotValidException`→400, `DataAccessException`→503,
  resto→500. Sempre `{ "message": "..." }`.

### 5.2 `adapter/out`

- **`oauth/GoogleIdTokenValidatorAdapter`** e **`oauth/MicrosoftIdTokenValidatorAdapter`** —
  verificam o ID token com o JWKS remoto do provider (Nimbus `JWKSourceBuilder`, cacheado) mais
  `iss`/`aud`/`exp`. Regras por provider em `especificacao.md` §6.2.
- **`persistence/JdbcAuthIdentityAdapter`** (implementa `FindAuthIdentityByEmailOutputPort` e
  `CreateAuthIdentityOutputPort`) — `JdbcClient` sobre `auth.AuthIdentity`, o schema que o
  serviço possui. Sem JPA; migrations com Flyway (`db/migration/`, `spring.flyway.schemas: auth`).
- **`token/NimbusRsaTokenSigner`** (implementa `TokenSignerPort`) — monta `JWTClaimsSet` (claims
  da `especificacao.md` §4, incluindo a claim de URI longa para compatibilidade), header com o
  `kid` da chave ativa, assina com `RSASSASigner`.

### 5.3 `config`

- **`AuthProperties`** (`@ConfigurationProperties("auth")`) — issuer, TTL, `activeKid`, PEM,
  JWKS extra, flag de dev.
- **`OAuthProperties`** (`@ConfigurationProperties("auth.oauth")`) — client id do Google, client
  id + tenant id da Microsoft. Usada pelos validators de `adapter/out/oauth`.
- **`SigningKeys`** (`@Component`) — no construtor: carrega a chave privada ativa (do PEM ou
  gera efêmera) e monta o `JWKSet` público (ativa + `additional-jwks`). Expõe
  `activeSigningKey()` (com privada, para o signer) e `publicJwks()` (só pública, para o
  controller). É o único ponto que toca material de chave.
- **`SecurityConfig`** — público: `/api/token/oauth`, JWKS e health; resto `denyAll`. `csrf`
  off, stateless, sem `formLogin`/`httpBasic`. **Não há filtro de JWT** — este serviço não
  valida token de ninguém.
- **`RequestTimingFilter`** — loga método, path, status e duração de cada requisição.

## 6. Decisões e trade-offs

- **Só login social, sem senha.** Sem hash, sem cadastro, sem reset: a credencial é a do
  provider, que já cuida de MFA e recuperação. O serviço só *verifica* o ID token; não é um
  Authorization Server.
- **`JdbcClient` em vez de JPA.** Uma tabela, duas queries (`SELECT` e `INSERT`). JPA traria
  `ddl-auto`, entidade e dialect sem benefício. O Flyway cuida do schema, restrito a `auth`.
- **Schema `auth` próprio.** Deixa a posse dos dados inequívoca no próprio banco e permite
  compartilhar o banco físico com outros sistemas sem risco: o Flyway só enxerga `auth`.
- **Emissão manual com Nimbus, não Spring Authorization Server.** O caso de uso é
  `ID token de provider → JWT` + JWKS. O Authorization Server entrega OAuth2/OIDC inteiro
  (fluxos, consent, discovery, client registry) — peso morto agora. A porta `TokenSignerPort`
  isola a decisão: trocar para o Authorization Server depois não toca o service.
- **Claim de URI longa mantida.** Dívida proposital: evita que a migração dos consumidores
  precise trocar a validação da assinatura **e** a extração do `userId` no mesmo deploy.
  Remoção agendada (`especificacao.md` §8).
- **`@Service`/`@Component` na aplicação.** Mesma concessão pragmática que o
  cashflow-investimentos documenta: anotação de DI em código de aplicação, aceita pelo tamanho
  do projeto. O `domain` não depende de Spring.
- **Chave privada por env var (PEM), não keystore.** Simples de injetar via secret manager e
  de rotacionar. `SigningKeys` está isolado o suficiente para trocar por um `KeyStore`/HSM
  sem mexer no resto.
- **RSA e não EC.** Só por compatibilidade universal das libs dos dois consumidores. Migrar
  para `ES256` depois é adicionar uma chave ao JWKS.
- **Sem refresh token no scaffold.** TTL de 60 min + rebusca de JWKS cobre o caminho feliz.
  Refresh é o item 7 do roteiro, quando/se a UX pedir.

## 7. Testes

| Alvo | Como |
|---|---|
| `NimbusRsaTokenSigner` + `SigningKeys` | JUnit puro: assina e valida **só com o JWKS público**; confere claims; garante que o JWKS não vaza material privado. **Existe.** |
| `AuthenticateWithProviderService` | JUnit + Mockito nas portas: usuário novo → cria e assina; usuário existente → não cria; token inválido → propaga a exceção. *(a escrever)* |
| Validators de provider | JUnit com um JWKS/JWT gerados no teste (sem rede): assinatura, `iss`, `aud`, `exp`, `email_verified`. *(a escrever)* |
| `adapter/in/web` | `@WebMvcTest` + `MockMvc`, use case mockado: shape do JSON, códigos de status. *(a escrever)* |
| `JdbcAuthIdentityAdapter` | `@JdbcTest` + Testcontainers (SQL Server) com o Flyway aplicado. *(a escrever)* |
| Fronteiras | ArchUnit: `domain` sem `org.springframework..`; `application` sem `..adapter..`. Há testes em `src/test/java/.../architecture/`, ainda sem apontar para o pacote real. |
