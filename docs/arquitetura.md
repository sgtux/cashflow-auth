# cashflow-auth — arquitetura

**Como** o serviço é organizado por dentro. O **o quê** está em
[`especificacao.md`](./especificacao.md).

Mesma filosofia do cashflow-investimentos (Ports & Adapters, dependência apontando para
dentro), mas o serviço é minúsculo — um caso de uso — então a estrutura é enxuta e a seção 6
registra onde a pureza hexagonal foi afrouxada de propósito.

## 1. Camadas

```
        adapter/in/web         TokenController · JwksController · ApiExceptionHandler
              │  chama a porta de entrada
              ▼
        application            IssueTokenUseCase (porta in)
                               IssueTokenService (orquestração)
                               LoadUserPort · TokenSignerPort (portas out)
              │  usa o domínio
              ▼
        domain                 AuthUser · InvalidCredentialsException
                               password/EnhancedBCryptPasswordVerifier
              ▲  implementam as portas out
              │
        adapter/out            persistence/JdbcUserAdapter  (LoadUserPort)
                               token/NimbusRsaTokenSigner   (TokenSignerPort)
        config                 SigningKeys · AuthProperties · SecurityConfig
```

Regra de dependência: `adapter → application → domain`. O domínio não conhece Spring, JDBC nem
Nimbus. `IssueTokenService` conhece só as portas e o domínio.

## 2. O fluxo, ponta a ponta

```
POST /api/token {email, password}
  │
  ▼  adapter/in/web — TokenController
validação Bean (email não-branco e bem-formado, senha não-branca)
monta IssueTokenCommand(email, password)
  │
  ▼  application — IssueTokenService.issue(command)
AuthUser user = loadUserPort.findByEmail(email)         → 401 se não existe
if !passwordVerifier.matches(senha, user.passwordHash) → 401
String jwt = tokenSigner.sign(user)
return IssuedToken(user.id, user.email, jwt, ttlSeconds)
  │
  ▼  adapter/out
JdbcUserAdapter   → SELECT Id, Email, Password FROM [User] WHERE Email = ?
NimbusRsaTokenSigner → JWTClaimsSet + JWSHeader(kid) + RSASSASigner(chave privada ativa)
  │
  ▼  TokenController → 200 TokenResponse
```

`GET /.well-known/jwks.json` é independente: `JwksController` devolve
`SigningKeys.publicJwks()` — só as chaves públicas, com `Cache-Control`.

## 3. Domínio (`domain`)

Java puro, sem framework.

- **`AuthUser`** (`record`) — `id`, `email`, `passwordHash`. É só o necessário para autenticar;
  não há entidade rica de usuário (o Cashflow .NET é o dono disso — ver `especificacao.md` §7).
- **`InvalidCredentialsException`** — mensagem única, sem distinguir os casos (anti-enumeração).
- **`password/EnhancedBCryptPasswordVerifier`** — regra de verificação de senha compatível com
  o BCrypt "enhanced" do .NET. É lógica de domínio (não depende de Spring nem de I/O), mas usa
  a lib `at.favre.lib:bcrypt` — igual a `PortfolioCalculator` usar `BigDecimal`. Anotado com
  `@Component` só para injeção; poderia ser um POJO instanciado no service.

## 4. Aplicação (`application`)

- **`port/in/IssueTokenUseCase`** — a única porta de entrada. Carrega o `IssueTokenCommand` e
  o `IssuedToken` como records aninhados.
- **`port/out/LoadUserPort`** — `Optional<AuthUser> findByEmail(String)`.
- **`port/out/TokenSignerPort`** — `String sign(AuthUser)`. Abstrai a lib de JWT: o service não
  sabe que é Nimbus nem que é RS256.
- **`service/IssueTokenService`** — orquestra os três passos. Sem regra própria além de
  normalizar o email e coordenar. `@Service`.

## 5. Adaptadores e config

### 5.1 `adapter/in/web`

- **`TokenController`** (`POST /api/token`) — JSON ↔ command, chama a porta, mapeia para
  `TokenResponse`. Os nomes de campo do contrato (`id`, `token`, `expiresIn`) vivem no DTO.
- **`JwksController`** (`GET /.well-known/jwks.json`) — serializa `SigningKeys.publicJwks()`.
- **`ApiExceptionHandler`** — `@RestControllerAdvice`: `InvalidCredentialsException`→401,
  `MethodArgumentNotValidException`→400, `DataAccessException`→503, resto→500. Sempre
  `{ "message": "..." }`.

### 5.2 `adapter/out`

- **`persistence/JdbcUserAdapter implements LoadUserPort`** — `JdbcClient` (sem JPA, sem
  Flyway: o serviço não é dono de nenhum schema, só faz um `SELECT`). `[User]` entre colchetes
  porque `USER` é reservada no T-SQL.
- **`token/NimbusRsaTokenSigner implements TokenSignerPort`** — monta `JWTClaimsSet` (claims da
  `especificacao.md` §4, incluindo a claim de URI longa para compatibilidade), header com o
  `kid` da chave ativa, assina com `RSASSASigner`.

### 5.3 `config`

- **`AuthProperties`** (`@ConfigurationProperties("auth")`) — issuer, TTL, `activeKid`, PEM,
  JWKS extra, flag de dev.
- **`SigningKeys`** (`@Component`) — no construtor: carrega a chave privada ativa (do PEM ou
  gera efêmera) e monta o `JWKSet` público (ativa + `additional-jwks`). Expõe
  `activeSigningKey()` (com privada, para o signer) e `publicJwks()` (só pública, para o
  controller). É o único ponto que toca material de chave.
- **`SecurityConfig`** — tudo público (`/api/token`, JWKS, health), resto `denyAll`. `csrf`
  off, stateless, sem `formLogin`/`httpBasic`. **Não há filtro de JWT** — este serviço não
  valida token de ninguém.

## 6. Decisões e trade-offs

- **`JdbcClient` em vez de JPA/Flyway.** O serviço faz um `SELECT` numa tabela de que não é
  dono. JPA traria `ddl-auto`, entidade, dialect — e Flyway sugeriria que o schema é daqui.
  Um `JdbcClient` deixa explícito: leitura, sem posse.
- **Emissão manual com Nimbus, não Spring Authorization Server.** O caso de uso é
  `password → JWT` + JWKS. O Authorization Server entrega OAuth2/OIDC inteiro (fluxos,
  consent, discovery, client registry) — peso morto agora. A porta `TokenSignerPort` isola a
  decisão: trocar para o Authorization Server depois não toca o service.
- **Claim de URI longa mantida.** Dívida proposital: evita que a migração dos consumidores
  precise trocar a validação da assinatura **e** a extração do `userId` no mesmo deploy.
  Remoção agendada (`especificacao.md` §8).
- **`@Component`/`@Service` na aplicação e no verifier de senha.** Mesma concessão pragmática
  que o cashflow-investimentos documenta: anotação de DI em código de aplicação, aceita pelo
  tamanho do projeto. O `domain` não depende de Spring em runtime (só a anotação, que é
  `SOURCE`/`RUNTIME` mas inerte fora de um contexto).
- **Chave privada por env var (PEM), não keystore.** Simples de injetar via secret manager e
  de rotacionar. `SigningKeys` está isolado o suficiente para trocar por um `KeyStore`/HSM
  sem mexer no resto.
- **RSA e não EC.** Só por compatibilidade universal das libs dos dois consumidores. Migrar
  para `ES256` depois é adicionar uma chave ao JWKS.
- **Sem refresh token no scaffold.** TTL de 60 min + rebusca de JWKS cobre o caminho feliz.
  Refresh é a etapa 5 do roteiro, quando/se a UX pedir.

## 7. Testes

| Alvo | Como |
|---|---|
| `NimbusRsaTokenSigner` + `SigningKeys` | JUnit puro: assina e valida **só com o JWKS público**; confere claims; garante que o JWKS não vaza material privado. |
| `EnhancedBCryptPasswordVerifier` | JUnit: round-trip com o mesmo pré-processamento do .NET; caso `@Disabled` reservado para um hash **real** do BCrypt.Net (`especificacao.md` §6). |
| `IssueTokenService` | JUnit + Mockito nas portas (`LoadUserPort`, `TokenSignerPort`): usuário inexistente → 401, senha errada → 401, sucesso → `IssuedToken` com o TTL certo. *(a escrever)* |
| `adapter/in/web` | `@WebMvcTest` + `MockMvc`, use case mockado: shape do JSON, códigos de status. *(a escrever)* |
| `JdbcUserAdapter` | `@JdbcTest` + Testcontainers (SQL Server). *(a escrever)* |
| Fronteiras | ArchUnit: `domain` sem `org.springframework..`; `application` sem `..adapter..`. *(a escrever, espelhando o cashflow-investimentos)* |
