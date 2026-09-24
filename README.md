# cashflow-auth

Serviço de **identidade** do ecossistema Cashflow. Responsabilidade única: **autenticar via
login social (Google ou Microsoft) e devolver um JWT assinado com RS256**. Não há login por
senha. Nada mais — sem domínio de negócio, sem CRUD, sem UI.

Os outros serviços (**cashflow** .NET, **cashflow-investimentos** Java) deixam de compartilhar
um segredo HMAC e passam a **validar o token com a chave pública** publicada aqui em
`GET /.well-known/jwks.json`. A chave privada nunca sai deste serviço.

```
                            ┌─────────────────────────────┐
  POST /api/token/oauth ──▶ │        cashflow-auth        │  assina com a CHAVE PRIVADA (RSA)
  {provider, idToken}       │  - valida o ID token        │
  (token do Google/MS)      │    com o provider           │
                            │  - cria o usuário (1º login)│
                            │  - emite JWT RS256          │
                            └────────────┬────────────────┘
                                         │  GET /.well-known/jwks.json  (chave PÚBLICA)
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
        cashflow-investimentos     cashflow (.NET)          (próximo app)
        valida o JWT com a chave pública — offline, sem chamar o auth por request
```

- **O quê** (contrato, formato do token, JWKS, login social, rotação de chave): [`docs/especificacao.md`](docs/especificacao.md)
- **Como** (camadas, pacotes, wiring, testes): [`docs/arquitetura.md`](docs/arquitetura.md)
- **Migração** dos dois apps de HMAC-SHA256 → RS256: [`docs/migracao-hs256-rs256.md`](docs/migracao-hs256-rs256.md)

## Por que agora

`docs/api-especificacao.md` do cashflow-investimentos registrou (§1) que um `cashflow-auth`
separado seria over-engineering **com só 2 apps**, e que valeria reavaliar quando surgisse um
terceiro consumidor da mesma identidade. É essa reavaliação: com mais de um serviço validando
o mesmo token, um **segredo simétrico compartilhado** entre todos deixa de ser aceitável
(qualquer serviço com o segredo pode *forjar* tokens, não só validá-los). Criptografia
assimétrica separa os papéis: **só o auth assina; todo o resto só verifica**.

## Estado atual — scaffold

| Item | Onde |
|------|------|
| Projeto Spring Boot 3.4 / Java 21 | [`pom.xml`](pom.xml) |
| `POST /api/token/oauth` — ID token Google/Microsoft → JWT RS256 | [`OAuthTokenController`](src/main/java/com/cashflow/auth/adapter/in/web/OAuthTokenController.java) → [`AuthenticateWithProviderService`](src/main/java/com/cashflow/auth/application/service/AuthenticateWithProviderService.java) |
| Validação do ID token de cada provider (JWKS remoto, `iss`, `aud`) | [`GoogleIdTokenValidatorAdapter`](src/main/java/com/cashflow/auth/adapter/out/oauth/GoogleIdTokenValidatorAdapter.java) · [`MicrosoftIdTokenValidatorAdapter`](src/main/java/com/cashflow/auth/adapter/out/oauth/MicrosoftIdTokenValidatorAdapter.java) |
| Usuários em `auth.AuthIdentity` (schema próprio, migrations com Flyway) | [`JdbcAuthIdentityAdapter`](src/main/java/com/cashflow/auth/adapter/out/persistence/JdbcAuthIdentityAdapter.java) · [`db/migration`](src/main/resources/db/migration) |
| `GET /.well-known/jwks.json` — chaves públicas | [`JwksController`](src/main/java/com/cashflow/auth/adapter/in/web/JwksController.java) |
| Assinatura RS256 + construção do JWKS (Nimbus) | [`SigningKeys`](src/main/java/com/cashflow/auth/config/SigningKeys.java) + [`NimbusRsaTokenSigner`](src/main/java/com/cashflow/auth/adapter/out/token/NimbusRsaTokenSigner.java) |
| `GET /actuator/health` | starter actuator |

**Ainda não** (ver `docs/especificacao.md` §8): rotação de chave automatizada, refresh tokens,
`POST /oauth/introspect`, endpoint OIDC discovery, mapeamento entre os ids deste serviço e os
usuários já existentes no Cashflow .NET.

## Pré-requisitos

- JDK 21
- Maven 3.9+ (sem wrapper commitado ainda — `mvn -N wrapper:wrapper` se quiser `./mvnw`)
- Docker (SQL Server local)
- Um app registrado no **Google Cloud Console** e/ou no **Microsoft Entra ID** (os client ids
  vão em `AUTH_OAUTH_*`, ver `.env.example`)

## Subir o banco de teste

```bash
cd cashflow-auth
cp .env.example .env          # ajuste as senhas se quiser
docker compose --env-file .env up -d

# cria o banco. O Flyway cria o schema "auth" e a tabela quando a aplicação sobe,
# mas não cria o banco em si:
docker exec -i cashflow-auth-db /opt/mssql-tools18/bin/sqlcmd \
  -C -S localhost -U sa -P "$(grep DATABASE_PASSWORD .env | cut -d= -f2)" \
  -Q "IF DB_ID('cashflow') IS NULL CREATE DATABASE cashflow"
```

Em produção `DATABASE_URL` aponta para um SQL Server onde o Flyway cria o schema `auth` — pode
ser o mesmo banco do Cashflow .NET, o serviço não toca nas tabelas dele.

## Rodar

```bash
cd cashflow-auth
mvn spring-boot:run     # lê o .env via spring.config.import
```

Sem `AUTH_PRIVATE_KEY_PEM` no `.env`, a subida gera um par RSA **efêmero** (troca a cada
restart — bom para dev, os consumidores rebuscam o JWKS sozinhos). Para uma chave estável:

```bash
mkdir -p local/keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out local/keys/active.pem
# no .env:  AUTH_PRIVATE_KEY_PEM="$(cat local/keys/active.pem)"   e   AUTH_DEV_GENERATE_KEY=false
```

### Provar a emissão + validação assimétrica

```bash
# 1. chave publica que qualquer servico usa para validar (nao precisa de provider)
curl -s localhost:9000/.well-known/jwks.json
# -> {"keys":[{"kty":"RSA","kid":"2026-09","use":"sig","alg":"RS256","n":"...","e":"AQAB"}]}

# 2. login social -> JWT RS256. Precisa de um ID token REAL do provider (obtido no frontend
#    com Google Sign-In / MSAL) e dos AUTH_OAUTH_* configurados para esse mesmo app:
curl -s localhost:9000/api/token/oauth \
  -H 'Content-Type: application/json' \
  -d '{"provider":"GOOGLE","idToken":"<id token do provider>"}'
# -> {"id":1,"email":"voce@exemplo.com","token":"<jwt>","expiresIn":3600}

# 3. inspecione o token em jwt.io: header {alg:RS256, kid:2026-09}, claims {iss, sub, exp, email, ...}
```

## Testes

```bash
mvn test
```

- `NimbusRsaTokenSignerTest` — ida-e-volta assimétrica: assina com a privada, valida só com o JWKS público.

## Notas de configuração

- **A chave privada nunca é versionada.** Em produção vem de um secret manager, injetada em
  `AUTH_PRIVATE_KEY_PEM` (ou um caminho de arquivo, se preferir adaptar `SigningKeys`).
- **`AUTH_ISSUER`** precisa ser idêntico ao valor que os consumidores esperam na claim `iss`.
- Os **client ids** (`AUTH_OAUTH_*`) precisam ser os do mesmo app que emitiu o ID token: o
  serviço rejeita tokens cujo `aud` seja outro.
- O `id` no token é o de `auth.AuthIdentity`, **não** o id de usuário do Cashflow .NET (ver
  `docs/especificacao.md` §7.3).
