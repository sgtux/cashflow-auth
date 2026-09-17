# cashflow-auth

Serviço de **identidade** do ecossistema Cashflow. Responsabilidade única: **autenticar um
usuário (email + senha) e devolver um JWT assinado com RS256**. Nada mais — sem domínio de
negócio, sem CRUD, sem UI.

Os outros serviços (**cashflow** .NET, **cashflow-investimentos** Java) deixam de compartilhar
um segredo HMAC e passam a **validar o token com a chave pública** publicada aqui em
`GET /.well-known/jwks.json`. A chave privada nunca sai deste serviço.

```
                            ┌────────────────────────────┐
  POST /api/token  ───────▶ │        cashflow-auth       │  assina com a CHAVE PRIVADA (RSA)
  {email, password}         │  - confere senha (bcrypt)  │
                            │  - emite JWT RS256         │
                            └────────────┬───────────────┘
                                         │  GET /.well-known/jwks.json  (chave PÚBLICA)
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
        cashflow-investimentos     cashflow (.NET)          (próximo app)
        valida o JWT com a chave pública — offline, sem chamar o auth por request
```

- **O quê** (contrato, formato do token, JWKS, rotação de chave): [`docs/especificacao.md`](docs/especificacao.md)
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
| `POST /api/token` — email+senha → JWT RS256 | [`TokenController`](src/main/java/com/cashflow/auth/adapter/in/web/TokenController.java) → [`IssueTokenService`](src/main/java/com/cashflow/auth/application/service/IssueTokenService.java) |
| `GET /.well-known/jwks.json` — chaves públicas | [`JwksController`](src/main/java/com/cashflow/auth/adapter/in/web/JwksController.java) |
| Assinatura RS256 + construção do JWKS (Nimbus) | [`SigningKeys`](src/main/java/com/cashflow/auth/config/SigningKeys.java) + [`NimbusRsaTokenSigner`](src/main/java/com/cashflow/auth/adapter/out/token/NimbusRsaTokenSigner.java) |
| Verificação de senha compatível com o BCrypt "enhanced" do .NET | [`EnhancedBCryptPasswordVerifier`](src/main/java/com/cashflow/auth/domain/password/EnhancedBCryptPasswordVerifier.java) |
| Leitura da tabela `[User]` do Cashflow (só leitura) | [`JdbcUserAdapter`](src/main/java/com/cashflow/auth/adapter/out/persistence/JdbcUserAdapter.java) |
| `GET /actuator/health` | starter actuator |

**Ainda não** (ver `docs/especificacao.md` §8): rotação de chave automatizada, refresh tokens,
`POST /oauth/introspect`, endpoint OIDC discovery, migração do cadastro de usuário para cá.

## Pré-requisitos

- JDK 21
- Maven 3.9+ (sem wrapper commitado ainda — `mvn -N wrapper:wrapper` se quiser `./mvnw`)
- Docker (SQL Server local com um usuário de teste)

## Subir o banco de teste

```bash
cd cashflow-auth
cp .env.example .env          # ajuste as senhas se quiser
docker compose --env-file .env up -d

# cria a tabela [User] e um usuario de teste (teste@cashflow.local / Cashflow@123):
docker exec -i cashflow-auth-db /opt/mssql-tools18/bin/sqlcmd \
  -C -S localhost -U sa -P "$(grep DATABASE_PASSWORD .env | cut -d= -f2)" \
  -i /dev/stdin < local/seed.sql
```

Em produção **não** se usa `local/seed.sql`: `DATABASE_URL` aponta para o banco real do
Cashflow .NET, que já tem `[User]` e os cadastros.

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
# 1. login -> JWT RS256
curl -s localhost:9000/api/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"teste@cashflow.local","password":"Cashflow@123"}'
# -> {"id":1,"email":"teste@cashflow.local","token":"<jwt>","expiresIn":3600}

# 2. chave publica que qualquer servico usa para validar
curl -s localhost:9000/.well-known/jwks.json
# -> {"keys":[{"kty":"RSA","kid":"dev","use":"sig","alg":"RS256","n":"...","e":"AQAB"}]}

# 3. inspecione o token em jwt.io: header {alg:RS256, kid:dev}, claims {iss, sub, exp, email, ...}
```

## Testes

```bash
mvn test
```

- `NimbusRsaTokenSignerTest` — ida-e-volta assimétrica: assina com a privada, valida só com o JWKS público.
- `EnhancedBCryptPasswordVerifierTest` — compatibilidade do hash de senha com o .NET (o caso
  `valida_hash_real_do_dotnet` está `@Disabled` até colar um hash real do Cashflow — ver
  `docs/especificacao.md` §6).

## Notas de configuração

- **A chave privada nunca é versionada.** Em produção vem de um secret manager, injetada em
  `AUTH_PRIVATE_KEY_PEM` (ou um caminho de arquivo, se preferir adaptar `SigningKeys`).
- **`AUTH_ISSUER`** precisa ser idêntico ao valor que os consumidores esperam na claim `iss`.
- O `[User]` lido aqui **continua sendo propriedade do Cashflow .NET** enquanto o cadastro
  não migrar para cá (ver `docs/especificacao.md` §7).
