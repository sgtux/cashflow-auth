# cashflow-auth — especificação

O **quê** o serviço entrega. O **como** interno está em [`arquitetura.md`](./arquitetura.md);
o plano de corte dos consumidores está em [`migracao-hs256-rs256.md`](./migracao-hs256-rs256.md).

## 1. Visão geral e decisões

- **Responsabilidade única: autenticar via login social e emitir token.** O `cashflow-auth`
  recebe o ID token que o frontend obteve do **Google** ou da **Microsoft**, valida esse token
  com o provider, cria o usuário no primeiro login e assina um JWT próprio. Ele **não** valida
  Bearer token de ninguém, não tem domínio de negócio, não tem tela.
- **Sem login por senha.** Não existe email+senha, hash de senha, cadastro nem reset aqui: a
  identidade de um usuário é sempre a de um provider. Não há `POST /api/token` com senha.
- **Criptografia assimétrica (RS256).** A chave **privada** RSA vive só neste serviço e só
  serve para **assinar**. A chave **pública** é distribuída via JWKS e serve para **verificar**.
  Assim, comprometer um serviço consumidor não permite **forjar** tokens — no esquema anterior
  (HMAC-SHA256 com segredo compartilhado) qualquer serviço que valida também pode emitir.
- **Validação offline nos consumidores.** Cada consumidor baixa o JWKS uma vez, cacheia, e
  valida assinatura + `exp` + `iss` localmente. Não há chamada ao `cashflow-auth` por
  request. O JWKS só é rebuscado quando aparece um `kid` desconhecido ou o cache expira.
- **Consome OIDC, não é um Authorization Server.** O serviço só *verifica* ID tokens de
  providers externos (`POST /api/token/oauth`). Não implementa `authorization_code` + PKCE,
  consent nem discovery — Spring Authorization Server seria peso sem benefício agora; a seção 8
  lista o caminho se isso mudar.
- **Compatível com o token anterior.** O formato de claims mantém a claim de URI longa que o
  .NET emitia (`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid`), para os
  consumidores migrarem a validação sem reescrever a extração de `userId` no mesmo passo.

## 2. Contrato

### `POST /api/token/oauth`

Troca um ID token de um provider por um token de aplicação.

Requisição:
```json
{ "provider": "GOOGLE", "idToken": "<id token (JWT) recebido do provider no frontend>" }
```
`provider` é `"GOOGLE"` ou `"MICROSOFT"` (maiúsculas, o nome exato).

Resposta — sucesso (200):
```json
{ "id": 42, "email": "usuario@exemplo.com", "token": "<jwt RS256>", "expiresIn": 3600 }
```
`id` é o `Id` do usuário em `auth.AuthIdentity` (ver §7).

Resposta — falha (401), ID token inválido (assinatura, `iss`/`aud` errados, claim obrigatória
ausente) ou expirado:
```json
{ "message": "Token do provider invalido" }
```
Hoje só o validador da Microsoft distingue o token **expirado** (401 com mensagem própria);
o do Google devolve a mensagem genérica também nesse caso.

Outras respostas: `400` (corpo inválido — `provider` ausente ou `idToken` em branco), `503`
(banco indisponível), `500` (inesperado). Sempre no envelope `{ "message": "..." }`.

### `GET /.well-known/jwks.json`

Conjunto de chaves **públicas** (JWK Set, RFC 7517). É tudo que um consumidor precisa.

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "2026-09",
      "use": "sig",
      "alg": "RS256",
      "n": "0vx7ag...Base64URL do módulo...",
      "e": "AQAB"
    }
  ]
}
```

- Só material público (`n`, `e`) — nunca `d`, `p`, `q`, etc.
- `Cache-Control: public, max-age=3600`.
- Durante uma rotação, o array tem **mais de uma** chave (a nova + a anterior) — ver §5.2.

### `GET /actuator/health`

Liveness/readiness. `503` se o banco não responde.

## 3. Configuração

Tudo por variável de ambiente (prefixos `auth.*` e `auth.oauth.*` em `application.yml`). Ver
`.env.example`.

| variável | descrição |
|---|---|
| `DATABASE_URL` / `DATABASE_USERNAME` / `DATABASE_PASSWORD` | conexão JDBC com o SQL Server onde vive o schema `auth` (§7). O banco precisa existir |
| `AUTH_ISSUER` | valor da claim `iss`; os consumidores exigem este valor exato |
| `AUTH_TOKEN_TTL_MINUTES` | tempo de vida do token (default 60) |
| `AUTH_ACTIVE_KID` | `kid` da chave que assina; precisa existir no JWKS |
| `AUTH_PRIVATE_KEY_PEM` | chave privada RSA ativa, PEM PKCS#8; vazio em dev usa chave efêmera |
| `AUTH_ADDITIONAL_JWKS` | JSON com chaves **públicas** antigas ainda aceitas (rotação) |
| `AUTH_DEV_GENERATE_KEY` | dev: gera par efêmero se não há `AUTH_PRIVATE_KEY_PEM`. **`false` em produção** |
| `AUTH_OAUTH_GOOGLE_CLIENT_ID` | client ID do app no Google Cloud Console; valida `aud` |
| `AUTH_OAUTH_MICROSOFT_CLIENT_ID` | client ID (Application ID) do app no Microsoft Entra ID; valida `aud` |
| `AUTH_OAUTH_MICROSOFT_TENANT_ID` | tenant ID do Microsoft Entra ID |
| `SERVER_PORT` | porta HTTP (default 9000) |

## 4. Formato do JWT

**Header**
```json
{ "alg": "RS256", "typ": "JWT", "kid": "2026-09" }
```
O `kid` diz ao consumidor qual chave do JWKS usar — essencial para rotação sem downtime.

**Claims**

| claim | exemplo | observação |
|---|---|---|
| `iss` | `https://auth.cashflow.example.com` | = `AUTH_ISSUER`. Consumidor valida igualdade exata. |
| `sub` | `"42"` | id do usuário (`auth.AuthIdentity.Id`), string. Claim padrão — consumidores novos devem ler daqui. |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid` | `"42"` | **compatibilidade**: é onde os consumidores atuais leem o id hoje. Removível ao fim da migração (§8). |
| `email` | `"usuario@exemplo.com"` | email confirmado pelo provider. |
| `iat` | `1757520000` | emissão. |
| `exp` | `1757523600` | `iat + AUTH_TOKEN_TTL_MINUTES`. Consumidor **deve** validar. |
| `jti` | `"9f1c..."` | id único do token; base para blocklist/introspect no futuro. |

**Não** há `aud` por enquanto (os consumidores não validam audience hoje). Quando houver mais
de um público com permissões distintas, adicionar `aud` com a lista de serviços e passar os
consumidores a validar — está anotado na §8.

**Algoritmo**: `RS256` (RSASSA-PKCS1-v1_5 + SHA-256), chave RSA de 2048 bits. `ES256` (curva
P-256) é uma alternativa válida e gera JWKS/assinaturas menores; ficou de fora só porque o
suporte a RSA é universal nas libs dos dois consumidores. Trocar depois é possível (é uma nova
chave no JWKS com outro `kty`/`alg`), mas não no mesmo passo da migração.

## 5. Chaves

### 5.1 Origem da chave

- **Produção**: `AUTH_PRIVATE_KEY_PEM` traz a privada (PEM PKCS#8), de um secret manager.
  `AUTH_ACTIVE_KID` dá o `kid`. Recomendação: `kid` = data (`2026-09`) ou thumbprint SHA-256
  da chave pública — algo estável e único por chave.
- **Dev**: sem PEM configurado e `AUTH_DEV_GENERATE_KEY=true`, `SigningKeys` gera um par RSA
  na subida. É efêmero (muda a cada restart); como os consumidores rebuscam o JWKS ao ver um
  `kid` novo, isso não trava o fluxo local.
- O serviço publica no JWKS a pública da chave ativa **+** as de `AUTH_ADDITIONAL_JWKS`.
- Sem `AUTH_PRIVATE_KEY_PEM` e com `AUTH_DEV_GENERATE_KEY=false`, a aplicação **não sobe**.

### 5.2 Rotação (runbook)

Sem downtime e sem invalidar tokens já emitidos:

1. **Gerar** a nova chave (`openssl genpkey ...`), com um `kid` novo.
2. **Publicar a pública nova junto com a atual**: colocar a pública da chave *vigente* em
   `AUTH_ADDITIONAL_JWKS` e subir a nova em `AUTH_PRIVATE_KEY_PEM` + `AUTH_ACTIVE_KID`.
   Agora o JWKS tem as duas; o serviço assina com a nova.
3. **Esperar** o TTL do cache de JWKS dos consumidores (1h) **+** o TTL dos tokens
   (`AUTH_TOKEN_TTL_MINUTES`). Depois disso, nenhum token válido em circulação foi assinado
   com a chave antiga.
4. **Remover** a chave antiga de `AUTH_ADDITIONAL_JWKS` e reiniciar. JWKS volta a ter uma só.
5. **Destruir** a privada antiga no secret manager.

**Comprometimento de chave** (rotação de emergência): pular direto para assinar com a nova e
**não** publicar a comprometida no JWKS — todos os tokens assinados por ela deixam de validar
na hora (é o efeito desejado). Avisar que os usuários vão precisar logar de novo.

## 6. Login social (OAuth)

### 6.1 Fluxo

O frontend já fez o login com o provider (Google Sign-In / MSAL) e tem um **ID token** (JWT
OIDC assinado pelo provider). O `cashflow-auth`:

1. Recebe `POST /api/token/oauth` com `{ provider, idToken }`.
2. Valida o ID token **localmente**, sem round-trip por request: verifica a assinatura com o
   JWKS público do provider (cacheado), além de `iss`, `aud` e `exp` (§6.2).
3. Busca o email confirmado em `auth.AuthIdentity`; se não existe, cria o registro (primeiro
   login daquela pessoa).
4. Assina e devolve o token de aplicação (§4).

### 6.2 Validação do ID token, por provider

| | Google | Microsoft (Entra ID) |
|---|---|---|
| JWKS | `https://www.googleapis.com/oauth2/v3/certs` | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| `iss` exigido | `https://accounts.google.com` | `https://login.microsoftonline.com/{tenant}/v2.0` |
| `aud` exigido | `AUTH_OAUTH_GOOGLE_CLIENT_ID` | `AUTH_OAUTH_MICROSOFT_CLIENT_ID` |
| Claims obrigatórias | `sub`, `email`, `exp` | `sub`, `exp` |
| Email usado | `email`, e `email_verified` tem de ser `true` | `email`; se ausente, `preferred_username` |

Assinatura `RS256` nos dois. Toda falha de validação devolve 401; só o validador da Microsoft
separa o caso "token expirado" (mensagem própria) do restante (mensagem genérica).

O claim `email` da Microsoft só vem preenchido se o app registration pedir o *optional claim*
`email` no Entra ID; o fallback para `preferred_username` (o UPN da conta) costuma ser um email
válido em contas corporativas/escolares, mas não é garantido.

### 6.3 Como a identidade é resolvida

A busca é **por email**, sem olhar o provider: quem loga com o mesmo email pelo Google e pela
Microsoft cai no **mesmo** usuário (o primeiro provider fica registrado). `Provider` e
`ExternalSubject` (o `sub` do provider) são gravados na criação, mas hoje **não** entram na
busca. Consequência: se a pessoa trocar o email na conta do provider, ela vira um usuário novo.
Passar a buscar por `(Provider, ExternalSubject)` resolveria isso sem migration.

### 6.4 Limitações conhecidas

- **Microsoft só com tenant fixo** (`AUTH_OAUTH_MICROSOFT_TENANT_ID`). O endpoint multi-tenant
  (`/common/`) emite um `iss` diferente por tenant; suportá-lo exigiria trocar a comparação
  exata de issuer por uma regra de padrão/prefixo.
- **Criação não é atômica com a busca.** Dois primeiros logins simultâneos do mesmo email
  podem tentar inserir duas vezes; a constraint `UNIQUE` em `Email` faz a segunda falhar, em vez
  de duplicar o registro.

## 7. Dados e migrations

### 7.1 Propriedade dos dados

O `cashflow-auth` possui **um schema**, `auth`, com **uma tabela**, `auth.AuthIdentity`:

| coluna | tipo | |
|---|---|---|
| `Id` | `INT IDENTITY` | vira `sub`/`sid` no token |
| `Email` | `VARCHAR(255)` `UNIQUE` | chave de busca (§6.3) |
| `Provider` | `VARCHAR(20)` | `GOOGLE` ou `MICROSOFT` |
| `ExternalSubject` | `VARCHAR(255)` | claim `sub` do provider |
| `CreatedAt` | `DATETIME` | default `GETUTCDATE()` |

O serviço **não lê nem escreve nenhuma tabela do Cashflow .NET**. O banco pode até ser o mesmo
banco físico dele; o schema separado é o que deixa a posse inequívoca no próprio banco, e é o
que torna seguro rodar Flyway ali (§7.2).

### 7.2 Migrations

Flyway, com `spring.flyway.schemas: auth`: ele **só enxerga** o schema `auth` e nunca `dbo` ou
qualquer outro. O schema `auth` é criado automaticamente na primeira subida; o **banco** em si
precisa existir antes (o Flyway cria schema e tabelas, não o banco).

Migrations em `src/main/resources/db/migration/`, versionadas por timestamp
(`V20260919141959__create_auth_identity.sql`, ...) em vez de inteiro sequencial (`V1`, `V2`) —
evita conflito de número entre branches/PRs concorrentes. Regra: nenhuma migration toca em algo
fora do schema `auth`.

### 7.3 Consequência para os consumidores

O id no token (`sub`/`sid`) é o `auth.AuthIdentity.Id`, um espaço de ids **próprio**, sem
relação com os ids de usuário do Cashflow .NET. Consumidores que usam esse id para achar dados
próprios (plano, carteira, registros) precisam decidir como mapeá-lo — ver "Ponto em aberto" em
[`migracao-hs256-rs256.md`](./migracao-hs256-rs256.md).

## 8. Roteiro

1. **Scaffold** (feito): `POST /api/token/oauth` (Google + Microsoft), JWKS, assinatura RS256
   com chave de config/efêmera, schema `auth` com Flyway, health.
2. **Migrar os consumidores** para validar RS256 via JWKS — ver `migracao-hs256-rs256.md`.
3. **Definir o mapeamento de identidade** com os ids de usuário do Cashflow .NET (ponto em
   aberto na migração), antes de virar os consumidores.
4. **Rotação de chave** como job/runbook versionado (hoje é manual via env).
5. **Buscar por `(Provider, ExternalSubject)`** em vez de só por email (§6.3), e tratar a
   corrida da criação (§6.4).
6. **Microsoft multi-tenant**, se aparecer cliente que precise (§6.4).
7. **Refresh token** (tabela própria + `POST /api/token/refresh` + revogação) se o TTL curto
   incomodar a UX.
8. **`POST /oauth/introspect`** e/ou blocklist por `jti` para revogação imediata.
9. **OIDC discovery** (`/.well-known/openid-configuration`) e, se aparecer cliente
   third-party, `authorization_code` + PKCE — aí sim adotar o Spring Authorization Server.
10. **Limpeza pós-migração**: remover a claim de URI longa e o segredo HMAC dos consumidores.
