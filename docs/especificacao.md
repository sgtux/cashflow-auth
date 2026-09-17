# cashflow-auth — especificação

O **quê** o serviço entrega. O **como** interno está em [`arquitetura.md`](./arquitetura.md);
o plano de corte dos consumidores está em [`migracao-hs256-rs256.md`](./migracao-hs256-rs256.md).

## 1. Visão geral e decisões

- **Responsabilidade única: emitir token.** O `cashflow-auth` autentica e assina um JWT. Ele
  **não** valida Bearer token de ninguém, não tem domínio de negócio, não tem tela. Se um dia
  precisar de "quem sou eu", isso é um endpoint dos serviços consumidores, não daqui.
- **Criptografia assimétrica (RS256).** A chave **privada** RSA vive só neste serviço e só
  serve para **assinar**. A chave **pública** é distribuída via JWKS e serve para **verificar**.
  Assim, comprometer um serviço consumidor não permite **forjar** tokens — no esquema atual
  (HMAC-SHA256 com segredo compartilhado) qualquer serviço que valida também pode emitir.
- **Validação offline nos consumidores.** Cada consumidor baixa o JWKS uma vez, cacheia, e
  valida assinatura + `exp` + `iss` localmente. Não há chamada ao `cashflow-auth` por
  request. O JWKS só é rebuscado quando aparece um `kid` desconhecido ou o cache expira.
- **Sem OAuth2/OIDC completo (por enquanto).** Um `POST /api/token` com `{email, password}` e
  um JWKS resolvem o caso de uso real (login de usuário para SPAs próprias). Spring
  Authorization Server / fluxo `authorization_code` + PKCE + discovery seria peso sem
  benefício agora — a seção 8 lista o caminho se isso mudar.
- **Compatível com o token de hoje.** O formato de claims mantém a claim de URI longa que o
  .NET emite atualmente (`http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid`), para
  os consumidores migrarem a validação sem reescrever a extração de `userId` no mesmo passo.

## 2. Contrato — emissão de token

### `POST /api/token`

Mesmo path e mesmo corpo que a API .NET expõe hoje, de propósito: o proxy de login do
cashflow-investimentos passa a apontar para cá trocando só a base URL.

Requisição:
```json
{ "email": "usuario@exemplo.com", "password": "senha123" }
```

Resposta — sucesso (200):
```json
{ "id": 42, "email": "usuario@exemplo.com", "token": "<jwt RS256>", "expiresIn": 3600 }
```

Resposta — falha (401), email/senha errados ou conta sem senha:
```json
{ "message": "Credenciais inválidas" }
```

Outras respostas: `400` (corpo inválido — email malformado / campo em branco), `503` (banco
de usuários indisponível), `500` (inesperado). Sempre no envelope `{ "message": "..." }`.

> A mensagem de 401 é **única** para email inexistente, conta sem senha e senha errada — não
> revela qual foi, para não permitir enumeração de usuários.

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

Liveness/readiness. `503` se o banco de usuários não responde.

## 3. Configuração

Tudo por variável de ambiente (prefixo `auth.*` em `application.yml`). Ver `.env.example`.

| variável | descrição |
|---|---|
| `DATABASE_URL` / `DATABASE_USERNAME` / `DATABASE_PASSWORD` | conexão JDBC com o banco que tem a tabela `[User]` (o banco do Cashflow .NET em produção) |
| `AUTH_ISSUER` | valor da claim `iss`; os consumidores exigem este valor exato |
| `AUTH_TOKEN_TTL_MINUTES` | tempo de vida do token (default 60) |
| `AUTH_ACTIVE_KID` | `kid` da chave que assina; precisa existir no JWKS |
| `AUTH_PRIVATE_KEY_PEM` | chave privada RSA ativa, PEM PKCS#8; vazio em dev usa chave efêmera |
| `AUTH_ADDITIONAL_JWKS` | JSON com chaves **públicas** antigas ainda aceitas (rotação) |
| `AUTH_DEV_GENERATE_KEY` | dev: gera par efêmero se não há `AUTH_PRIVATE_KEY_PEM`. **`false` em produção** |
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
| `sub` | `"42"` | id do usuário, string. Claim padrão — consumidores novos devem ler daqui. |
| `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/sid` | `"42"` | **compatibilidade**: é onde os consumidores atuais leem o id hoje. Removível ao fim da migração (§8). |
| `email` | `"usuario@exemplo.com"` | conveniência. |
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

## 6. Verificação de senha — compatibilidade com o .NET

O cadastro do Cashflow grava a senha com
`BCrypt.Net.BCrypt.EnhancedHashPassword(senha, 12, HashType.SHA512)`
(`Api/Utils/CryptographyUtils.cs`). "Enhanced" quer dizer:

```
bcrypt( Base64( SHA-512( utf8(senha) ) ), custo=12 )
```

`EnhancedBCryptPasswordVerifier` reproduz exatamente isso. **Ponto de atenção — limite de 72
bytes do bcrypt**: o Base64 de um SHA-512 tem 88 bytes. O verifier usa a estratégia
`truncate` (corta em 72, comportamento clássico do bcrypt em C). Isso **precisa ser conferido
contra um hash real** do BCrypt.Net:

```
# no projeto Cashflow, num teste ou REPL:
Console.WriteLine(CryptographyUtils.PasswordHash("Cashflow@123"));
```

Cole o resultado em `EnhancedBCryptPasswordVerifierTest#valida_hash_real_do_dotnet`, remova o
`@Disabled` e rode. Se falhar, as hipóteses, em ordem:

1. BCrypt.Net-Next **não trunca** — ele hasheia-para-caber. Trocar `truncate` por uma
   estratégia equivalente (ou aplicar outro SHA-256 sobre o Base64).
2. O default "enhanced" real é **SHA-384** (Base64 = 64 bytes, cabe em 72 sem truncar) e o
   `HashType.SHA512` explícito no código muda só o pré-hash — conferir a lib.
3. Encoding do pré-hash é hex, não Base64.

Enquanto isso não for validado, tratar o login por senha como **não homologado**. Alternativa
de menor risco para a fase 1: o `cashflow-auth` **delega** a checagem de senha para o
`POST /api/token` do .NET (server-to-server) e só re-emite como RS256 — ver
`migracao-hs256-rs256.md` §Fase 1, opção B.

Contas criadas via Google (`Password` nulo na tabela) **não logam por senha** aqui — retornam
401. Login social, se necessário, é um endpoint à parte no futuro (§8).

## 7. Propriedade dos dados

O `cashflow-auth` **lê** a tabela `[User]` (colunas `Id`, `Email`, `Password`) mas **não é
dono dela**: cadastro, plano, limites, `RecordsUsed` etc. continuam no Cashflow .NET, que
escreve nessa tabela. O `cashflow-auth` só precisa de identidade + credencial.

Fim de jogo desejável (fora do escopo deste scaffold): mover cadastro/reset de senha para o
`cashflow-auth`, e o `[User]` (ou ao menos `Email`/`Password`) passa a ser propriedade dele,
com o Cashflow .NET lendo o id via token como qualquer outro consumidor. Só vale o esforço se
o cadastro precisar evoluir de forma independente do Cashflow.

## 8. Roteiro

1. **Scaffold** (feito): `POST /api/token` assinando RS256 com chave de config/efêmera,
   `GET /.well-known/jwks.json`, verificação de senha, leitura do `[User]`, health.
2. **Homologar o hash de senha** contra o BCrypt.Net real (§6) — ou plugar a opção B (delegar
   ao .NET) se a compatibilidade não fechar rápido.
3. **Migrar os consumidores** para validar RS256 via JWKS — ver `migracao-hs256-rs256.md`.
4. **Rotação de chave** como job/runbook versionado (hoje é manual via env).
5. **Refresh token** (tabela própria + `POST /api/token/refresh` + revogação) se o TTL curto
   incomodar a UX.
6. **`POST /oauth/introspect`** e/ou blocklist por `jti` para revogação imediata.
7. **OIDC discovery** (`/.well-known/openid-configuration`) e, se aparecer cliente
   third-party, `authorization_code` + PKCE — aí sim adotar o Spring Authorization Server.
8. **Limpeza pós-migração**: remover a claim de URI longa, o segredo HMAC dos consumidores e o
   endpoint `/api/token` do .NET.
