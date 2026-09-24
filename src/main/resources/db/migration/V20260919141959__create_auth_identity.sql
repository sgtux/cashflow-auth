-- Tabela dos usuarios provisionados via login social (Google/Microsoft) - unica coisa que o
-- cashflow-auth realmente possui no banco. Ver JdbcAuthIdentityAdapter e
-- ./docs/especificacao.md secao 9. O schema "auth" ja existe quando este script roda
-- (spring.flyway.schemas cria antes de aplicar as migrations).

CREATE TABLE auth.AuthIdentity (
    Id              INT           IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuthIdentity PRIMARY KEY,
    Email           VARCHAR(255)  NOT NULL CONSTRAINT UQ_AuthIdentity_Email UNIQUE,
    Provider        VARCHAR(20)   NOT NULL,
    ExternalSubject VARCHAR(255)  NOT NULL,
    CreatedAt       DATETIME      NOT NULL CONSTRAINT DF_AuthIdentity_CreatedAt DEFAULT (GETUTCDATE())
);
