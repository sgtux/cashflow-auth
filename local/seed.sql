-- Seed SO para desenvolvimento local isolado do cashflow-auth (docker-compose deste projeto).
-- Em producao NAO se roda isto: o cashflow-auth aponta para o banco real do Cashflow .NET, que
-- ja tem a tabela [User] e os cadastros. Aqui recriamos o minimo necessario para logar.
--
-- Usuario de teste:  teste@cashflow.local  /  Cashflow@123
-- O hash abaixo foi gerado com o MESMO pre-processamento do EnhancedBCryptPasswordVerifier
-- (SHA-512 -> Base64 -> truncar 72 -> bcrypt custo 12). Ao validar contra o .NET de verdade,
-- substitua por um hash real de CryptographyUtils.PasswordHash(...).

IF DB_ID('cashflow') IS NULL
    CREATE DATABASE cashflow;
GO

USE cashflow;
GO

IF OBJECT_ID('dbo.[User]', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.[User] (
        Id              INT           IDENTITY(1,1) NOT NULL CONSTRAINT PK_User PRIMARY KEY,
        Email           VARCHAR(255)  NOT NULL,
        Password        VARCHAR(255)  NULL,
        CreatedAt       DATETIME      NOT NULL CONSTRAINT DF_User_CreatedAt DEFAULT (GETUTCDATE())
    );
END
GO

IF NOT EXISTS (SELECT 1 FROM dbo.[User] WHERE Email = 'teste@cashflow.local')
BEGIN
    INSERT INTO dbo.[User] (Email, Password)
    VALUES ('teste@cashflow.local', '$2a$12$nVVPU5Jr/zRH0tzM3Z2xyeBR5Ub2hTuqM79W6.sg6rhg.Bqk1GduG');
END
GO
