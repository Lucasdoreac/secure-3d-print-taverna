# Políticas de Segurança

## Reportando Vulnerabilidades

Se você descobrir uma vulnerabilidade de segurança no projeto Secure 3D Print Taverna, agradecemos que nos informe de maneira responsável:

1. **Não divulgue publicamente** a vulnerabilidade até que ela tenha sido corrigida
2. Envie um relatório detalhado para `security@example.com` incluindo:
   - Descrição da vulnerabilidade
   - Passos para reproduzir
   - Possível impacto
   - Sugestões para mitigação (se houver)

## Guardrails de Segurança Implementados

Este projeto foi desenvolvido com os seguintes guardrails de segurança:

1. **Validação de Entrada**
   - Toda entrada de usuário é validada via `InputValidationTrait`
   - Validação de tipo, tamanho e formato
   - Proteção contra injeção de dados maliciosos

2. **Proteção CSRF**
   - Tokens criptograficamente seguros em todos formulários
   - Validação one-time-use para tokens
   - Expiração de tokens não utilizados

3. **Prevenção de SQL Injection**
   - Uso obrigatório de prepared statements
   - Parâmetros tipados nas consultas
   - ORM com escape automático

4. **Prevenção de XSS**
   - Sanitização de saída com `htmlspecialchars()`
   - Content Security Policy rigorosa
   - Validação de conteúdo renderizado

5. **Gestão de Sessões**
   - Cookies com flags secure e httpOnly
   - Regeneração de ID de sessão após login
   - Timeout para sessões inativas

6. **Headers HTTP de Segurança**
   - X-Content-Type-Options: nosniff
   - X-Frame-Options: DENY
   - Content-Security-Policy configurada
   - Strict-Transport-Security implementado

## Ciclo de Atualizações de Segurança

Atualizações de segurança são lançadas:

- Imediatamente para vulnerabilidades críticas
- Dentro de 7 dias para vulnerabilidades de severidade alta
- No próximo ciclo de release para vulnerabilidades moderadas ou baixas

## Ferramentas de Verificação Automática

Este projeto utiliza as seguintes ferramentas de análise estática:

- PHPStan (nível 5)
- PHP Code Sniffer (PSR-12)
- PHP Mess Detector
- Symfony Security Checker

As verificações são executadas em cada pull request e semanalmente no repositório.