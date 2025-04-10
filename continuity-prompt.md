# Prompt de Continuidade: Secure 3D Print Taverna

## Status Atual do Projeto

O projeto Secure 3D Print Taverna implementou com sucesso sua infraestrutura de segurança base. Os seguintes componentes críticos de segurança foram completados:

1. **SecurityManager**: Interface unificada para todas funcionalidades de segurança
2. **CsrfProtection**: Implementação robusta de proteção contra CSRF com tokens criptograficamente seguros
3. **InputValidationTrait**: Framework para validação de entrada em controllers
4. **SecurityHeaders**: Gerenciamento de headers HTTP de segurança configuráveis
5. **InputValidator**: Validador extensível com suporte a múltiplos tipos de dados e regras de validação

A arquitetura base está estabelecida com configurações Docker para desenvolvimento e GitHub Actions para CI/CD com verificações de segurança automatizadas.

## Próximos Passos Prioritários

### 1. Implementação do Sistema de Autenticação Segura

Desenvolver um sistema de autenticação segura com as seguintes características:

- Armazenamento de senhas usando Argon2id conforme configurado em `security.php`
- Proteção contra ataques de força bruta (já configurado na política de segurança)
- Gerenciamento seguro de sessão com regeneração de IDs após login
- Verificação em dois fatores (opcional)
- Implementação de tokens JWT para API (opcional)

Código recomendado:
```php
namespace App\Models;

use App\Lib\Security\SecurityManager;

class User {
    // Implementar métodos seguros de autenticação
    public static function authenticate(string $username, string $password): ?self {
        // Implementar lógica segura de autenticação
    }
    
    // Método para hash de senha usando Argon2id
    public static function hashPassword(string $password): string {
        // Hash da senha com Argon2id conforme configurações de segurança
    }
}
```

### 2. Camada de Abstração para Banco de Dados

Desenvolver uma camada de abstração para acesso a dados que implemente consistentemente:

- Uso obrigatório de Prepared Statements para todas as consultas
- Validação de dados antes de consultas
- Escaping automático de parâmetros
- Tratamento de erros com mensagens genéricas para o usuário

Código recomendado:
```php
namespace App\Lib\Database;

class DatabaseQuery {
    // Implementar métodos seguros para execução de consultas
    public function execute(string $query, array $params = []): array {
        // Implementar lógica com Prepared Statements
    }
}
```

### 3. Controladores Base com Validação Integrada

Criar controladores base que utilizem automaticamente os componentes de segurança:

- Integração automática da validação de entrada
- Verificação de CSRF em todas as rotas POST
- Aplicação de headers de segurança em todas as respostas
- Verificação de permissões para operações críticas

## Estrutura de Arquivos Sugerida

```
app/
  controllers/
    BaseController.php          # Controller base com segurança integrada
    UserController.php          # Controller para autenticação e gestão de usuários
    OrderController.php         # Controller para gestão de pedidos
  models/
    User.php                    # Modelo para autenticação e dados de usuário
    Order.php                   # Modelo para pedidos de impressão 3D
    PrintJob.php                # Modelo para trabalhos de impressão 3D
  lib/
    Database/
      DatabaseConnection.php    # Singleton para conexão com banco
      DatabaseQuery.php         # Classe para queries seguras
      QueryBuilder.php          # Builder para consultas seguras
```

## Guardrails de Segurança a Manter

Durante o desenvolvimento, mantenha os seguintes guardrails de segurança:

1. SEMPRE usar `InputValidationTrait` para validar entradas de usuário
2. SEMPRE usar proteção CSRF para todas as rotas POST/PUT/DELETE
3. NUNCA concatenar strings em consultas SQL - SEMPRE usar Prepared Statements
4. SEMPRE sanitizar saída com `htmlspecialchars()`
5. SEMPRE aplicar o princípio do menor privilégio nas verificações de permissões
6. NUNCA armazenar senhas em texto plano ou usar algoritmos obsoletos (MD5, SHA1)
7. SEMPRE configurar headers de segurança HTTP para todas as respostas
8. NUNCA expor mensagens detalhadas de erro para o usuário final

## Considerações de Arquitetura

- Mantenha a separação clara entre camadas (MVC)
- Implemente princípios SOLID para facilitar testes e manutenção
- Documente detalhadamente todos os controles de segurança implementados
- Implemente validação específica para arquivos 3D antes de processamento
- Aplique throttling em APIs e endpoints críticos para prevenir DDoS