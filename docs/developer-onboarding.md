# Guia de Integração para Desenvolvedores

## Secure 3D Print Taverna - Instruções Técnicas

Este documento fornece orientações detalhadas para desenvolvedores que estão integrando-se ao projeto Secure 3D Print Taverna, com foco em configuração do ambiente, padrões de código e requisitos de segurança não-negociáveis.

## 1. Configuração do Ambiente de Desenvolvimento

### 1.1 Requisitos Preliminares

- PHP 8.2+
- Composer 2.x
- Docker & Docker Compose
- Git

### 1.2 Inicialização do Ambiente

```bash
# Clone o repositório
git clone https://github.com/Lucasdoreac/secure-3d-print-taverna.git
cd secure-3d-print-taverna

# Instale as dependências
composer install

# Configure variáveis de ambiente
cp .env.example .env
# Edite as variáveis conforme necessário

# Inicie o ambiente containerizado
docker-compose up -d

# Verifique a instalação
./scripts/validate-env.sh
```

### 1.3 Validação da Configuração

Após inicializar o ambiente, execute as verificações de segurança:

```bash
# Validação estática de código
composer run-script phpstan

# Verificação de conformidade com padrões
composer run-script phpcs

# Execução de testes de segurança
composer run-script test
```

## 2. Arquitetura do Projeto

### 2.1 Estrutura de Diretórios

```
app/
  controllers/            # Controladores com validação integrada
  models/                 # Modelos com abstração para persistência segura
  views/                  # Templates com sanitização de saída
  lib/
    Security/             # Componentes de segurança transversais
    Validation/           # Framework de validação de entrada
    Database/             # Abstração segura para acesso a dados
    Logging/              # Sistema de logging com segurança
config/                   # Configurações segregadas por ambiente
public/                   # Único ponto de entrada da aplicação
tests/                    # Testes automatizados incluindo pentests
docs/                     # Documentação técnica e de segurança
```

### 2.2 Fluxo de Requisição

1. Todas as requisições são roteadas através de `public/index.php`
2. Headers de segurança são aplicados imediatamente via `SecurityHeaders`
3. Dados de entrada são validados rigorosamente usando `InputValidationTrait`
4. Autenticação e autorização são verificadas antes de qualquer operação
5. Operações são processadas com isolamento de contexto
6. Saída é sanitizada antes da renderização para prevenir XSS

## 3. Componentes Implementados

### 3.1 Segurança Transversal

| Componente | Descrição | Uso Obrigatório |
|------------|-----------|-----------------|
| `SecurityManager` | Interface unificada para funcionalidades de segurança | Sim |
| `CsrfProtection` | Tokens criptograficamente seguros com expiração | Sim para todas operações não-idempotentes |
| `SecurityHeaders` | Headers HTTP defensivos contra XSS e clickjacking | Sim |
| `InputValidator` | Validação tipada rígida com regras extensíveis | Sim |
| `InputValidationTrait` | Integração simplificada de validação em controllers | Sim |
| `Logger` | Sistema de logging com mascaramento de dados sensíveis | Sim |

### 3.2 Persistência e Modelos

| Componente | Descrição | Uso Obrigatório |
|------------|-----------|-----------------|
| `DatabaseConnection` | Abstração de acesso a dados com Prepared Statements | Sim |
| `DatabaseException` | Exceções com sanitização de informações sensíveis | Sim |
| `User` | Modelo de usuário com autenticação segura Argon2id | Sim |
| `BaseController` | Controller base com guardrails de segurança integrados | Sim |

## 4. Desenvolvimento de Novos Recursos

### 4.1 Princípios Fundamentais

- **Security by Design**: A segurança é um requisito funcional, não um add-on
- **Defense in Depth**: Múltiplas camadas de proteção para cada vetor de ataque
- **Princípio do Privilégio Mínimo**: Acesso concedido apenas ao necessário
- **Validação Estrita**: Todas as entradas passam por validação rigorosa de tipo e formato
- **Sanitização Sistemática**: Toda saída é sanitizada para evitar XSS e injeções
- **Auditabilidade**: Operações críticas geram logs detalhados e auditáveis

### 4.2 Exemplo de Implementação Segura de Controller

```php
<?php

namespace App\Controllers;

use App\Lib\Security\InputValidator;
use App\Models\PrintModel;

class ModelController extends BaseController
{
    /**
     * Cria um novo modelo 3D
     */
    public function createModel(): void
    {
        // 1. Verificar CSRF token (obrigatório)
        $this->verifyCsrfToken();
        
        // 2. Verificar método HTTP
        $this->requireHttpMethod('POST');
        
        // 3. Validar autenticação
        $user = $this->requireAuthentication();
        
        // 4. Validar entradas com tipo explícito
        $name = $this->postValidatedParam('name', InputValidator::TYPE_STRING, [
            'required' => true,
            'minLength' => 3,
            'maxLength' => 100
        ]);
        
        $description = $this->postValidatedParam('description', InputValidator::TYPE_STRING, [
            'required' => false,
            'maxLength' => 1000
        ]);
        
        // 5. Verificar erros de validação
        if ($this->hasValidationErrors()) {
            $this->renderError('Dados inválidos', 400);
            return;
        }
        
        // 6. Processar upload do arquivo com validações de segurança
        try {
            $modelUploader = new ModelUploader();
            $uploadResult = $modelUploader->processUpload($_FILES['model_file'] ?? null);
            
            if (!$uploadResult->isSuccess()) {
                $this->renderError($uploadResult->getErrorMessage(), 400);
                return;
            }
            
            // 7. Persistir com prepared statements via repositório
            $model = new PrintModel();
            $model->setName($name);
            $model->setDescription($description);
            $model->setFilePath($uploadResult->getFilePath());
            $model->setUserId($user->getId());
            
            $modelId = $model->save();
            
            // 8. Auditar operação crítica
            $this->logger->info('Model created', [
                'user_id' => $user->getId(),
                'model_id' => $modelId
            ]);
            
            // 9. Renderizar resposta com sanitização
            $this->renderJson([
                'success' => true,
                'model_id' => $modelId
            ]);
        } catch (\Exception $e) {
            // 10. Log detalhado interno, mensagem genérica externamente
            $this->logger->error('Failed to create model', [
                'exception' => $e->getMessage(),
                'user_id' => $user->getId()
            ]);
            
            $this->renderError('Erro ao processar o modelo', 500);
        }
    }
}
```

### 4.3 Próximos Recursos a Implementar

Prioridade para implementação imediata:

1. **Validação de Modelos 3D**
   - Implementar validadores para STL, OBJ e outros formatos
   - Criar sistema de quarentena para uploads
   - Desenvolver análise de printabilidade e custo

2. **Gestão de Pedidos**
   - Implementar fluxo seguro de orçamento e aprovação
   - Criar sistema de status com auditoria
   - Desenvolver integração com sistema de pagamento

Consulte o arquivo `docs/development-roadmap.md` para detalhes completos.

## 5. Fluxo de Trabalho Git e Revisão de Código

### 5.1 Branches e Commits

- `main`: Código estável, pronto para produção
- `develop`: Branch de integração para próxima release
- `feature/xxx`: Features em desenvolvimento
- `fix/xxx`: Correções de bugs
- `security/xxx`: Patches de segurança (privados)

### 5.2 Processo de Pull Request

1. Criar branch a partir de `develop`
2. Implementar código seguindo os guardrails
3. Escrever testes unitários e de integração
4. Executar verificações de segurança localmente
5. Criar PR com descrição detalhada
6. Aguardar CI/CD e revisão de código
7. Abordar feedbacks e problemas identificados
8. Merge após aprovação

### 5.3 Critérios para Aprovação

- Todos os testes passando
- Cobertura de teste adequada
- PHPStan nível 5 sem erros
- Conformidade PSR-12
- Implementação dos guardrails de segurança
- Documentação atualizada

## 6. Verificações de Segurança

### 6.1 Verificações Automatizadas

```bash
# Análise estática com PHPStan
composer run-script phpstan

# Verificação de estilo
composer run-script phpcs

# Verificação de vulnerabilidades em dependências
composer audit

# Execução de testes de segurança
vendor/bin/phpunit tests/Security
```

### 6.2 Verificações Manuais

- Revisão de segurança para cada PR
- Sessões de pair programming para código crítico
- Revisão periódica de modelos de ameaças
- Verificação manual de proteções CSRF
- Scan de SQLi e XSS em novas funcionalidades

## 7. Resolução de Problemas

### 7.1 Erros Comuns

| Erro | Solução |
|------|---------|
| Falhas de CI/CD | Verificar conformidade PSR-12, PHPStan e cobertura de testes |
| Erros de validação | Sempre usar `InputValidationTrait` para validação de entrada |
| Falhas em ataques XSS | Garantir sanitização de saída com `htmlspecialchars()` |
| SQL Injection | Utilizar exclusivamente `DatabaseConnection` para queries |

### 7.2 Recursos para Desenvolvimento

- Documentação de segurança em `docs/security/`
- Exemplos de implementação em `docs/examples/`
- Logs detalhados em `logs/app.log` (desenvolvimento)
- Análise de segurança em `logs/security/`

---

> **Nota de Segurança**: A proteção contra vulnerabilidades é responsabilidade de todos os desenvolvedores. Se você identificar um problema de segurança, reporte imediatamente ao líder técnico e não compartilhe publicamente até que o patch seja aplicado.

Para mais informações, consulte os documentos detalhados em `docs/` e o roadmap técnico em `docs/development-roadmap.md`.
