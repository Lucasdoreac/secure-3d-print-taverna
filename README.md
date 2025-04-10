# Secure 3D Print Taverna

Plataforma de e-commerce para serviços de impressão 3D com arquitetura segura, resiliência a falhas e isolamento de componentes.

## Guardrails de Segurança

Este projeto implementa os seguintes guardrails de segurança:

1. Validação rigorosa de todas as entradas via InputValidationTrait
2. Proteção CSRF em todos os formulários POST
3. Prepared statements para todas consultas SQL
4. Sanitização de saída para prevenção de XSS
5. Verificação de permissões para operações sensíveis
6. Headers HTTP de segurança em todas as respostas
7. Armazenamento seguro de senhas com hash e salt
8. Proteção contra path traversal em uploads
9. Mensagens de erro genéricas para usuários
10. Logging detalhado para depuração interna
11. **Circuit Breaker** para isolamento de falhas em subsistemas
12. **Validação profunda de modelos 3D** com detecção de anomalias
13. **Sandboxing por usuário** com isolamento de recursos
14. **Auto-recuperação** em processos críticos

## Arquitetura Resiliente

### Circuit Breaker Pattern

O padrão Circuit Breaker foi implementado para isolar falhas e permitir degradação gradual do sistema:

- Previne falhas em cascata quando subsistemas falham
- Permite auto-recuperação após períodos de timeout
- Implementa métricas de degradação e monitoramento

### Validação de Modelos 3D

Validação em múltiplas camadas para garantir segurança:

- Verificação de extensão e MIME type
- Validação de assinatura de arquivo (magic bytes)
- Análise de estrutura interna específica por formato (STL, OBJ, 3MF, AMF)
- Detecção de anomalias estruturais e conteúdo malicioso
- Cálculo de entropia para identificar conteúdo suspeito

### Upload Seguro

Sistema de upload com isolamento e recuperação:

- Quotas dinâmicas por tipo de usuário
- Diretórios segregados com sharding
- Verificação assíncrona com circuit breaker
- Mecanismo de backup e fallback automático
- Verificação de integridade pós-upload

### CI/CD com Auto-recuperação

Pipeline de integração contínua com diagnóstico e recuperação:

- Monitoramento detalhado de falhas de teste
- Captura de ambiente e estado do sistema
- Mecanismos de auto-correção para problemas comuns
- Degradação gradual para manter funcionalidades essenciais
- Relatórios detalhados para análise pós-falha

## Instalação

```bash
git clone https://github.com/Lucasdoreac/secure-3d-print-taverna.git
cd secure-3d-print-taverna
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate
```

## Executando Testes

### Testes com Monitoramento

Execute testes com captura de diagnóstico detalhado:

```bash
./scripts/run-tests-with-monitoring.sh
```

Este script detecta falhas, captura detalhes do ambiente e gera relatórios para análise.

### Testes Unitários Específicos

```bash
vendor/bin/phpunit tests/Unit/Models/ModelValidatorTest.php
vendor/bin/phpunit tests/Unit/Upload/SecureFileUploaderTest.php
```

## Arquitetura de Componentes

### Circuit Breaker
```php
use App\Lib\Resilience\CircuitBreaker;

$circuitBreaker = new CircuitBreaker('service-name', 3, 30);

// Execução protegida com fallback
$result = $circuitBreaker->execute(
    function() {
        // Operação principal
        return serviceCall();
    },
    function(\Exception $e) {
        // Fallback em caso de falha
        return backupOperation();
    }
);
```

### Validação de Modelos 3D
```php
use App\Lib\Models\ModelValidator;

$validator = new ModelValidator();
$result = $validator->validateStructure($filePath);

if ($result->isValid()) {
    // Modelo seguro
} else {
    // Lidar com erros
    $errors = $result->getErrors();
}

// Análise profunda
$deepResult = $validator->performDeepStructuralAnalysis($filePath);
```

### Upload Seguro
```php
use App\Lib\Upload\SecureFileUploader;

$uploader = new SecureFileUploader('/path/to/storage');
$result = $uploader->processUpload($_FILES['model'], $userId, 'regular');

if ($result->isSuccess()) {
    $metadata = $result->getMetadata();
    $filePath = $metadata['stored_path'];
    $fileHash = $metadata['file_hash'];
} else {
    $errorMessage = $result->getErrorMessage();
}
```

## Contribuição

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para orientações detalhadas.

## Segurança

Para relatar vulnerabilidades de segurança, veja [SECURITY.md](SECURITY.md).
