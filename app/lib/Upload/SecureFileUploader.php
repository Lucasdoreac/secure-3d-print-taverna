<?php
namespace App\Lib\Upload;

use App\Lib\Security\InputValidationTrait;
use App\Lib\Models\ModelValidator;
use App\Lib\Models\ValidationResult;
use App\Lib\Resilience\CircuitBreaker;
use App\Lib\Logging\Logger;

/**
 * Gerenciador seguro de upload de arquivos com isolamento de falhas
 * 
 * Implementa múltiplas camadas de validação e verificação de
 * segurança para arquivos de modelos 3D com sandboxing por
 * usuário, verificação assíncrona e circuit breaker para
 * isolamento de falhas em componentes externos.
 */
class SecureFileUploader 
{
    use InputValidationTrait;
    
    // Tipos MIME permitidos
    private array $allowedMimeTypes = [
        'model/stl', 
        'model/obj', 
        'model/x.stl-binary',
        'model/x.stl-ascii',
        'model/3mf',
        'model/amf'
    ];
    
    // Formatos alternativos de MIME que servidores podem gerar
    private array $allowedAlternativeMimeTypes = [
        'application/sla',
        'application/octet-stream',
        'text/plain',
        'application/x-stl',
        'application/vnd.ms-3mfdocument',
        'application/vnd.ms-package.3dmanufacturing-3dmodel+xml'
    ];
    
    // Extensões permitidas (fallback quando MIME falha)
    private array $allowedExtensions = ['stl', 'obj', '3mf', 'amf'];
    
    // Tamanho máximo padrão (50MB)
    private int $maxFileSize = 52428800;
    
    // Quotas dinâmicas por tipo de usuário (em bytes)
    private array $userQuotas = [
        'regular' => 104857600,     // 100MB
        'premium' => 1073741824,    // 1GB
        'business' => 5368709120    // 5GB
    ];
    
    // Circuit breakers para isolamento de falhas em subsistemas
    private CircuitBreaker $threatScanCircuit;
    private CircuitBreaker $storageCircuit;
    
    // Validator para modelos 3D
    private ModelValidator $modelValidator;
    
    // Diretório base para armazenamento
    private string $baseStoragePath;
    
    /**
     * Inicializa o gerenciador de upload seguro
     * 
     * @param string $baseStoragePath Caminho base para armazenamento
     * @param array $config Configurações avançadas (opcional)
     */
    public function __construct(string $baseStoragePath, array $config = []) 
    {
        $this->baseStoragePath = rtrim($baseStoragePath, '/');
        
        // Permitir configuração via injeção
        if (isset($config['max_file_size']) && is_int($config['max_file_size'])) {
            $this->maxFileSize = $config['max_file_size'];
        }
        
        if (isset($config['allowed_mime_types']) && is_array($config['allowed_mime_types'])) {
            $this->allowedMimeTypes = array_merge($this->allowedMimeTypes, $config['allowed_mime_types']);
        }
        
        if (isset($config['allowed_extensions']) && is_array($config['allowed_extensions'])) {
            $this->allowedExtensions = array_merge($this->allowedExtensions, $config['allowed_extensions']);
        }
        
        if (isset($config['user_quotas']) && is_array($config['user_quotas'])) {
            $this->userQuotas = array_merge($this->userQuotas, $config['user_quotas']);
        }
        
        // Inicializar validator de modelos 3D
        $this->modelValidator = new ModelValidator();
        
        // Inicializa circuit breaker para o scanner de ameaças
        $this->threatScanCircuit = new CircuitBreaker(
            'threat-scanner',
            3,      // Três falhas consecutivas abrem o circuito
            300     // Tenta recuperar após 5 minutos
        );
        
        // Inicializa circuit breaker para operações de armazenamento
        $this->storageCircuit = new CircuitBreaker(
            'storage-system',
            5,      // Cinco falhas consecutivas abrem o circuito
            120     // Tenta recuperar após 2 minutos
        );
    }
    
    /**
     * Processa upload de arquivo seguro com validações
     * 
     * @param array $fileData Dados do arquivo de $_FILES
     * @param int $userId ID do usuário
     * @param string $userType Tipo de usuário (regular, premium, business)
     * @return UploadResult Resultado do upload
     */
    public function processUpload(array $fileData, int $userId, string $userType = 'regular'): UploadResult 
    {
        try {
            // Passo 1: Validar estrutura de dados de upload
            if (!$this->isValidUploadData($fileData)) {
                return new UploadResult(false, null, 'Dados de upload inválidos ou incompletos');
            }
            
            // Passo 2: Verificar tamanhos, quotas e limites
            $sizeResult = $this->validateFileSize($fileData, $userId, $userType);
            if (!$sizeResult->isValid()) {
                return new UploadResult(
                    false, 
                    null, 
                    'Validação de tamanho falhou: ' . implode(', ', $sizeResult->getErrors())
                );
            }
            
            // Passo 3: Verificar tipo/extensão de arquivo
            $typeResult = $this->validateFileType($fileData);
            if (!$typeResult->isValid()) {
                return new UploadResult(
                    false, 
                    null, 
                    'Validação de tipo falhou: ' . implode(', ', $typeResult->getErrors())
                );
            }
            
            // Passo 4: Mover para diretório temporário seguro
            $tempResult = $this->moveToSecureTempLocation($fileData);
            if (!$tempResult->isValid()) {
                return new UploadResult(
                    false, 
                    null, 
                    'Falha ao mover arquivo: ' . implode(', ', $tempResult->getErrors())
                );
            }
            
            $tempFilePath = $tempResult->getFilePath();
            
            // Passo 5: Validar estrutura do modelo 3D
            $modelResult = $this->modelValidator->validateStructure($tempFilePath);
            if (!$modelResult->isValid()) {
                // Remover arquivo temporário falho
                @unlink($tempFilePath);
                return new UploadResult(
                    false, 
                    null, 
                    'Validação de modelo falhou: ' . implode(', ', $modelResult->getErrors())
                );
            }
            
            // Passo 6: Escanear por ameaças
            $scanResult = $this->scanForThreats($tempFilePath);
            if (!$scanResult->isSecure()) {
                // Remover arquivo temporário inseguro
                @unlink($tempFilePath);
                return new UploadResult(
                    false, 
                    null, 
                    'Verificação de segurança falhou: ' . $scanResult->getMessage()
                );
            }
            
            // Passo 7: Armazenar arquivo permanentemente com backup e verificação
            $storageResult = $this->storeSecurely($tempFilePath, $userId, $fileData['name']);
            
            // Remover arquivo temporário após armazenamento definitivo
            @unlink($tempFilePath);
            
            if (!$storageResult->isSuccess()) {
                return new UploadResult(
                    false, 
                    null, 
                    'Falha no armazenamento: ' . $storageResult->getErrorMessage()
                );
            }
            
            // Preparar resultado de sucesso com metadados
            $metaData = [
                'original_name' => $fileData['name'],
                'file_size' => $fileData['size'],
                'file_type' => $fileData['type'],
                'stored_path' => $storageResult->getFilePath(),
                'file_hash' => $storageResult->getFileHash(),
                'upload_time' => time(),
                'warnings' => array_merge($modelResult->getWarnings(), $scanResult->getWarnings())
            ];
            
            Logger::info('Upload de arquivo concluído com sucesso', [
                'user_id' => $userId,
                'file_hash' => $storageResult->getFileHash(),
                'original_name' => $fileData['name']
            ]);
            
            return new UploadResult(true, $metaData);
        } catch (\Exception $e) {
            Logger::error('Erro não tratado durante upload', [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
                'user_id' => $userId
            ]);
            
            // Remover arquivos temporários em caso de erro
            if (isset($tempFilePath) && file_exists($tempFilePath)) {
                @unlink($tempFilePath);
            }
            
            return new UploadResult(false, null, 'Erro interno no processamento: ' . $e->getMessage());
        }
    }
    
    /**
     * Valida dados básicos do upload
     * 
     * @param array $fileData Dados do arquivo
     * @return bool True se o upload é válido
     */
    private function isValidUploadData(array $fileData): bool 
    {
        // Verificações básicas de estrutura de dados
        if (!isset($fileData['tmp_name']) || !isset($fileData['size']) || 
            !isset($fileData['name']) || !isset($fileData['error'])) {
            Logger::warning('Dados de upload incompletos', ['data' => array_keys($fileData)]);
            return false;
        }
        
        // Verificar se upload foi bem-sucedido pelo PHP
        if ($fileData['error'] !== UPLOAD_ERR_OK) {
            $errorMessage = $this->getUploadErrorMessage($fileData['error']);
            Logger::warning('Erro de upload do PHP', [
                'error_code' => $fileData['error'],
                'error_message' => $errorMessage
            ]);
            return false;
        }
        
        // Verificar se arquivo temporário existe
        if (!file_exists($fileData['tmp_name']) || !is_uploaded_file($fileData['tmp_name'])) {
            Logger::warning('Arquivo temporário de upload não encontrado ou inválido', [
                'tmp_name' => $fileData['tmp_name']
            ]);
            return false;
        }
        
        return true;
    }
    
    /**
     * Obtém mensagem descritiva para códigos de erro do PHP
     * 
     * @param int $errorCode Código de erro do PHP
     * @return string Mensagem descritiva
     */
    private function getUploadErrorMessage(int $errorCode): string 
    {
        switch ($errorCode) {
            case UPLOAD_ERR_INI_SIZE:
                return 'O arquivo excede o tamanho máximo definido no php.ini (upload_max_filesize)';
            case UPLOAD_ERR_FORM_SIZE:
                return 'O arquivo excede o tamanho máximo definido no formulário HTML (MAX_FILE_SIZE)';
            case UPLOAD_ERR_PARTIAL:
                return 'O arquivo foi apenas parcialmente carregado';
            case UPLOAD_ERR_NO_FILE:
                return 'Nenhum arquivo foi enviado';
            case UPLOAD_ERR_NO_TMP_DIR:
                return 'Diretório temporário ausente no servidor';
            case UPLOAD_ERR_CANT_WRITE:
                return 'Falha ao escrever arquivo no disco';
            case UPLOAD_ERR_EXTENSION:
                return 'Uma extensão PHP interrompeu o upload';
            default:
                return 'Erro desconhecido no upload';
        }
    }
    
    /**
     * Valida tamanho do arquivo e quota do usuário
     * 
     * @param array $fileData Dados do arquivo
     * @param int $userId ID do usuário
     * @param string $userType Tipo de usuário
     * @return ValidationResult Resultado da validação
     */
    private function validateFileSize(array $fileData, int $userId, string $userType): ValidationResult 
    {
        // Verificar tamanho máximo permitido por arquivo
        if ($fileData['size'] <= 0) {
            return new ValidationResult(false, ['Arquivo vazio']);
        }
        
        if ($fileData['size'] > $this->maxFileSize) {
            return new ValidationResult(false, [
                'Arquivo excede o tamanho máximo permitido de ' . 
                $this->formatBytes($this->maxFileSize)
            ]);
        }
        
        // Verificar quota do usuário se estivermos em um ambiente real
        $quotaLimit = $this->userQuotas[$userType] ?? $this->userQuotas['regular'];
        
        // Obter uso atual de quota (implementação simplificada)
        $currentUsage = $this->getCurrentStorageUsage($userId);
        
        // Verificar se há espaço disponível
        if (($currentUsage + $fileData['size']) > $quotaLimit) {
            return new ValidationResult(false, [
                'Quota de armazenamento excedida. Disponível: ' . 
                $this->formatBytes($quotaLimit - $currentUsage) . 
                ', Necessário: ' . $this->formatBytes($fileData['size'])
            ]);
        }
        
        return new ValidationResult(true);
    }
    
    /**
     * Valida tipo de arquivo, verificando MIME e extensão
     * 
     * @param array $fileData Dados do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateFileType(array $fileData): ValidationResult 
    {
        // Obter extensão do arquivo
        $extension = strtolower(pathinfo($fileData['name'], PATHINFO_EXTENSION));
        
        // Verificar extensão
        if (!in_array($extension, $this->allowedExtensions)) {
            return new ValidationResult(false, [
                'Extensão de arquivo não permitida. Extensões aceitas: ' . 
                implode(', ', $this->allowedExtensions)
            ]);
        }
        
        // Verificar tipo MIME com fallbacks
        $mimeType = $this->detectMimeType($fileData['tmp_name']);
        
        // Verificar se MIME está na lista de permitidos (incluindo alternativos)
        $isAllowedMime = in_array($mimeType, $this->allowedMimeTypes) || 
                         in_array($mimeType, $this->allowedAlternativeMimeTypes);
        
        if (!$isAllowedMime) {
            // Log detalhado mas não rejeitar apenas com base em MIME que pode ser impreciso
            Logger::warning('Tipo MIME potencialmente não permitido', [
                'detected_mime' => $mimeType,
                'extension' => $extension,
                'file_name' => $fileData['name']
            ]);
            
            // Realizar verificação mais rigorosa de assinatura de arquivo
            $signatureCheck = $this->validateFileSignature($fileData['tmp_name'], $extension);
            if (!$signatureCheck->isValid()) {
                return $signatureCheck;
            }
        }
        
        return new ValidationResult(true);
    }
    
    /**
     * Detecta o tipo MIME real de um arquivo usando múltiplos métodos
     * 
     * @param string $filePath Caminho do arquivo
     * @return string Tipo MIME detectado
     */
    private function detectMimeType(string $filePath): string 
    {
        // Método 1: Usando fileinfo (mais confiável)
        if (function_exists('finfo_open')) {
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime = finfo_file($finfo, $filePath);
            finfo_close($finfo);
            
            if ($mime && $mime !== 'application/octet-stream') {
                return $mime;
            }
        }
        
        // Método 2: Usando mime_content_type se disponível
        if (function_exists('mime_content_type')) {
            $mime = mime_content_type($filePath);
            if ($mime && $mime !== 'application/octet-stream') {
                return $mime;
            }
        }
        
        // Método 3: Verificação manual de assinatura de arquivo
        $handle = fopen($filePath, 'rb');
        if ($handle) {
            $header = fread($handle, 256);
            fclose($handle);
            
            // Detecção específica para modelos 3D
            $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            
            // STL ASCII começa com "solid"
            if (strpos($header, 'solid') === 0) {
                return 'model/x.stl-ascii';
            } 
            
            // OBJ geralmente começa com # ou v
            if ($extension === 'obj' && (strpos($header, '#') === 0 || strpos($header, 'v ') !== false)) {
                return 'model/obj';
            }
            
            // 3MF e AMF são XML
            if (($extension === '3mf' || $extension === 'amf') && strpos($header, '<?xml') !== false) {
                return $extension === '3mf' ? 'model/3mf' : 'model/amf';
            }
            
            // STL binário (por eliminação, com extensão correta)
            if ($extension === 'stl') {
                return 'model/x.stl-binary';
            }
        }
        
        // Fallback para octet-stream
        return 'application/octet-stream';
    }
    
    /**
     * Verifica assinatura de arquivo para determinar se é válido
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Extensão declarada
     * @return ValidationResult Resultado da validação
     */
    private function validateFileSignature(string $filePath, string $extension): ValidationResult 
    {
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return new ValidationResult(false, ['Falha ao abrir arquivo para verificação de assinatura']);
        }
        
        $header = fread($handle, 256);
        fclose($handle);
        
        if (empty($header)) {
            return new ValidationResult(false, ['Arquivo vazio']);
        }
        
        switch ($extension) {
            case 'stl':
                // STL ASCII deve começar com "solid"
                if (strpos($header, 'solid') === 0) {
                    // Verificar se parece um STL ASCII válido
                    if (strpos($header, 'facet') === false && strpos($header, 'vertex') === false) {
                        return new ValidationResult(false, ['Arquivo STL ASCII inválido']);
                    }
                    return new ValidationResult(true);
                }
                
                // STL binário: verificar se tem pelo menos 84 bytes (header + count)
                if (filesize($filePath) < 84) {
                    return new ValidationResult(false, ['Arquivo STL binário muito pequeno']);
                }
                return new ValidationResult(true);
                
            case 'obj':
                // OBJ geralmente começa com comentários "#" ou definições de vértices "v"
                if (preg_match('/^(\s*#|\s*v\s)/m', $header)) {
                    return new ValidationResult(true);
                }
                return new ValidationResult(false, ['Arquivo OBJ não possui formato válido']);
                
            case '3mf':
            case 'amf':
                // Baseados em XML, devem ter tag XML
                if (strpos($header, '<?xml') !== false) {
                    // Verificar elemento raiz esperado
                    $rootElement = $extension === 'amf' ? '<amf' : '<model';
                    if (strpos($header, $rootElement) !== false) {
                        return new ValidationResult(true);
                    }
                    return new ValidationResult(false, ["Arquivo {$extension} não contém elemento raiz esperado"]);
                }
                return new ValidationResult(false, ["Arquivo {$extension} não é um XML válido"]);
                
            default:
                return new ValidationResult(false, ['Extensão de arquivo não suportada']);
        }
    }
    
    /**
     * Move arquivo para diretório temporário seguro
     * 
     * @param array $fileData Dados do arquivo
     * @return TempFileResult Resultado com caminho temporário
     */
    private function moveToSecureTempLocation(array $fileData): TempFileResult 
    {
        try {
            // Criar diretório temporário seguro se não existir
            $tempDir = sys_get_temp_dir() . '/secure_3d_print_uploads';
            if (!is_dir($tempDir)) {
                if (!mkdir($tempDir, 0750, true)) {
                    return new TempFileResult(false, null, ['Falha ao criar diretório temporário seguro']);
                }
                
                // Definir permissões adequadas
                chmod($tempDir, 0750);
            }
            
            // Gerar nome de arquivo temporário único com extensão original
            $extension = pathinfo($fileData['name'], PATHINFO_EXTENSION);
            $tempFileName = uniqid('upload_', true) . '.' . $extension;
            $tempFilePath = $tempDir . '/' . $tempFileName;
            
            // Mover arquivo para localização temporária
            if (!move_uploaded_file($fileData['tmp_name'], $tempFilePath)) {
                return new TempFileResult(false, null, ['Falha ao mover arquivo para localização temporária']);
            }
            
            // Definir permissões adequadas (somente leitura)
            chmod($tempFilePath, 0440);
            
            Logger::info('Arquivo movido para localização temporária segura', [
                'original_name' => $fileData['name'],
                'temp_path' => $tempFilePath
            ]);
            
            return new TempFileResult(true, $tempFilePath);
        } catch (\Exception $e) {
            Logger::error('Erro ao mover arquivo para localização temporária', [
                'error' => $e->getMessage()
            ]);
            return new TempFileResult(false, null, ['Erro interno: ' . $e->getMessage()]);
        }
    }
    
    /**
     * Escaneia arquivo em busca de ameaças com circuit breaker
     * 
     * @param string $filePath Caminho do arquivo
     * @return ThreatScanResult Resultado da verificação
     */
    private function scanForThreats(string $filePath): ThreatScanResult 
    {
        $context = ['path' => $filePath];
        
        return $this->threatScanCircuit->execute(
            // Operação principal
            function() use ($filePath, $context) {
                Logger::info('Iniciando verificação de ameaças', $context);
                
                // Verificações específicas de segurança para modelos 3D
                // Exemplo: verificação profunda de estrutura
                $structureCheck = $this->modelValidator->performDeepStructuralAnalysis($filePath);
                
                // Verificação de malware dentro dos arquivos
                $malwareCheck = $this->scanForMaliciousContent($filePath);
                
                // Verificar resultado combinado
                if (!$structureCheck->isValid()) {
                    return new ThreatScanResult(
                        false, 
                        'Estrutura do modelo 3D contém anomalias de segurança: ' . 
                        implode(', ', $structureCheck->getErrors())
                    );
                }
                
                if (!$malwareCheck->isSecure()) {
                    return new ThreatScanResult(
                        false, 
                        'Conteúdo malicioso detectado: ' . $malwareCheck->getMessage()
                    );
                }
                
                // Adicionar avisos do scanner de estrutura
                $result = new ThreatScanResult(true, 'Arquivo seguro');
                foreach ($structureCheck->getWarnings() as $warning) {
                    $result->addWarning($warning);
                }
                
                return $result;
            },
            // Fallback em caso de falha do scanner
            function(\Exception $e, array $context) {
                Logger::warning('Fallback para escaneamento de ameaças', [
                    'error' => $e->getMessage(),
                    'context' => $context
                ]);
                
                // Em caso de falha do scanner completo, executamos verificações básicas
                $basicSafety = $this->performBasicSafetyCheck($context['path']);
                
                $result = new ThreatScanResult(
                    $basicSafety->isSecure(),
                    $basicSafety->isSecure() 
                        ? 'Verificação básica aprovada (modo de contingência)' 
                        : 'Verificação básica falhou: ' . $basicSafety->getMessage()
                );
                
                // Adicionar aviso sobre o modo de contingência
                $result->addWarning('Verificação de segurança em modo de contingência devido a falha no scanner primário');
                
                return $result;
            },
            $context
        );
    }
    
    /**
     * Verifica arquivo em busca de conteúdo malicioso
     * 
     * @param string $filePath Caminho do arquivo
     * @return ThreatScanResult Resultado da verificação
     */
    private function scanForMaliciousContent(string $filePath): ThreatScanResult 
    {
        try {
            // Obter tipo de arquivo
            $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            
            // Verificações específicas por tipo de arquivo
            switch ($extension) {
                case 'stl':
                    return $this->scanStlForThreats($filePath);
                    
                case 'obj':
                    return $this->scanObjForThreats($filePath);
                    
                case '3mf':
                case 'amf':
                    return $this->scanXmlModelForThreats($filePath, $extension);
                    
                default:
                    return new ThreatScanResult(false, 'Tipo de arquivo não suportado para verificação de ameaças');
            }
        } catch (\Exception $e) {
            Logger::error('Erro na verificação de conteúdo malicioso', [
                'error' => $e->getMessage(),
                'path' => $filePath
            ]);
            
            return new ThreatScanResult(false, 'Erro na verificação de conteúdo malicioso');
        }
    }
    
    /**
     * Verifica arquivo STL em busca de ameaças
     * 
     * @param string $filePath Caminho do arquivo
     * @return ThreatScanResult Resultado da verificação
     */
    private function scanStlForThreats(string $filePath): ThreatScanResult 
    {
        // Verificar se é ASCII ou binário
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return new ThreatScanResult(false, 'Falha ao abrir arquivo STL para verificação');
        }
        
        $header = fread($handle, 5);
        
        if (strtolower(trim($header)) === 'solid') {
            // STL ASCII - verificar injeção de script
            fseek($handle, 0);
            $content = fread($handle, min(filesize($filePath), 1024 * 1024)); // Ler máximo 1MB
            fclose($handle);
            
            // Verificar padrões suspeitos
            $suspiciousPatterns = [
                // Possíveis injeções JavaScript ou comandos
                '<script', 'eval(', 'system(', 'exec(',
                // Tags HTML que não deveriam estar em STL
                '<iframe', '<img', '<svg', '<embed',
                // Comandos shell
                'bash', '#!/', 'chmod', 'sudo',
                // Payloads comuns de exploits
                'base64_decode', 'passthru'
            ];
            
            foreach ($suspiciousPatterns as $pattern) {
                if (stripos($content, $pattern) !== false) {
                    Logger::warning('Padrão suspeito encontrado em STL ASCII', [
                        'pattern' => $pattern,
                        'path' => $filePath
                    ]);
                    return new ThreatScanResult(false, 'Conteúdo potencialmente malicioso encontrado: ' . $pattern);
                }
            }
        } else {
            // STL binário - verificar anomalias estruturais
            // Cálculo de entropia para detectar conteúdo oculto
            fseek($handle, 0);
            $sample = fread($handle, min(filesize($filePath), 50 * 1024)); // Amostra de 50KB
            fclose($handle);
            
            $entropy = $this->calculateEntropy($sample);
            
            // Entropia muito alta pode indicar conteúdo ofuscado/criptografado/compactado
            if ($entropy > 7.5) {
                Logger::warning('Entropia anormalmente alta em STL binário', [
                    'entropy' => $entropy,
                    'path' => $filePath
                ]);
                return new ThreatScanResult(false, 'Possível conteúdo oculto detectado (entropia anormal)');
            }
        }
        
        return new ThreatScanResult(true, 'Arquivo STL seguro');
    }
    
    /**
     * Verifica arquivo OBJ em busca de ameaças
     * 
     * @param string $filePath Caminho do arquivo
     * @return ThreatScanResult Resultado da verificação
     */
    private function scanObjForThreats(string $filePath): ThreatScanResult 
    {
        // OBJ é formato ASCII, verificar por injeções
        $handle = fopen($filePath, 'r');
        if (!$handle) {
            return new ThreatScanResult(false, 'Falha ao abrir arquivo OBJ para verificação');
        }
        
        // Verificar linhas suspeitas
        $lineCount = 0;
        $suspiciousLines = [];
        
        while (($line = fgets($handle)) !== false && $lineCount < 10000) {
            $lineCount++;
            $line = trim($line);
            
            // Ignorar comentários e linhas vazias
            if (empty($line) || $line[0] === '#') {
                continue;
            }
            
            // OBJ legítimo deve começar com identificadores específicos
            $validPrefixes = ['v ', 'vt ', 'vn ', 'f ', 'g ', 'o ', 'mtllib ', 'usemtl '];
            $isValidLine = false;
            
            foreach ($validPrefixes as $prefix) {
                if (strpos($line, $prefix) === 0) {
                    $isValidLine = true;
                    break;
                }
            }
            
            if (!$isValidLine) {
                // Verificar se é uma linha suspeita
                $suspiciousPatterns = ['<', '>', '(', ')', ';', '|', '$', '`', '='];
                foreach ($suspiciousPatterns as $char) {
                    if (strpos($line, $char) !== false) {
                        $suspiciousLines[] = [
                            'line_number' => $lineCount,
                            'content' => $line
                        ];
                        break;
                    }
                }
            }
            
            // Limitar verificação para evitar DoS
            if (count($suspiciousLines) >= 5) {
                break;
            }
        }
        
        fclose($handle);
        
        if (!empty($suspiciousLines)) {
            Logger::warning('Linhas suspeitas encontradas em arquivo OBJ', [
                'suspicious_lines' => $suspiciousLines,
                'path' => $filePath
            ]);
            
            return new ThreatScanResult(false, 'Conteúdo potencialmente malicioso encontrado no arquivo OBJ');
        }
        
        return new ThreatScanResult(true, 'Arquivo OBJ seguro');
    }
    
    /**
     * Verifica modelos XML (3MF, AMF) em busca de ameaças
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Tipo de arquivo (amf ou 3mf)
     * @return ThreatScanResult Resultado da verificação
     */
    private function scanXmlModelForThreats(string $filePath, string $extension): ThreatScanResult 
    {
        try {
            // Desativar processamento de entidades externas
            $previousValue = null;
            if (function_exists('libxml_disable_entity_loader')) {
                $previousValue = libxml_disable_entity_loader(true);
            }
            
            // Prevenir ataques XXE (XML eXternal Entity)
            libxml_use_internal_errors(true);
            
            $xml = new \DOMDocument();
            $xml->resolveExternals = false;
            $xml->substituteEntities = false;
            
            // Verificar se o arquivo é carregável
            $loaded = $xml->load($filePath);
            
            // Restaurar configuração libxml
            if (function_exists('libxml_disable_entity_loader') && $previousValue !== null) {
                libxml_disable_entity_loader($previousValue);
            }
            
            if (!$loaded) {
                $errors = libxml_get_errors();
                libxml_clear_errors();
                
                $errorMessages = [];
                foreach ($errors as $error) {
                    $errorMessages[] = $error->message;
                }
                
                return new ThreatScanResult(false, 'Falha ao carregar XML: ' . implode(', ', $errorMessages));
            }
            
            // Verificar elementos script ou outros conteúdos potencialmente maliciosos
            $suspiciousElements = [
                'script', 'iframe', 'object', 'embed', 'xsl:stylesheet', 'xsl:import',
                'xml-stylesheet', 'include', 'import'
            ];
            
            foreach ($suspiciousElements as $element) {
                $nodes = $xml->getElementsByTagName($element);
                if ($nodes->length > 0) {
                    return new ThreatScanResult(false, "Elemento suspeito encontrado: {$element}");
                }
            }
            
            // Verificar atributos com javascript:
            $xpath = new \DOMXPath($xml);
            $attributes = $xpath->query('//@*');
            
            foreach ($attributes as $attr) {
                $value = strtolower($attr->value);
                if (strpos($value, 'javascript:') !== false || 
                    strpos($value, 'data:') === 0 || 
                    strpos($value, 'vbscript:') !== false) {
                    return new ThreatScanResult(false, "Atributo suspeito encontrado: {$attr->name}={$attr->value}");
                }
            }
            
            // Verificar DTD (Document Type Definition) personalizada
            if ($xml->doctype) {
                return new ThreatScanResult(false, 'DTD personalizada não permitida (risco de XXE)');
            }
            
            return new ThreatScanResult(true, "Arquivo {$extension} seguro");
        } catch (\Exception $e) {
            Logger::error('Erro na verificação de modelo XML', [
                'error' => $e->getMessage(),
                'path' => $filePath
            ]);
            
            return new ThreatScanResult(false, 'Erro na verificação de segurança XML: ' . $e->getMessage());
        }
    }
    
    /**
     * Realiza verificação básica de segurança como fallback
     * 
     * @param string $filePath Caminho do arquivo
     * @return ThreatScanResult Resultado da verificação
     */
    private function performBasicSafetyCheck(string $filePath): ThreatScanResult 
    {
        try {
            // Verificações básicas de tamanho e extensão
            $fileSize = filesize($filePath);
            
            if ($fileSize > $this->maxFileSize) {
                return new ThreatScanResult(false, 'Arquivo excede tamanho máximo permitido');
            }
            
            $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            if (!in_array($extension, $this->allowedExtensions)) {
                return new ThreatScanResult(false, 'Extensão de arquivo não permitida');
            }
            
            // Verificação de assinatura de arquivo
            $signatureResult = $this->validateFileSignature($filePath, $extension);
            if (!$signatureResult->isValid()) {
                return new ThreatScanResult(false, 'Assinatura de arquivo inválida: ' . 
                                                  implode(', ', $signatureResult->getErrors()));
            }
            
            // Verificação básica de entropia para detectar conteúdo suspeito
            $handle = fopen($filePath, 'rb');
            if ($handle) {
                $sample = fread($handle, min($fileSize, 50 * 1024)); // Amostra de 50KB
                fclose($handle);
                
                $entropy = $this->calculateEntropy($sample);
                
                // Entropia extrema (muito alta ou muito baixa) pode indicar conteúdo malicioso
                if ($entropy > 7.8 || $entropy < 0.5) {
                    return new ThreatScanResult(false, 'Distribuição de dados suspeita (entropia anormal)');
                }
            }
            
            // Verificação de strings suspeitas em arquivos de texto
            if (in_array($extension, ['stl', 'obj', 'amf', '3mf'])) {
                if ($this->containsSuspiciousStrings($filePath)) {
                    return new ThreatScanResult(false, 'Padrões suspeitos detectados no conteúdo');
                }
            }
            
            $result = new ThreatScanResult(true, 'Verificação básica de segurança passou');
            $result->addWarning('Apenas verificações básicas foram aplicadas');
            
            return $result;
        } catch (\Exception $e) {
            Logger::error('Erro na verificação básica de segurança', [
                'error' => $e->getMessage(),
                'path' => $filePath
            ]);
            
            return new ThreatScanResult(false, 'Erro na verificação básica de segurança');
        }
    }
    
    /**
     * Verifica strings suspeitas em arquivos de texto
     * 
     * @param string $filePath Caminho do arquivo
     * @return bool True se contém padrões suspeitos
     */
    private function containsSuspiciousStrings(string $filePath): bool 
    {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $suspiciousPatterns = [
            '<script', 'eval(', 'setTimeout(', 'setInterval(',
            'function()', '#!/', 'system(', 'exec(', 'shell_exec(',
            'passthru(', 'proc_open(', 'popen(', '`', '|', '$(',
            'curl ', 'wget ', 'nc ', 'netcat ', 'ncat '
        ];
        
        // Para modelos XML, adicionar padrões específicos
        if ($extension === '3mf' || $extension === 'amf') {
            $suspiciousPatterns = array_merge($suspiciousPatterns, [
                '<!ENTITY', '<!DOCTYPE', 'SYSTEM', 'PUBLIC',
                'data:', 'javascript:', 'vbscript:',
                '<script>', '<iframe>', '<object>', '<embed>'
            ]);
        }
        
        $handle = fopen($filePath, 'r');
        if (!$handle) {
            return false;
        }
        
        $content = fread($handle, min(filesize($filePath), 1024 * 1024)); // Máximo 1MB
        fclose($handle);
        
        foreach ($suspiciousPatterns as $pattern) {
            if (stripos($content, $pattern) !== false) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Armazena arquivo com backup e verificação de integridade
     * 
     * @param string $tempPath Caminho temporário do arquivo
     * @param int $userId ID do usuário
     * @param string $originalName Nome original do arquivo
     * @return StorageResult Resultado do armazenamento
     */
    private function storeSecurely(string $tempPath, int $userId, string $originalName): StorageResult 
    {
        $context = [
            'temp_path' => $tempPath,
            'user_id' => $userId,
            'original_name' => $originalName
        ];
        
        return $this->storageCircuit->execute(
            // Operação principal
            function() use ($tempPath, $userId, $originalName, $context) {
                try {
                    // Gerar nome de arquivo seguro baseado em hash
                    $fileHash = hash_file('sha256', $tempPath);
                    $extension = pathinfo($originalName, PATHINFO_EXTENSION);
                    $safeName = $fileHash . '.' . $extension;
                    
                    // Diretório segregado por usuário para isolamento
                    $userDir = $this->getUserStoragePath($userId);
                    if (!is_dir($userDir)) {
                        if (!mkdir($userDir, 0750, true)) {
                            throw new \RuntimeException('Falha ao criar diretório de usuário');
                        }
                    }
                    
                    $destinationPath = $userDir . '/' . $safeName;
                    
                    // Evitar duplicação se o arquivo já existir
                    if (file_exists($destinationPath)) {
                        Logger::info('Arquivo já existe no armazenamento, evitando duplicação', [
                            'file_hash' => $fileHash,
                            'destination' => $destinationPath
                        ]);
                        
                        // Verificar integridade
                        $existingHash = hash_file('sha256', $destinationPath);
                        if ($existingHash === $fileHash) {
                            return new StorageResult(true, $destinationPath, $fileHash);
                        } else {
                            // Hash diferente mas mesmo nome indica corrupção
                            Logger::warning('Possível corrupção detectada, arquivo será substituído', [
                                'expected_hash' => $fileHash,
                                'actual_hash' => $existingHash
                            ]);
                        }
                    }
                    
                    // Criação de backup antes da movimentação
                    $backupPath = $userDir . '/backup_' . time() . '_' . $safeName;
                    if (!copy($tempPath, $backupPath)) {
                        throw new \RuntimeException('Falha ao criar backup do arquivo');
                    }
                    
                    // Mover arquivo com verificação atomicidade
                    if (!rename($tempPath, $destinationPath)) {
                        throw new \RuntimeException('Falha ao mover arquivo para destino final');
                    }
                    
                    // Definir permissões restritas
                    chmod($destinationPath, 0440);
                    
                    // Verificar integridade após upload
                    $newFileHash = hash_file('sha256', $destinationPath);
                    if ($newFileHash !== $fileHash) {
                        // Restaurar do backup em caso de corrupção
                        if (file_exists($backupPath)) {
                            copy($backupPath, $destinationPath);
                        }
                        throw new \RuntimeException('Falha na verificação de integridade após armazenamento');
                    }
                    
                    // Criar registro de metadados
                    $this->saveFileMetadata($userId, $fileHash, $originalName, $destinationPath);
                    
                    // Remover backup se tudo ocorreu bem
                    if (file_exists($backupPath)) {
                        unlink($backupPath);
                    }
                    
                    Logger::info('Arquivo armazenado com sucesso', [
                        'user_id' => $userId,
                        'file_hash' => $fileHash,
                        'destination' => $destinationPath
                    ]);
                    
                    return new StorageResult(true, $destinationPath, $fileHash);
                } catch (\Exception $e) {
                    Logger::error('Erro ao armazenar arquivo', [
                        'error' => $e->getMessage(),
                        'trace' => $e->getTraceAsString(),
                        'context' => $context
                    ]);
                    
                    return new StorageResult(false, '', '', $e->getMessage());
                }
            },
            // Fallback em caso de falha no sistema de armazenamento
            function(\Exception $e, array $context) {
                Logger::warning('Executando fallback para armazenamento de arquivo', [
                    'error' => $e->getMessage(),
                    'context' => $context
                ]);
                
                try {
                    // Diretório de contingência para casos de falha
                    $contingencyDir = $this->baseStoragePath . '/contingency_storage';
                    if (!is_dir($contingencyDir)) {
                        mkdir($contingencyDir, 0750, true);
                    }
                    
                    // Usar timestamp e ID de usuário para evitar colisões
                    $safeFileName = time() . '_' . $context['user_id'] . '_' . 
                                    pathinfo($context['original_name'], PATHINFO_FILENAME) . '.' . 
                                    pathinfo($context['original_name'], PATHINFO_EXTENSION);
                    
                    $destinationPath = $contingencyDir . '/' . $safeFileName;
                    
                    // Copiar arquivo para destino de contingência
                    if (!copy($context['temp_path'], $destinationPath)) {
                        throw new \RuntimeException('Falha no armazenamento de contingência');
                    }
                    
                    // Calcular hash para consistência
                    $fileHash = hash_file('sha256', $destinationPath);
                    
                    Logger::info('Arquivo armazenado em diretório de contingência', [
                        'destination' => $destinationPath,
                        'file_hash' => $fileHash
                    ]);
                    
                    return new StorageResult(
                        true, 
                        $destinationPath, 
                        $fileHash, 
                        null,
                        ['Arquivo armazenado em modo de contingência devido a falhas no sistema primário']
                    );
                } catch (\Exception $fallbackError) {
                    Logger::error('Falha crítica no armazenamento de contingência', [
                        'error' => $fallbackError->getMessage()
                    ]);
                    
                    return new StorageResult(false, '', '', 'Falha crítica no sistema de armazenamento');
                }
            },
            $context
        );
    }
    
    /**
     * Calcula entropia de dados para detecção de anomalias
     * 
     * @param string $data Dados para análise
     * @return float Valor de entropia (0-8)
     */
    private function calculateEntropy(string $data): float 
    {
        $bytes = str_split($data);
        $byteCounts = array_fill(0, 256, 0);
        $length = strlen($data);
        
        // Contar ocorrências de cada byte
        foreach ($bytes as $byte) {
            $byteCounts[ord($byte)]++;
        }
        
        // Calcular entropia
        $entropy = 0;
        foreach ($byteCounts as $count) {
            if ($count > 0) {
                $probability = $count / $length;
                $entropy -= $probability * log($probability, 2);
            }
        }
        
        return $entropy;
    }
    
    /**
     * Obtém o caminho de armazenamento segregado para um usuário
     * 
     * @param int $userId ID do usuário
     * @return string Caminho completo de armazenamento
     */
    private function getUserStoragePath(int $userId): string 
    {
        // Implementação de diretório com sharding para evitar limitações de filesystem
        $userIdPadded = str_pad($userId, 10, '0', STR_PAD_LEFT);
        $shard1 = substr($userIdPadded, 0, 2);
        $shard2 = substr($userIdPadded, 2, 2);
        
        return $this->baseStoragePath . '/models/' . $shard1 . '/' . $shard2 . '/' . $userId;
    }
    
    /**
     * Salva metadados de arquivo para referência futura
     * 
     * @param int $userId ID do usuário
     * @param string $fileHash Hash do arquivo
     * @param string $originalName Nome original
     * @param string $storedPath Caminho armazenado
     */
    private function saveFileMetadata(int $userId, string $fileHash, string $originalName, string $storedPath): void 
    {
        try {
            // Diretório de metadados
            $metaDir = $this->getUserStoragePath($userId) . '/metadata';
            if (!is_dir($metaDir)) {
                mkdir($metaDir, 0750, true);
            }
            
            // Arquivo de metadados JSON
            $metaFile = $metaDir . '/' . $fileHash . '.json';
            
            $metadata = [
                'file_hash' => $fileHash,
                'original_name' => $originalName,
                'stored_path' => $storedPath,
                'uploaded_at' => time(),
                'file_size' => filesize($storedPath),
                'mime_type' => $this->detectMimeType($storedPath),
                'extension' => pathinfo($originalName, PATHINFO_EXTENSION)
            ];
            
            file_put_contents($metaFile, json_encode($metadata, JSON_PRETTY_PRINT));
        } catch (\Exception $e) {
            // Não falhar o upload se falhar apenas metadados
            Logger::warning('Falha ao salvar metadados do arquivo', [
                'error' => $e->getMessage(),
                'file_hash' => $fileHash
            ]);
        }
    }
    
    /**
     * Obtém o uso atual de armazenamento de um usuário
     * 
     * @param int $userId ID do usuário
     * @return int Bytes utilizados
     */
    private function getCurrentStorageUsage(int $userId): int 
    {
        try {
            $userDir = $this->getUserStoragePath($userId);
            
            if (!is_dir($userDir)) {
                return 0;
            }
            
            // Calcular tamanho recursivamente
            return $this->dirSize($userDir);
        } catch (\Exception $e) {
            Logger::warning('Falha ao calcular uso de armazenamento', [
                'error' => $e->getMessage(),
                'user_id' => $userId
            ]);
            
            // Em caso de falha, assume zero para não bloquear uploads
            return 0;
        }
    }
    
    /**
     * Calcula tamanho de diretório recursivamente
     * 
     * @param string $dir Caminho do diretório
     * @return int Tamanho em bytes
     */
    private function dirSize(string $dir): int 
    {
        $size = 0;
        $files = scandir($dir);
        
        foreach ($files as $file) {
            if ($file === '.' || $file === '..') continue;
            
            $path = $dir . '/' . $file;
            
            if (is_dir($path)) {
                $size += $this->dirSize($path);
            } else {
                $size += filesize($path);
            }
        }
        
        return $size;
    }
    
    /**
     * Formata bytes para unidades legíveis
     * 
     * @param int $bytes Quantidade em bytes
     * @param int $precision Precisão decimal
     * @return string Valor formatado
     */
    private function formatBytes(int $bytes, int $precision = 2): string 
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= (1 << (10 * $pow));
        
        return round($bytes, $precision) . ' ' . $units[$pow];
    }
}

/**
 * Classe para resultados de upload
 */
class UploadResult 
{
    private bool $success;
    private ?array $metadata;
    private ?string $errorMessage;
    
    /**
     * Inicializa resultado de upload
     * 
     * @param bool $success Indicador de sucesso
     * @param array|null $metadata Metadados do arquivo
     * @param string|null $errorMessage Mensagem de erro
     */
    public function __construct(bool $success, ?array $metadata = null, ?string $errorMessage = null) 
    {
        $this->success = $success;
        $this->metadata = $metadata;
        $this->errorMessage = $errorMessage;
    }
    
    /**
     * Verifica se upload foi bem-sucedido
     * 
     * @return bool Status de sucesso
     */
    public function isSuccess(): bool 
    {
        return $this->success;
    }
    
    /**
     * Obtém metadados do arquivo
     * 
     * @return array|null Metadados
     */
    public function getMetadata(): ?array 
    {
        return $this->metadata;
    }
    
    /**
     * Obtém mensagem de erro
     * 
     * @return string|null Mensagem de erro
     */
    public function getErrorMessage(): ?string 
    {
        return $this->errorMessage;
    }
}

/**
 * Classe para resultados de armazenamento
 */
class StorageResult 
{
    private bool $success;
    private string $filePath;
    private string $fileHash;
    private ?string $errorMessage;
    private array $warnings;
    
    /**
     * Inicializa resultado de armazenamento
     * 
     * @param bool $success Indicador de sucesso
     * @param string $filePath Caminho do arquivo
     * @param string $fileHash Hash do arquivo
     * @param string|null $errorMessage Mensagem de erro
     * @param array $warnings Avisos gerados
     */
    public function __construct(bool $success, string $filePath, string $fileHash, 
                               ?string $errorMessage = null, array $warnings = []) 
    {
        $this->success = $success;
        $this->filePath = $filePath;
        $this->fileHash = $fileHash;
        $this->errorMessage = $errorMessage;
        $this->warnings = $warnings;
    }
    
    /**
     * Verifica se armazenamento foi bem-sucedido
     * 
     * @return bool Status de sucesso
     */
    public function isSuccess(): bool 
    {
        return $this->success;
    }
    
    /**
     * Obtém caminho do arquivo armazenado
     * 
     * @return string Caminho do arquivo
     */
    public function getFilePath(): string 
    {
        return $this->filePath;
    }
    
    /**
     * Obtém hash do arquivo
     * 
     * @return string Hash SHA-256
     */
    public function getFileHash(): string 
    {
        return $this->fileHash;
    }
    
    /**
     * Obtém mensagem de erro
     * 
     * @return string|null Mensagem de erro
     */
    public function getErrorMessage(): ?string 
    {
        return $this->errorMessage;
    }
    
    /**
     * Obtém avisos do armazenamento
     * 
     * @return array Avisos
     */
    public function getWarnings(): array 
    {
        return $this->warnings;
    }
}

/**
 * Classe para resultados de verificação de ameaças
 */
class ThreatScanResult 
{
    private bool $secure;
    private string $message;
    private array $warnings = [];
    
    /**
     * Inicializa resultado de verificação
     * 
     * @param bool $secure Indicador de segurança
     * @param string $message Mensagem descritiva
     */
    public function __construct(bool $secure, string $message) 
    {
        $this->secure = $secure;
        $this->message = $message;
    }
    
    /**
     * Verifica se arquivo é seguro
     * 
     * @return bool Status de segurança
     */
    public function isSecure(): bool 
    {
        return $this->secure;
    }
    
    /**
     * Obtém mensagem descritiva
     * 
     * @return string Mensagem
     */
    public function getMessage(): string 
    {
        return $this->message;
    }
    
    /**
     * Adiciona um aviso
     * 
     * @param string $warning Mensagem de aviso
     */
    public function addWarning(string $warning): void 
    {
        $this->warnings[] = $warning;
    }
    
    /**
     * Obtém avisos da verificação
     * 
     * @return array Avisos
     */
    public function getWarnings(): array 
    {
        return $this->warnings;
    }
}

/**
 * Classe para resultados de arquivo temporário
 */
class TempFileResult 
{
    private bool $valid;
    private ?string $filePath;
    private array $errors;
    
    /**
     * Inicializa resultado de arquivo temporário
     * 
     * @param bool $valid Indicador de validade
     * @param string|null $filePath Caminho do arquivo
     * @param array $errors Erros encontrados
     */
    public function __construct(bool $valid, ?string $filePath = null, array $errors = []) 
    {
        $this->valid = $valid;
        $this->filePath = $filePath;
        $this->errors = $errors;
    }
    
    /**
     * Verifica se operação foi válida
     * 
     * @return bool Status de validade
     */
    public function isValid(): bool 
    {
        return $this->valid;
    }
    
    /**
     * Obtém caminho do arquivo temporário
     * 
     * @return string|null Caminho do arquivo
     */
    public function getFilePath(): ?string 
    {
        return $this->filePath;
    }
    
    /**
     * Obtém erros encontrados
     * 
     * @return array Erros
     */
    public function getErrors(): array 
    {
        return $this->errors;
    }
}
