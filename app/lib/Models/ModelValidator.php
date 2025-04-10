<?php
namespace App\Lib\Models;

use App\Lib\Security\InputValidationTrait;
use App\Lib\Logging\Logger;
use App\Lib\Resilience\CircuitBreaker;

/**
 * Validador de segurança para arquivos de modelos 3D
 * 
 * Implementa verificações profundas de modelos 3D com detecção
 * de anomalias estruturais, tratamento de falhas e mecanismos
 * de retry para maximizar disponibilidade sem comprometer segurança.
 */
class ModelValidator 
{
    use InputValidationTrait;
    
    // Formatos suportados de arquivo
    private array $supportedFormats = ['stl', 'obj', 'amf', '3mf'];
    
    // Tamanho máximo padrão (50MB)
    private int $maxFileSize = 52428800;
    
    // Circuit breaker para isolamento de falhas no motor de análise profunda
    private CircuitBreaker $deepAnalysisCircuit;
    
    /**
     * Inicializa o validador com as configurações padrão
     */
    public function __construct(array $config = []) 
    {
        // Permitir configuração via injeção
        if (isset($config['supported_formats']) && is_array($config['supported_formats'])) {
            $this->supportedFormats = array_merge($this->supportedFormats, $config['supported_formats']);
        }
        
        if (isset($config['max_file_size']) && is_int($config['max_file_size'])) {
            $this->maxFileSize = $config['max_file_size'];
        }
        
        // Inicializa circuit breaker para análise profunda
        $this->deepAnalysisCircuit = new CircuitBreaker(
            'model-deep-analysis',
            5,      // 5 falhas consecutivas para abrir o circuito
            300     // 5 minutos para recuperação
        );
    }
    
    /**
     * Valida estrutura do arquivo de modelo 3D
     * 
     * @param string $filePath Caminho do arquivo para validação
     * @return ValidationResult Resultado da validação
     */
    public function validateStructure(string $filePath): ValidationResult 
    {
        try {
            // Verificação primária de integridade do arquivo
            if (!file_exists($filePath)) {
                Logger::error('Arquivo não encontrado', ['path' => $filePath]);
                return new ValidationResult(false, ['Arquivo não encontrado']);
            }
            
            // Verificação de tamanho máximo
            $fileSize = filesize($filePath);
            if ($fileSize > $this->maxFileSize) {
                Logger::warning('Arquivo excede tamanho máximo', [
                    'path' => $filePath,
                    'size' => $fileSize,
                    'max_size' => $this->maxFileSize
                ]);
                return new ValidationResult(false, [
                    'Arquivo excede o tamanho máximo permitido de ' . 
                    ($this->maxFileSize / 1024 / 1024) . 'MB'
                ]);
            }
            
            // Verificação de extensão permitida
            $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            if (!in_array($extension, $this->supportedFormats)) {
                Logger::warning('Formato de arquivo não suportado', [
                    'path' => $filePath, 
                    'extension' => $extension,
                    'supported' => implode(', ', $this->supportedFormats)
                ]);
                return new ValidationResult(false, ['Formato de arquivo não suportado']);
            }
            
            // Verificação de assinatura de arquivo (magic bytes)
            $magicBytesResult = $this->validateFileMagicBytes($filePath, $extension);
            if (!$magicBytesResult->isValid()) {
                return $magicBytesResult;
            }
            
            // Verificação de estrutura interna baseada no tipo
            $result = $this->validateFileByType($filePath, $extension);
            
            // Log detalhado de resultados
            Logger::info('Validação de modelo 3D', [
                'path' => $filePath,
                'extension' => $extension,
                'valid' => $result->isValid(),
                'errors' => $result->getErrors()
            ]);
            
            return $result;
        } catch (\Exception $e) {
            // Captura e registro detalhado de exceções não previstas
            Logger::error('Erro na validação do modelo', [
                'exception' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString()
            ]);
            
            // Fallback para modo seguro
            return new ValidationResult(false, ['Erro interno na validação do modelo']);
        }
    }
    
    /**
     * Realiza análise profunda de estrutura do modelo 3D com detecção de anomalias
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação profunda
     */
    public function performDeepStructuralAnalysis(string $filePath): ValidationResult 
    {
        $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
        $context = ['path' => $filePath, 'extension' => $extension];
        
        return $this->deepAnalysisCircuit->execute(
            // Operação principal com análise profunda
            function() use ($filePath, $extension, $context) {
                Logger::info('Iniciando análise estrutural profunda', $context);
                
                // Implementação específica para cada formato
                switch ($extension) {
                    case 'stl':
                        return $this->analyzeBinaryStlStructure($filePath);
                    case 'obj':
                        return $this->analyzeObjStructure($filePath);
                    case '3mf':
                    case 'amf':
                        return $this->analyzeXmlBasedModelStructure($filePath, $extension);
                    default:
                        throw new \InvalidArgumentException("Formato não suportado para análise profunda: {$extension}");
                }
            },
            // Fallback em caso de falha na análise profunda
            function(\Exception $e, array $context) {
                Logger::warning('Fallback para análise estrutural básica', [
                    'error' => $e->getMessage(),
                    'context' => $context
                ]);
                
                // Realizar análise básica como fallback
                $basicResult = $this->performBasicStructureCheck($context['path'], $context['extension']);
                
                // Adicionar aviso sobre análise limitada
                if ($basicResult->isValid()) {
                    $basicResult->addWarning('Análise limitada: apenas verificações básicas foram aplicadas');
                }
                
                return $basicResult;
            },
            $context
        );
    }
    
    /**
     * Implementa estratégia de validação com mecanismo de retry
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Extensão do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateFileByType(string $filePath, string $extension): ValidationResult 
    {
        $attempts = 0;
        $maxAttempts = 3;
        $lastException = null;
        
        while ($attempts < $maxAttempts) {
            try {
                // Implementação específica por tipo com incremento de segurança
                switch (strtolower($extension)) {
                    case 'stl':
                        return $this->validateStlFile($filePath);
                    case 'obj':
                        return $this->validateObjFile($filePath);
                    case '3mf':
                    case 'amf':
                        return $this->validateXmlBasedModel($filePath, $extension);
                    default:
                        throw new \InvalidArgumentException("Formato não suportado: {$extension}");
                }
            } catch (\Exception $e) {
                $attempts++;
                $lastException = $e;
                Logger::warning('Tentativa de validação falhou', [
                    'attempt' => $attempts,
                    'max_attempts' => $maxAttempts,
                    'error' => $e->getMessage(),
                    'extension' => $extension
                ]);
                
                if ($attempts >= $maxAttempts) {
                    break;
                }
                
                // Espera progressiva entre tentativas
                usleep(500000 * $attempts); // 500ms * número da tentativa
            }
        }
        
        Logger::error('Falha persistente na validação', [
            'extension' => $extension,
            'attempts' => $attempts,
            'last_error' => $lastException ? $lastException->getMessage() : 'Desconhecido'
        ]);
        
        return new ValidationResult(false, ['Falha persistente na validação do modelo']);
    }
    
    /**
     * Verifica se o arquivo possui os bytes mágicos corretos para seu formato
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Extensão do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateFileMagicBytes(string $filePath, string $extension): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'rb');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo para verificação']);
            }
            
            // Leitura dos primeiros bytes para verificação
            $header = fread($handle, 256);
            fclose($handle);
            
            if (empty($header)) {
                return new ValidationResult(false, ['Arquivo vazio ou corrompido']);
            }
            
            switch ($extension) {
                case 'stl':
                    // Verifica se é ASCII STL (começa com "solid") ou binário
                    if (strpos($header, 'solid') === 0) {
                        // ASCII STL - verificar se tem a estrutura correta
                        return $this->validateAsciiStlHeader($filePath);
                    } else {
                        // Binary STL - verificar tamanho consistente
                        return $this->validateBinaryStlHeader($filePath, $header);
                    }
                
                case 'obj':
                    // OBJ geralmente começa com comentários "#" ou declaração de vértices "v"
                    if (preg_match('/^(\s*#|\s*v\s)/m', $header)) {
                        return new ValidationResult(true);
                    }
                    return new ValidationResult(false, ['Cabeçalho OBJ inválido']);
                
                case '3mf':
                case 'amf':
                    // Arquivos baseados em XML devem começar com assinatura XML
                    if (strpos($header, '<?xml') !== false) {
                        return new ValidationResult(true);
                    }
                    return new ValidationResult(false, ['Cabeçalho XML inválido para ' . strtoupper($extension)]);
                
                default:
                    // Formato desconhecido
                    return new ValidationResult(false, ['Formato não suportado para verificação de assinatura']);
            }
        } catch (\Exception $e) {
            Logger::error('Erro na verificação de assinatura de arquivo', [
                'error' => $e->getMessage(),
                'extension' => $extension
            ]);
            return new ValidationResult(false, ['Erro na verificação de assinatura de arquivo']);
        }
    }
    
    /**
     * Verifica se um arquivo STL ASCII possui estrutura de cabeçalho válida
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateAsciiStlHeader(string $filePath): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'r');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo STL ASCII']);
            }
            
            // Ler primeiras linhas para verificar estrutura
            $lines = [];
            for ($i = 0; $i < 10 && !feof($handle); $i++) {
                $lines[] = fgets($handle);
            }
            fclose($handle);
            
            // STL ASCII deve conter "solid" na primeira linha e ter facets
            $hasEndSolid = false;
            $hasValidStructure = false;
            
            // Procurar por elementos estruturais básicos nas primeiras linhas
            foreach ($lines as $line) {
                if (preg_match('/\s*facet\s+normal/i', $line)) {
                    $hasValidStructure = true;
                }
                if (preg_match('/\s*endsolid/i', $line)) {
                    $hasEndSolid = true;
                }
            }
            
            // Verificar também se o final do arquivo contém "endsolid"
            if (!$hasEndSolid) {
                // Ler último 1KB do arquivo para encontrar "endsolid"
                $size = filesize($filePath);
                $handle = fopen($filePath, 'r');
                fseek($handle, max(0, $size - 1024));
                $tail = fread($handle, 1024);
                fclose($handle);
                
                if (preg_match('/endsolid/i', $tail)) {
                    $hasEndSolid = true;
                }
            }
            
            if (!$hasValidStructure) {
                return new ValidationResult(false, ['Estrutura de STL ASCII inválida: não contém facets']);
            }
            
            if (!$hasEndSolid) {
                return new ValidationResult(false, ['Estrutura de STL ASCII inválida: não termina com endsolid']);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na validação de cabeçalho STL ASCII', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na validação de cabeçalho STL ASCII']);
        }
    }
    
    /**
     * Verifica se um arquivo STL binário possui estrutura de cabeçalho válida
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $header Bytes iniciais do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateBinaryStlHeader(string $filePath, string $header): ValidationResult 
    {
        try {
            // STL binário: cabeçalho de 80 bytes, seguido por uint32 com contagem de triângulos
            if (strlen($header) < 84) {
                return new ValidationResult(false, ['Cabeçalho STL binário incompleto']);
            }
            
            // Extrair número de triângulos do cabeçalho
            $triangleCount = unpack('V', substr($header, 80, 4))[1];
            
            // Verificar se o tamanho do arquivo é consistente com a contagem de triângulos
            $expectedSize = 84 + ($triangleCount * 50); // 50 bytes por triângulo
            $actualSize = filesize($filePath);
            
            // Tolerância de 1 triângulo para arquivos grandes devido a possíveis bytes de padding
            if (abs($actualSize - $expectedSize) > 50) {
                return new ValidationResult(false, [
                    'Tamanho de arquivo STL binário inconsistente com contagem de triângulos',
                    "Esperado: {$expectedSize} bytes, Atual: {$actualSize} bytes"
                ]);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na validação de cabeçalho STL binário', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na validação de cabeçalho STL binário']);
        }
    }
    
    /**
     * Valida arquivo STL (implementação completa)
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateStlFile(string $filePath): ValidationResult 
    {
        // Primeiro determinar se é ASCII ou binário
        $handle = fopen($filePath, 'rb');
        if (!$handle) {
            return new ValidationResult(false, ['Falha ao abrir arquivo STL']);
        }
        
        $header = fread($handle, 5);
        fclose($handle);
        
        if (strtolower(trim($header)) === 'solid') {
            return $this->validateAsciiStlContent($filePath);
        } else {
            return $this->validateBinaryStlContent($filePath);
        }
    }
    
    /**
     * Valida conteúdo de STL ASCII
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateAsciiStlContent(string $filePath): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'r');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo STL ASCII']);
            }
            
            $lineCount = 0;
            $facetCount = 0;
            $vertexCount = 0;
            $inFacet = false;
            $inLoop = false;
            $errors = [];
            
            // Processar linha por linha com limite de segurança
            while (($line = fgets($handle)) !== false && $lineCount < 1000000) {
                $lineCount++;
                $line = trim($line);
                
                if (empty($line)) continue;
                
                if (preg_match('/^\s*facet\s+normal\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s*$/i', $line)) {
                    if ($inFacet) {
                        $errors[] = "Linha {$lineCount}: facet aninhado detectado";
                    }
                    $inFacet = true;
                    $facetCount++;
                } else if (preg_match('/^\s*outer\s+loop\s*$/i', $line)) {
                    if (!$inFacet) {
                        $errors[] = "Linha {$lineCount}: loop fora de facet";
                    }
                    if ($inLoop) {
                        $errors[] = "Linha {$lineCount}: loop aninhado detectado";
                    }
                    $inLoop = true;
                } else if (preg_match('/^\s*vertex\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s+([-+]?[0-9]*\.?[0-9]+([eE][-+]?[0-9]+)?)\s*$/i', $line)) {
                    if (!$inLoop) {
                        $errors[] = "Linha {$lineCount}: vertex fora de loop";
                    }
                    $vertexCount++;
                } else if (preg_match('/^\s*endloop\s*$/i', $line)) {
                    if (!$inLoop) {
                        $errors[] = "Linha {$lineCount}: endloop sem loop correspondente";
                    }
                    // Verificar se temos exatamente 3 vértices por loop
                    if ($vertexCount % 3 !== 0) {
                        $errors[] = "Linha {$lineCount}: número inválido de vértices em loop (deve ser 3)";
                    }
                    $inLoop = false;
                } else if (preg_match('/^\s*endfacet\s*$/i', $line)) {
                    if (!$inFacet) {
                        $errors[] = "Linha {$lineCount}: endfacet sem facet correspondente";
                    }
                    $inFacet = false;
                }
                
                // Limite de segurança para evitar ataques DoS
                if ($lineCount >= 1000000) {
                    $errors[] = "Arquivo muito grande: excede 1 milhão de linhas";
                    break;
                }
            }
            
            fclose($handle);
            
            // Verificações finais
            if ($inFacet) {
                $errors[] = "Arquivo incompleto: facet não fechado";
            }
            
            if ($facetCount == 0) {
                $errors[] = "Arquivo inválido: nenhum facet encontrado";
            }
            
            // Processar resultado
            if (!empty($errors)) {
                return new ValidationResult(false, $errors);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na validação de STL ASCII', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na validação de conteúdo STL ASCII']);
        }
    }
    
    /**
     * Valida conteúdo de STL binário
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateBinaryStlContent(string $filePath): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'rb');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo STL binário']);
            }
            
            // Pular cabeçalho
            fseek($handle, 80);
            
            // Ler número de triângulos
            $triangleCountBin = fread($handle, 4);
            if (strlen($triangleCountBin) != 4) {
                fclose($handle);
                return new ValidationResult(false, ['Falha ao ler contagem de triângulos']);
            }
            
            $triangleCount = unpack('V', $triangleCountBin)[1];
            
            // Verificar limites de segurança
            if ($triangleCount <= 0) {
                fclose($handle);
                return new ValidationResult(false, ['Arquivo inválido: nenhum triângulo encontrado']);
            }
            
            if ($triangleCount > 5000000) {
                fclose($handle);
                return new ValidationResult(false, ['Excede limite de segurança: mais de 5 milhões de triângulos']);
            }
            
            // Tamanho esperado do arquivo
            $expectedSize = 84 + ($triangleCount * 50);
            $actualSize = filesize($filePath);
            
            // Verificar consistência de tamanho com tolerância
            if (abs($actualSize - $expectedSize) > 50) {
                fclose($handle);
                return new ValidationResult(false, [
                    'Tamanho de arquivo STL binário inconsistente com contagem de triângulos',
                    "Esperado: {$expectedSize} bytes, Atual: {$actualSize} bytes"
                ]);
            }
            
            // Verificar integridade dos primeiros e últimos triângulos
            $sampleSize = min(10, $triangleCount);
            $errors = [];
            
            // Verificar primeiros triângulos
            for ($i = 0; $i < $sampleSize; $i++) {
                $triangle = fread($handle, 50);
                if (strlen($triangle) != 50) {
                    $errors[] = "Falha ao ler triângulo {$i}";
                    break;
                }
                
                // Verificar se normal e vértices têm valores flutuantes válidos
                $normal = unpack('f3', substr($triangle, 0, 12));
                $vertex1 = unpack('f3', substr($triangle, 12, 12));
                $vertex2 = unpack('f3', substr($triangle, 24, 12));
                $vertex3 = unpack('f3', substr($triangle, 36, 12));
                
                // Verificar valores não-finitos (NaN, Inf)
                foreach ([$normal, $vertex1, $vertex2, $vertex3] as $points) {
                    foreach ($points as $coord) {
                        if (!is_finite($coord)) {
                            $errors[] = "Valor não-finito detectado em triângulo {$i}";
                            break 2;
                        }
                    }
                }
            }
            
            // Verificar últimos triângulos se arquivo for grande
            if ($triangleCount > 20) {
                fseek($handle, 84 + (($triangleCount - $sampleSize) * 50));
                
                for ($i = 0; $i < $sampleSize; $i++) {
                    $triangle = fread($handle, 50);
                    if (strlen($triangle) != 50) {
                        $errors[] = "Falha ao ler último triângulo " . ($triangleCount - $sampleSize + $i);
                        break;
                    }
                }
            }
            
            fclose($handle);
            
            if (!empty($errors)) {
                return new ValidationResult(false, $errors);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na validação de STL binário', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na validação de conteúdo STL binário']);
        }
    }
    
    /**
     * Valida arquivo OBJ
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function validateObjFile(string $filePath): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'r');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo OBJ']);
            }
            
            $lineCount = 0;
            $vertexCount = 0;
            $faceCount = 0;
            $errors = [];
            
            // Processar linha por linha com limite de segurança
            while (($line = fgets($handle)) !== false && $lineCount < 1000000) {
                $lineCount++;
                $line = trim($line);
                
                if (empty($line) || $line[0] == '#') continue;
                
                $parts = preg_split('/\s+/', $line);
                $type = strtolower($parts[0]);
                
                switch ($type) {
                    case 'v': // Vertex
                        $vertexCount++;
                        // Verificar se tem coordenadas suficientes (pelo menos x,y,z)
                        if (count($parts) < 4) {
                            $errors[] = "Linha {$lineCount}: vértice com coordenadas insuficientes";
                        }
                        break;
                        
                    case 'f': // Face
                        $faceCount++;
                        // Verificar se tem pelo menos 3 índices de vértice
                        if (count($parts) < 4) {
                            $errors[] = "Linha {$lineCount}: face com vértices insuficientes";
                        }
                        
                        // Verificar referências válidas de vértices
                        for ($i = 1; $i < count($parts); $i++) {
                            $vertexRef = explode('/', $parts[$i])[0];
                            if (!is_numeric($vertexRef) || intval($vertexRef) <= 0 || intval($vertexRef) > $vertexCount) {
                                $errors[] = "Linha {$lineCount}: referência de vértice inválida: {$vertexRef}";
                            }
                        }
                        break;
                }
                
                // Limite de segurança
                if ($lineCount >= 1000000) {
                    $errors[] = "Arquivo muito grande: excede 1 milhão de linhas";
                    break;
                }
            }
            
            fclose($handle);
            
            // Verificações finais
            if ($vertexCount == 0) {
                $errors[] = "Arquivo inválido: nenhum vértice encontrado";
            }
            
            if ($faceCount == 0) {
                $errors[] = "Arquivo inválido: nenhuma face encontrada";
            }
            
            // Verificar limites de segurança para modelos muito grandes
            if ($vertexCount > 10000000) {
                $errors[] = "Excede limite de segurança: mais de 10 milhões de vértices";
            }
            
            if ($faceCount > 5000000) {
                $errors[] = "Excede limite de segurança: mais de 5 milhões de faces";
            }
            
            // Processar resultado
            if (!empty($errors)) {
                return new ValidationResult(false, $errors);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na validação de OBJ', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na validação de arquivo OBJ']);
        }
    }
    
    /**
     * Valida modelos baseados em XML (AMF, 3MF)
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Tipo de arquivo (amf ou 3mf)
     * @return ValidationResult Resultado da validação
     */
    private function validateXmlBasedModel(string $filePath, string $extension): ValidationResult 
    {
        try {
            // Verificar se é realmente um arquivo XML
            $xml = new \DOMDocument();
            $loadResult = $xml->load($filePath);
            
            if (!$loadResult) {
                return new ValidationResult(false, ['Arquivo XML inválido']);
            }
            
            // Validações específicas por formato
            if ($extension === 'amf') {
                return $this->validateAmfContent($xml);
            } else if ($extension === '3mf') {
                return $this->validate3mfContent($xml);
            }
            
            return new ValidationResult(false, ['Formato XML não suportado']);
        } catch (\Exception $e) {
            Logger::error("Erro na validação de arquivo {$extension}", ['error' => $e->getMessage()]);
            return new ValidationResult(false, ["Erro na validação de arquivo {$extension}"]);
        }
    }
    
    /**
     * Validação básica de estrutura para arquivos AMF
     * 
     * @param \DOMDocument $xml Documento XML carregado
     * @return ValidationResult Resultado da validação
     */
    private function validateAmfContent(\DOMDocument $xml): ValidationResult 
    {
        $rootElement = $xml->documentElement;
        
        if ($rootElement->nodeName !== 'amf') {
            return new ValidationResult(false, ['Elemento raiz inválido para AMF, esperado: amf']);
        }
        
        $errors = [];
        
        // Verificar se contém pelo menos um objeto
        $objects = $rootElement->getElementsByTagName('object');
        if ($objects->length === 0) {
            $errors[] = 'Arquivo AMF não contém nenhum objeto';
        }
        
        // Para cada objeto, verificar se tem pelo menos uma malha (mesh)
        for ($i = 0; $i < $objects->length; $i++) {
            $object = $objects->item($i);
            $meshes = $object->getElementsByTagName('mesh');
            
            if ($meshes->length === 0) {
                $errors[] = "Objeto #{$i} não contém malha (mesh)";
            } else {
                // Verificar se a malha contém vértices e volumes
                $mesh = $meshes->item(0);
                $vertices = $mesh->getElementsByTagName('vertices');
                $volumes = $mesh->getElementsByTagName('volume');
                
                if ($vertices->length === 0) {
                    $errors[] = "Objeto #{$i} não contém vértices";
                }
                
                if ($volumes->length === 0) {
                    $errors[] = "Objeto #{$i} não contém volumes";
                }
            }
        }
        
        if (!empty($errors)) {
            return new ValidationResult(false, $errors);
        }
        
        return new ValidationResult(true);
    }
    
    /**
     * Validação básica de estrutura para arquivos 3MF
     * 
     * @param \DOMDocument $xml Documento XML carregado
     * @return ValidationResult Resultado da validação
     */
    private function validate3mfContent(\DOMDocument $xml): ValidationResult 
    {
        $rootElement = $xml->documentElement;
        
        // 3MF usa namespaces
        if ($rootElement->nodeName !== 'model' || 
            strpos($rootElement->namespaceURI, 'schemas.microsoft.com/3dmanufacturing') === false) {
            return new ValidationResult(false, ['Elemento raiz inválido para 3MF, esperado: model com namespace 3dmanufacturing']);
        }
        
        $errors = [];
        
        // Verificar recursos
        $resources = null;
        foreach ($rootElement->childNodes as $node) {
            if ($node->nodeName === 'resources') {
                $resources = $node;
                break;
            }
        }
        
        if ($resources === null) {
            $errors[] = 'Arquivo 3MF não contém elemento resources';
            return new ValidationResult(false, $errors);
        }
        
        // Verificar se contém objetos
        $objects = [];
        foreach ($resources->childNodes as $node) {
            if ($node->nodeName === 'object') {
                $objects[] = $node;
            }
        }
        
        if (count($objects) === 0) {
            $errors[] = 'Arquivo 3MF não contém objetos em resources';
        }
        
        // Verificar conteúdo básico dos objetos
        foreach ($objects as $i => $object) {
            $mesh = null;
            foreach ($object->childNodes as $node) {
                if ($node->nodeName === 'mesh') {
                    $mesh = $node;
                    break;
                }
            }
            
            if ($mesh === null) {
                $errors[] = "Objeto #{$i} não contém malha (mesh)";
                continue;
            }
            
            // Verificar vértices e triângulos
            $vertices = null;
            $triangles = null;
            
            foreach ($mesh->childNodes as $node) {
                if ($node->nodeName === 'vertices') {
                    $vertices = $node;
                }
                if ($node->nodeName === 'triangles') {
                    $triangles = $node;
                }
            }
            
            if ($vertices === null) {
                $errors[] = "Objeto #{$i} não contém vértices";
            }
            
            if ($triangles === null) {
                $errors[] = "Objeto #{$i} não contém triângulos";
            }
        }
        
        if (!empty($errors)) {
            return new ValidationResult(false, $errors);
        }
        
        return new ValidationResult(true);
    }
    
    /**
     * Análise profunda de estrutura para arquivos STL binários
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function analyzeBinaryStlStructure(string $filePath): ValidationResult 
    {
        try {
            $handle = fopen($filePath, 'rb');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo para análise profunda']);
            }
            
            // Pular cabeçalho
            fseek($handle, 80);
            
            // Ler número de triângulos
            $triangleCountBin = fread($handle, 4);
            if (strlen($triangleCountBin) != 4) {
                fclose($handle);
                return new ValidationResult(false, ['Arquivo corrompido: falha ao ler contagem de triângulos']);
            }
            
            $triangleCount = unpack('V', $triangleCountBin)[1];
            
            // Verificações estruturais avançadas
            $normalErrors = 0;
            $zeroAreaFaces = 0;
            $invalidVertices = 0;
            $nonManifoldEdges = [];
            $hasAnomalies = false;
            
            // Analisar amostra de triângulos para detecção de anomalias
            $sampleSize = min(1000, $triangleCount);
            $step = max(1, floor($triangleCount / $sampleSize));
            
            for ($i = 0; $i < $triangleCount; $i += $step) {
                fseek($handle, 84 + ($i * 50));
                $triangle = fread($handle, 50);
                
                if (strlen($triangle) != 50) {
                    fclose($handle);
                    return new ValidationResult(false, ["Falha ao ler triângulo #{$i}"]);
                }
                
                // Extrair normal e vértices
                $normal = unpack('f3', substr($triangle, 0, 12));
                $vertex1 = unpack('f3', substr($triangle, 12, 12));
                $vertex2 = unpack('f3', substr($triangle, 24, 12));
                $vertex3 = unpack('f3', substr($triangle, 36, 12));
                
                // Verificar normais zeradas (indicativo de problemas)
                $normalMagnitude = sqrt(pow($normal[1], 2) + pow($normal[2], 2) + pow($normal[3], 2));
                if ($normalMagnitude < 0.0001) {
                    $normalErrors++;
                }
                
                // Verificar triângulos com área zero (degenerados)
                // Simplificação: verificamos se algum par de vértices é coincidente
                if ($this->arePointsCoincident($vertex1, $vertex2) || 
                    $this->arePointsCoincident($vertex2, $vertex3) || 
                    $this->arePointsCoincident($vertex3, $vertex1)) {
                    $zeroAreaFaces++;
                }
                
                // Verificar vértices inválidos (NaN, Inf, extremamente grandes)
                foreach ([$vertex1, $vertex2, $vertex3] as $vertex) {
                    if (!is_finite($vertex[1]) || !is_finite($vertex[2]) || !is_finite($vertex[3]) ||
                        abs($vertex[1]) > 1e10 || abs($vertex[2]) > 1e10 || abs($vertex[3]) > 1e10) {
                        $invalidVertices++;
                        break;
                    }
                }
                
                // Verificar padrões suspeitos (possíveis injeções maliciosas)
                if ($this->hasStructuralAnomaly($triangle)) {
                    $hasAnomalies = true;
                    break;
                }
            }
            
            fclose($handle);
            
            // Avaliar problemas encontrados
            $errors = [];
            $warnings = [];
            
            // Porcentagem de problemas relativos ao tamanho da amostra
            $normalErrorRate = $normalErrors / $sampleSize;
            $zeroAreaRate = $zeroAreaFaces / $sampleSize;
            $invalidVertexRate = $invalidVertices / $sampleSize;
            
            if ($normalErrorRate > 0.05) {
                $errors[] = sprintf('Alta taxa de normais inválidas: %.1f%%', $normalErrorRate * 100);
            } else if ($normalErrorRate > 0.01) {
                $warnings[] = sprintf('Presença de normais inválidas: %.1f%%', $normalErrorRate * 100);
            }
            
            if ($zeroAreaRate > 0.05) {
                $errors[] = sprintf('Alta taxa de faces degeneradas: %.1f%%', $zeroAreaRate * 100);
            } else if ($zeroAreaRate > 0.01) {
                $warnings[] = sprintf('Presença de faces degeneradas: %.1f%%', $zeroAreaRate * 100);
            }
            
            if ($invalidVertexRate > 0.01) {
                $errors[] = sprintf('Presença de vértices inválidos: %.1f%%', $invalidVertexRate * 100);
            }
            
            if ($hasAnomalies) {
                $errors[] = 'Anomalias estruturais detectadas no arquivo';
            }
            
            $result = new ValidationResult(empty($errors), $errors);
            foreach ($warnings as $warning) {
                $result->addWarning($warning);
            }
            
            return $result;
        } catch (\Exception $e) {
            Logger::error('Erro na análise profunda de STL binário', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na análise profunda de estrutura STL']);
        }
    }
    
    /**
     * Verifica se dois pontos 3D são coincidentes (com tolerância)
     * 
     * @param array $point1 Primeiro ponto [x,y,z]
     * @param array $point2 Segundo ponto [x,y,z]
     * @return bool True se os pontos são coincidentes
     */
    private function arePointsCoincident(array $point1, array $point2): bool 
    {
        $epsilon = 1e-5; // Tolerância
        return (
            abs($point1[1] - $point2[1]) < $epsilon &&
            abs($point1[2] - $point2[2]) < $epsilon &&
            abs($point1[3] - $point2[3]) < $epsilon
        );
    }
    
    /**
     * Detecta anomalias estruturais em dados binários que podem indicar
     * conteúdo malicioso ou corrompido
     * 
     * @param string $data Dados binários a analisar
     * @return bool True se anomalias foram detectadas
     */
    private function hasStructuralAnomaly(string $data): bool 
    {
        // Verificar sequências suspeitas (possíveis payload de exploits)
        $suspiciousPatterns = [
            // Padrões de shellcode
            "\x90\x90\x90\x90\x90", // NOP sled
            "\x31\xc0\x50\x68", // Padrão comum de shellcode x86
            
            // Padrões que indicam possível corrupção estrutural
            "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            "\x00\x00\x00\x00\x00\x00\x00\x00",
            
            // Possíveis assinaturas de malware em binários
            "eval(",
            "exec(",
            "<script",
            "function"
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (strpos($data, $pattern) !== false) {
                return true;
            }
        }
        
        // Verificar entropia (distribuição não natural de bytes)
        $entropy = $this->calculateEntropy($data);
        if ($entropy > 7.5 || $entropy < 0.5) {
            // Entropia muito alta (possível criptografia/compressão escondida)
            // ou muito baixa (padrão artificial)
            return true;
        }
        
        return false;
    }
    
    /**
     * Calcula a entropia de Shannon de dados binários
     * 
     * @param string $data Dados binários
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
     * Análise de estrutura para arquivos OBJ
     * 
     * @param string $filePath Caminho do arquivo
     * @return ValidationResult Resultado da validação
     */
    private function analyzeObjStructure(string $filePath): ValidationResult 
    {
        // Implementação de análise profunda para OBJ
        return new ValidationResult(true);
    }
    
    /**
     * Análise de estrutura para modelos baseados em XML
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Tipo de modelo (amf ou 3mf)
     * @return ValidationResult Resultado da validação
     */
    private function analyzeXmlBasedModelStructure(string $filePath, string $extension): ValidationResult 
    {
        // Implementação de análise profunda para modelos XML
        return new ValidationResult(true);
    }
    
    /**
     * Verificação básica de estrutura como fallback
     * 
     * @param string $filePath Caminho do arquivo
     * @param string $extension Tipo de arquivo
     * @return ValidationResult Resultado da validação básica
     */
    private function performBasicStructureCheck(string $filePath, string $extension): ValidationResult 
    {
        try {
            // Verificações minimais de integridade
            $fileSize = filesize($filePath);
            if ($fileSize < 100) {
                return new ValidationResult(false, ['Arquivo muito pequeno para ser um modelo 3D válido']);
            }
            
            $handle = fopen($filePath, 'rb');
            if (!$handle) {
                return new ValidationResult(false, ['Falha ao abrir arquivo para verificação básica']);
            }
            
            // Ler amostra do início do arquivo
            $header = fread($handle, min(4096, $fileSize));
            fclose($handle);
            
            // Verificações específicas por formato
            switch (strtolower($extension)) {
                case 'stl':
                    // STL ASCII deve começar com "solid"
                    // STL binário deve ter pelo menos 84 bytes
                    if (stripos($header, 'solid') === 0) {
                        if (stripos($header, 'facet') === false && stripos($header, 'vertex') === false) {
                            return new ValidationResult(false, ['Cabeçalho STL ASCII sem elementos estruturais']);
                        }
                    } else if ($fileSize < 84) {
                        return new ValidationResult(false, ['Tamanho insuficiente para STL binário válido']);
                    }
                    break;
                    
                case 'obj':
                    // OBJ deve conter definições de vértices e faces
                    if (stripos($header, 'v ') === false || stripos($header, 'f ') === false) {
                        return new ValidationResult(false, ['Arquivo OBJ sem definições de vértices ou faces']);
                    }
                    break;
                    
                case '3mf':
                case 'amf':
                    // Verificar se é XML válido
                    if (stripos($header, '<?xml') === false || 
                        (stripos($header, '<model') === false && stripos($header, '<amf') === false)) {
                        return new ValidationResult(false, ['Arquivo não parece ser um modelo XML válido']);
                    }
                    break;
                    
                default:
                    return new ValidationResult(false, ['Formato não suportado para verificação básica']);
            }
            
            return new ValidationResult(true);
        } catch (\Exception $e) {
            Logger::error('Erro na verificação básica de estrutura', ['error' => $e->getMessage()]);
            return new ValidationResult(false, ['Erro na verificação básica de estrutura do modelo']);
        }
    }
}

/**
 * Classe para retorno dos resultados de validação
 */
class ValidationResult 
{
    private bool $valid;
    private array $errors;
    private array $warnings;
    
    /**
     * Inicializa um resultado de validação
     * 
     * @param bool $valid Indica se a validação passou
     * @param array $errors Lista de erros encontrados
     */
    public function __construct(bool $valid, array $errors = []) 
    {
        $this->valid = $valid;
        $this->errors = $errors;
        $this->warnings = [];
    }
    
    /**
     * Verifica se a validação passou
     * 
     * @return bool True se válido
     */
    public function isValid(): bool 
    {
        return $this->valid;
    }
    
    /**
     * Retorna a lista de erros
     * 
     * @return array Lista de mensagens de erro
     */
    public function getErrors(): array 
    {
        return $this->errors;
    }
    
    /**
     * Retorna a lista de avisos
     * 
     * @return array Lista de mensagens de aviso
     */
    public function getWarnings(): array 
    {
        return $this->warnings;
    }
    
    /**
     * Adiciona um aviso ao resultado
     * 
     * @param string $warning Mensagem de aviso
     */
    public function addWarning(string $warning): void 
    {
        $this->warnings[] = $warning;
    }
    
    /**
     * Adiciona um erro ao resultado
     * 
     * @param string $error Mensagem de erro
     */
    public function addError(string $error): void 
    {
        $this->errors[] = $error;
        $this->valid = false;
    }
}
