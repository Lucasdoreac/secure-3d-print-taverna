<?php

namespace App\Lib\Security;

/**
 * Gerenciador central de segurança da aplicação
 * 
 * Esta classe provê interface unificada para funcionalidades
 * de segurança, incluindo CSRF, headers HTTP seguros e
 * validação de entrada.
 */
class SecurityManager {
    /**
     * Obtém um token CSRF para formulários
     * 
     * @return string Token CSRF
     */
    public static function getCsrfToken(): string {
        return CsrfProtection::getToken();
    }
    
    /**
     * Valida um token CSRF
     * 
     * @param string $token Token a ser validado
     * @return bool True se válido, false caso contrário
     */
    public static function validateCsrfToken(?string $token): bool {
        return CsrfProtection::validateToken($token);
    }
    
    /**
     * Configura headers HTTP de segurança para uma resposta
     * 
     * @return void
     */
    public static function applySecurityHeaders(): void {
        SecurityHeaders::applyHeaders();
    }
    
    /**
     * Processa upload de arquivo com validações de segurança
     * 
     * @param array $fileData Dados do arquivo enviado ($_FILES)
     * @param array $allowedTypes Tipos MIME permitidos
     * @param int $maxSize Tamanho máximo em bytes
     * @return array Informações do arquivo processado ou erro
     */
    public static function processFileUpload(array $fileData, array $allowedTypes, int $maxSize): array {
        // Verifica se os dados do arquivo são válidos
        if (empty($fileData) || !isset($fileData['tmp_name']) || !isset($fileData['name']) || empty($fileData['tmp_name'])) {
            return ['success' => false, 'error' => 'Arquivo inválido ou não enviado'];
        }
        
        // Verifica se ocorreu algum erro no upload
        if (isset($fileData['error']) && $fileData['error'] !== UPLOAD_ERR_OK) {
            $errorMessages = [
                UPLOAD_ERR_INI_SIZE => 'O arquivo excede o tamanho máximo permitido pelo PHP',
                UPLOAD_ERR_FORM_SIZE => 'O arquivo excede o tamanho máximo permitido pelo formulário',
                UPLOAD_ERR_PARTIAL => 'O arquivo foi apenas parcialmente carregado',
                UPLOAD_ERR_NO_FILE => 'Nenhum arquivo foi enviado',
                UPLOAD_ERR_NO_TMP_DIR => 'Diretório temporário não encontrado',
                UPLOAD_ERR_CANT_WRITE => 'Falha ao gravar o arquivo no disco',
                UPLOAD_ERR_EXTENSION => 'Uma extensão PHP interrompeu o upload'
            ];
            
            $errorMessage = $errorMessages[$fileData['error']] ?? 'Erro desconhecido no upload';
            return ['success' => false, 'error' => $errorMessage];
        }
        
        // Verifica o tamanho do arquivo
        if ($fileData['size'] > $maxSize) {
            return ['success' => false, 'error' => 'O arquivo excede o tamanho máximo permitido'];
        }
        
        // Verifica o tipo MIME do arquivo
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->file($fileData['tmp_name']);
        
        if (!in_array($mimeType, $allowedTypes, true)) {
            return ['success' => false, 'error' => 'Tipo de arquivo não permitido'];
        }
        
        // Gera um nome seguro para o arquivo
        $fileExtension = pathinfo($fileData['name'], PATHINFO_EXTENSION);
        $safeFileName = bin2hex(random_bytes(16)) . '.' . $fileExtension;
        
        return [
            'success' => true,
            'original_name' => $fileData['name'],
            'safe_name' => $safeFileName,
            'mime_type' => $mimeType,
            'size' => $fileData['size'],
            'tmp_name' => $fileData['tmp_name']
        ];
    }
    
    /**
     * Sanitiza saída para prevenção de XSS
     * 
     * @param string $input Texto a ser sanitizado
     * @return string Texto sanitizado
     */
    public static function sanitizeOutput(string $input): string {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
    
    /**
     * Valida o acesso baseado no nível de permissão do usuário
     * 
     * @param int $requiredLevel Nível de permissão necessário
     * @param int $userLevel Nível de permissão do usuário
     * @return bool True se o usuário tem permissão, false caso contrário
     */
    public static function validateAccess(int $requiredLevel, int $userLevel): bool {
        return $userLevel >= $requiredLevel;
    }
    
    /**
     * Registra tentativa de acesso não autorizado
     * 
     * @param string $userId ID do usuário
     * @param string $resource Recurso acessado
     * @param string $ip Endereço IP
     * @return void
     */
    public static function logUnauthorizedAccess(string $userId, string $resource, string $ip): void {
        // Implementação de logging para acesso não autorizado
        $logMessage = sprintf(
            "[%s] Acesso não autorizado - Usuário: %s, Recurso: %s, IP: %s",
            date('Y-m-d H:i:s'),
            $userId,
            $resource,
            $ip
        );
        
        error_log($logMessage, 3, dirname(__DIR__, 3) . '/logs/security/unauthorized.log');
    }
}