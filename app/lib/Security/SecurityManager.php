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
        // Implementação a ser adicionada
        return ['success' => false, 'error' => 'Not implemented'];
    }
}