<?php

namespace App\Lib\Security;

/**
 * Implementação de proteção CSRF com tokens de uso único e expiração
 */
class CsrfProtection
{
    /**
     * Tempo de expiração padrão dos tokens (3600 segundos = 1 hora)
     */
    private const DEFAULT_EXPIRATION = 3600;
    
    /**
     * Gera um novo token CSRF e o armazena na sessão
     * 
     * @param int|null $expiration Tempo em segundos até a expiração (null para usar padrão)
     * @return string Token gerado
     */
    public static function generateToken(?int $expiration = null): string
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Inicializar array de tokens na sessão se não existir
        if (!isset($_SESSION['csrf_tokens']) || !is_array($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        // Limpar tokens expirados
        self::cleanExpiredTokens();
        
        // Gerar novo token criptograficamente seguro
        $token = bin2hex(random_bytes(32)); // 64 caracteres hex
        
        // Armazenar token com timestamp de criação
        $expirationTime = $expiration ?? self::DEFAULT_EXPIRATION;
        $_SESSION['csrf_tokens'][$token] = time() + $expirationTime;
        
        return $token;
    }
    
    /**
     * Valida um token CSRF e o remove após validação (one-time use)
     * 
     * @param string|null $token Token a ser validado
     * @return bool True se o token é válido
     */
    public static function validateToken(?string $token): bool
    {
        if (empty($token) || session_status() === PHP_SESSION_NONE) {
            return false;
        }
        
        if (!isset($_SESSION['csrf_tokens']) || !is_array($_SESSION['csrf_tokens'])) {
            return false;
        }
        
        // Verificar se o token existe e não expirou
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        $expirationTime = $_SESSION['csrf_tokens'][$token];
        if (time() > $expirationTime) {
            // Token expirado, remover e retornar falso
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }
        
        // Token válido, remover (one-time use) e retornar verdadeiro
        unset($_SESSION['csrf_tokens'][$token]);
        return true;
    }
    
    /**
     * Gera um campo de formulário HTML com token CSRF
     * 
     * @param int|null $expiration Tempo de expiração opcional
     * @return string HTML do campo hidden com token
     */
    public static function generateTokenField(?int $expiration = null): string
    {
        $token = self::generateToken($expiration);
        return sprintf(
            '<input type="hidden" name="csrf_token" value="%s">',
            htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
        );
    }
    
    /**
     * Remove tokens expirados da sessão
     * 
     * @return void
     */
    private static function cleanExpiredTokens(): void
    {
        if (!isset($_SESSION['csrf_tokens']) || !is_array($_SESSION['csrf_tokens'])) {
            return;
        }
        
        $currentTime = time();
        foreach ($_SESSION['csrf_tokens'] as $token => $expirationTime) {
            if ($currentTime > $expirationTime) {
                unset($_SESSION['csrf_tokens'][$token]);
            }
        }
    }
    
    /**
     * Limpa todos os tokens CSRF armazenados
     * 
     * @return void
     */
    public static function clearAllTokens(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        $_SESSION['csrf_tokens'] = [];
    }
}
