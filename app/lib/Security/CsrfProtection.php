<?php

namespace App\Lib\Security;

/**
 * Implementação robusta de proteção CSRF
 * 
 * Esta classe implementa proteção contra ataques Cross-Site Request Forgery
 * utilizando tokens criptograficamente seguros.
 */
class CsrfProtection
{
    /** @var string Nome do token nos formulários */
    private const TOKEN_NAME = 'csrf_token';
    
    /** @var int Tempo de expiração dos tokens em segundos (1 hora) */
    private const TOKEN_EXPIRATION = 3600;
    
    /**
     * Gera um token CSRF criptograficamente seguro
     * 
     * @return string Token gerado em formato hexadecimal
     */
    public static function generateToken(): string
    {
        $token = bin2hex(random_bytes(32)); // 64 caracteres hexadecimais
        
        // Armazenar token e timestamp na sessão
        $_SESSION['csrf_tokens'][$token] = time();
        
        // Limpar tokens expirados
        self::cleanExpiredTokens();
        
        return $token;
    }
    
    /**
     * Obtém um token CSRF para uso em formulários
     * 
     * @return string Token CSRF existente ou novo
     */
    public static function getToken(): string
    {
        // Inicializar sessão se necessário
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Inicializar array de tokens se não existir
        if (!isset($_SESSION['csrf_tokens']) || !is_array($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
        
        // Obter último token não expirado ou gerar novo
        $validTokens = array_filter($_SESSION['csrf_tokens'], function ($timestamp) {
            return time() - $timestamp < self::TOKEN_EXPIRATION;
        });
        
        if (empty($validTokens)) {
            return self::generateToken();
        }
        
        // Retornar token mais recente
        $token = array_key_first($validTokens);
        return $token;
    }
    
    /**
     * Valida um token CSRF recebido
     * 
     * @param string $token Token a ser validado
     * @return bool True se o token for válido, false caso contrário
     */
    public static function validateToken(?string $token): bool
    {
        if (empty($token) || !is_string($token) || strlen($token) !== 64) {
            return false;
        }
        
        // Verificar se o token existe na sessão
        if (!isset($_SESSION['csrf_tokens'][$token])) {
            return false;
        }
        
        // Verificar expiração
        $timestamp = $_SESSION['csrf_tokens'][$token];
        if (time() - $timestamp > self::TOKEN_EXPIRATION) {
            unset($_SESSION['csrf_tokens'][$token]);
            return false;
        }
        
        // Remover token após uso (one-time use)
        unset($_SESSION['csrf_tokens'][$token]);
        return true;
    }
    
    /**
     * Limpa tokens expirados da sessão
     */
    private static function cleanExpiredTokens(): void
    {
        if (!isset($_SESSION['csrf_tokens'])) {
            return;
        }
        
        $currentTime = time();
        
        foreach ($_SESSION['csrf_tokens'] as $token => $timestamp) {
            if ($currentTime - $timestamp > self::TOKEN_EXPIRATION) {
                unset($_SESSION['csrf_tokens'][$token]);
            }
        }
    }
    
    /**
     * Retorna campo HTML para inclusão em formulários
     * 
     * @return string HTML para token CSRF
     */
    public static function getFormField(): string
    {
        $token = self::getToken();
        return '<input type="hidden" name="' . self::TOKEN_NAME . '" value="' . htmlspecialchars($token, ENT_QUOTES, 'UTF-8') . '">';
    }
}
