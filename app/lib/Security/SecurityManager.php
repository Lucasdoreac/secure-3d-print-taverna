<?php

namespace App\Lib\Security;

/**
 * Interface unificada para funcionalidades de segurança
 */
class SecurityManager
{
    /**
     * Aplica todos os headers de segurança HTTP
     * 
     * @return void
     */
    public static function applySecurityHeaders(): void
    {
        SecurityHeaders::applyAll();
    }
    
    /**
     * Gera um token CSRF
     * 
     * @param int|null $expiration Tempo de expiração opcional
     * @return string Token gerado
     */
    public static function generateCsrfToken(?int $expiration = null): string
    {
        return CsrfProtection::generateToken($expiration);
    }
    
    /**
     * Valida um token CSRF
     * 
     * @param string|null $token Token a validar
     * @return bool Resultado da validação
     */
    public static function validateCsrfToken(?string $token): bool
    {
        return CsrfProtection::validateToken($token);
    }
    
    /**
     * Gera um campo de formulário com token CSRF
     * 
     * @param int|null $expiration Tempo de expiração opcional
     * @return string HTML do campo
     */
    public static function generateCsrfField(?int $expiration = null): string
    {
        return CsrfProtection::generateTokenField($expiration);
    }
    
    /**
     * Valida dados de entrada com tipo específico
     * 
     * @param string $name Nome do campo
     * @param mixed $value Valor a validar
     * @param string $type Tipo de dados esperado
     * @param array<string, mixed> $rules Regras adicionais
     * @return ValidationResult Resultado da validação
     */
    public static function validateInput(
        string $name,
        mixed $value,
        string $type,
        array $rules = []
    ): ValidationResult {
        $validator = new InputValidator();
        return $validator->validate($name, $value, $type, $rules);
    }
    
    /**
     * Cria um hash seguro de senha usando Argon2id
     * 
     * @param string $password Senha em texto puro
     * @return string Hash da senha
     */
    public static function hashPassword(string $password): string
    {
        // Argon2id com parâmetros seguros
        return password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => 65536, // 64MB
            'time_cost' => 4,
            'threads' => 3
        ]);
    }
    
    /**
     * Verifica uma senha contra um hash com timing constante
     * 
     * @param string $password Senha em texto puro
     * @param string $hash Hash armazenado
     * @return bool Resultado da verificação
     */
    public static function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }
    
    /**
     * Realiza sanitização de saída para prevenir XSS
     * 
     * @param string $input String a sanitizar
     * @return string String sanitizada
     */
    public static function sanitizeOutput(string $input): string
    {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
    
    /**
     * Regenera o ID de sessão de forma segura
     * 
     * @param bool $deleteOldSession Se true, apaga dados da sessão antiga
     * @return bool Resultado da operação
     */
    public static function regenerateSessionId(bool $deleteOldSession = true): bool
    {
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        return session_regenerate_id($deleteOldSession);
    }
    
    /**
     * Configura cookies de sessão com flags de segurança
     * 
     * @return bool Resultado da operação
     */
    public static function secureSessionCookies(): bool
    {
        return session_set_cookie_params([
            'lifetime' => 0, // Até o fechamento do navegador
            'path' => '/',
            'secure' => true, // Apenas HTTPS
            'httponly' => true, // Inacessível via JavaScript
            'samesite' => 'Lax' // Proteção contra CSRF
        ]);
    }
}
