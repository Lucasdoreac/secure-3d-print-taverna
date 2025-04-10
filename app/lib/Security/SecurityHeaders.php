<?php

namespace App\Lib\Security;

/**
 * Gerenciador de headers HTTP de segurança
 * 
 * Esta classe implementa headers HTTP de segurança recomendados
 * para proteger contra diversas vulnerabilidades web.
 */
class SecurityHeaders
{
    /**
     * Lista de headers de segurança padrão e seus valores
     * 
     * @var array
     */
    protected static $defaultHeaders = [
        // Previne MIME-sniffing
        'X-Content-Type-Options' => 'nosniff',
        
        // Controla onde o site pode ser incorporado (previne clickjacking)
        'X-Frame-Options' => 'DENY',
        
        // Previne XSS refletido em navegadores modernos
        'X-XSS-Protection' => '1; mode=block',
        
        // Enforce HTTPS
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        
        // Evita exposição de informações sensíveis
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        
        // Controla quais recursos o navegador pode carregar
        'Content-Security-Policy' => self::getDefaultCSP(),
        
        // Controla quais recursos são permitidos na página
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=()',
    ];
    
    /**
     * Retorna a política CSP padrão
     * 
     * @return string
     */
    protected static function getDefaultCSP(): string
    {
        return "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src 'self' data:; " .
               "font-src 'self'; " .
               "connect-src 'self'; " .
               "media-src 'self'; " .
               "object-src 'none'; " .
               "frame-src 'none'; " .
               "base-uri 'self'; " .
               "form-action 'self'";
    }
    
    /**
     * Aplica os headers de segurança à resposta HTTP
     * 
     * @param array $customHeaders Headers personalizados para substituir os padrões
     * @return void
     */
    public static function applyHeaders(array $customHeaders = []): void
    {
        $headers = array_merge(self::$defaultHeaders, $customHeaders);
        
        foreach ($headers as $name => $value) {
            if (!headers_sent()) {
                header("$name: $value");
            }
        }
    }
    
    /**
     * Obtém a política CSP para ambiente de desenvolvimento (mais permissiva)
     * 
     * @return string Header CSP para desenvolvimento
     */
    public static function getDevelopmentCSP(): string
    {
        return "default-src 'self'; " .
               "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " .
               "style-src 'self' 'unsafe-inline'; " .
               "img-src 'self' data:; " .
               "font-src 'self'; " .
               "connect-src 'self'; " .
               "media-src 'self'; " .
               "object-src 'none'; " .
               "frame-src 'self'; " .
               "base-uri 'self'; " .
               "form-action 'self'";
    }
    
    /**
     * Configura headers para ambiente de desenvolvimento
     * 
     * @return void
     */
    public static function applyDevelopmentHeaders(): void
    {
        $devHeaders = self::$defaultHeaders;
        $devHeaders['Content-Security-Policy'] = self::getDevelopmentCSP();
        
        // Remover HSTS em ambiente de desenvolvimento
        unset($devHeaders['Strict-Transport-Security']);
        
        self::applyHeaders($devHeaders);
    }
}
