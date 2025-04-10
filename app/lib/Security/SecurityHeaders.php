<?php

namespace App\Lib\Security;

/**
 * Implementação de headers HTTP de segurança
 */
class SecurityHeaders
{
    /**
     * Content Security Policy padrão
     */
    private const DEFAULT_CSP = [
        "default-src 'self'",
        "img-src 'self' data:",
        "style-src 'self' 'unsafe-inline'",
        "script-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'"
    ];
    
    /**
     * Headers de segurança padrão
     */
    private const SECURITY_HEADERS = [
        'X-Content-Type-Options' => 'nosniff',
        'X-Frame-Options' => 'DENY',
        'X-XSS-Protection' => '1; mode=block',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(), microphone=(), camera=()',
        'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma' => 'no-cache'
    ];
    
    /**
     * Aplica todos os headers de segurança HTTP
     * 
     * @return void
     */
    public static function applyAll(): void
    {
        self::applyContentSecurityPolicy();
        self::applySecurityHeaders();
        
        if (self::isHttpsEnabled()) {
            self::applyStrictTransportSecurity();
        }
    }
    
    /**
     * Aplica Content Security Policy
     * 
     * @param array<string>|null $policies Políticas CSP personalizadas
     * @return void
     */
    public static function applyContentSecurityPolicy(?array $policies = null): void
    {
        $cspHeader = implode('; ', $policies ?? self::DEFAULT_CSP);
        header("Content-Security-Policy: {$cspHeader}");
    }
    
    /**
     * Aplica headers de segurança padrão
     * 
     * @param array<string, string>|null $headers Headers personalizados
     * @return void
     */
    public static function applySecurityHeaders(?array $headers = null): void
    {
        $securityHeaders = $headers ?? self::SECURITY_HEADERS;
        
        foreach ($securityHeaders as $header => $value) {
            header("{$header}: {$value}");
        }
    }
    
    /**
     * Aplica Strict-Transport-Security
     * 
     * @param int $maxAge Duração em segundos (padrão: 31536000 = 1 ano)
     * @param bool $includeSubDomains Incluir subdomínios na política
     * @param bool $preload Incluir flag de preload
     * @return void
     */
    public static function applyStrictTransportSecurity(
        int $maxAge = 31536000,
        bool $includeSubDomains = true,
        bool $preload = false
    ): void {
        $hsts = "max-age={$maxAge}";
        
        if ($includeSubDomains) {
            $hsts .= '; includeSubDomains';
        }
        
        if ($preload) {
            $hsts .= '; preload';
        }
        
        header("Strict-Transport-Security: {$hsts}");
    }
    
    /**
     * Verifica se HTTPS está habilitado
     * 
     * @return bool True se HTTPS estiver ativo
     */
    private static function isHttpsEnabled(): bool
    {
        return (
            (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ||
            (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https') ||
            (isset($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443)
        );
    }
    
    /**
     * Aplica header de Feature-Policy
     * 
     * @deprecated Use Permissions-Policy instead (já incluído nos headers padrão)
     * @param array<string, string> $policies Políticas de Feature-Policy
     * @return void
     */
    public static function applyFeaturePolicy(array $policies): void
    {
        $policyHeader = [];
        
        foreach ($policies as $feature => $allowList) {
            $policyHeader[] = "{$feature} {$allowList}";
        }
        
        header("Feature-Policy: " . implode('; ', $policyHeader));
    }
}
