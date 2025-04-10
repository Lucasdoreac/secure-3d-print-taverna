<?php

namespace App\Lib\Security;

/**
 * Implementação de headers HTTP de segurança
 * 
 * Esta classe gerencia a aplicação de headers HTTP de segurança
 * para mitigar vários tipos de ataques.
 */
class SecurityHeaders {
    /** @var array Headers de segurança padrão */
    private static array $defaultHeaders = [
        // Previne XSS forçando o navegador a ativar proteções embutidas
        'X-XSS-Protection' => '1; mode=block',
        
        // Impede o navegador de interpretar arquivos como um tipo diferente
        'X-Content-Type-Options' => 'nosniff',
        
        // Protege contra clickjacking
        'X-Frame-Options' => 'SAMEORIGIN',
        
        // Referrer Policy - controla quanta informação de referência é incluída com requisições
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        
        // Desabilita recursos de rastreamento de terceiros
        'Permissions-Policy' => 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
        
        // Força conexões HTTPS
        'Strict-Transport-Security' => 'max-age=31536000; includeSubDomains',
        
        // Define políticas de segurança de conteúdo para prevenir XSS e injeções
        'Content-Security-Policy' => "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none';"
    ];
    
    /**
     * Aplica os headers HTTP de segurança
     * 
     * @param array $customHeaders Headers personalizados
     * @return void
     */
    public static function applyHeaders(array $customHeaders = []): void {
        // Combina os headers padrão com os personalizados
        $headers = array_merge(self::$defaultHeaders, $customHeaders);
        
        // Define cada header
        foreach ($headers as $name => $value) {
            header("$name: $value");
        }
        
        // Remove headers que podem expor informações do servidor
        header_remove('X-Powered-By');
        header_remove('Server');
    }
    
    /**
     * Configura uma política CSP personalizada
     * 
     * @param array $policies Array associativo com diretivas CSP personalizadas
     * @return string Política CSP formatada
     */
    public static function buildCustomCsp(array $policies): string {
        $cspDirectives = [];
        
        foreach ($policies as $directive => $sources) {
            // Certifica-se de que as fontes estão em um array
            if (!is_array($sources)) {
                $sources = [$sources];
            }
            
            // Formata a diretiva CSP
            $cspDirectives[] = $directive . ' ' . implode(' ', $sources);
        }
        
        return implode('; ', $cspDirectives) . ';';
    }
    
    /**
     * Obtém um header de CSP mais permissivo para ambientes de desenvolvimento
     * 
     * @return string Política CSP para desenvolvimento
     */
    public static function getDevCsp(): string {
        return "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self';";
    }
    
    /**
     * Obtém headers rigorosos para dados sensíveis
     * 
     * @return array Headers adicionais para áreas de alta segurança
     */
    public static function getStrictHeaders(): array {
        return [
            'Cache-Control' => 'no-store, no-cache, must-revalidate, max-age=0',
            'Pragma' => 'no-cache',
            'X-XSS-Protection' => '1; mode=block',
            'Content-Security-Policy' => "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none';",
        ];
    }
}