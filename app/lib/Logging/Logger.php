<?php

namespace App\Lib\Logging;

/**
 * Sistema de logging centralizado com suporte a diferentes níveis
 * e formatos de saída.
 */
class Logger
{
    /** @var string Níveis de log */
    const LEVEL_DEBUG = 'DEBUG';
    const LEVEL_INFO = 'INFO';
    const LEVEL_NOTICE = 'NOTICE';
    const LEVEL_WARNING = 'WARNING';
    const LEVEL_ERROR = 'ERROR';
    const LEVEL_CRITICAL = 'CRITICAL';
    const LEVEL_ALERT = 'ALERT';
    const LEVEL_EMERGENCY = 'EMERGENCY';
    
    /** @var array<string> Níveis de log em ordem de severidade */
    private static array $levels = [
        self::LEVEL_DEBUG,
        self::LEVEL_INFO,
        self::LEVEL_NOTICE,
        self::LEVEL_WARNING,
        self::LEVEL_ERROR,
        self::LEVEL_CRITICAL,
        self::LEVEL_ALERT,
        self::LEVEL_EMERGENCY
    ];
    
    /** @var string Nível mínimo de log configurado */
    private static string $minLevel = self::LEVEL_DEBUG;
    
    /** @var string|null Caminho para o arquivo de log */
    private static ?string $logFile = null;
    
    /**
     * Configura o sistema de logging
     * 
     * @param string $minLevel Nível mínimo para logging
     * @param string|null $logFile Caminho para o arquivo de log (null para syslog)
     * @return void
     */
    public static function configure(string $minLevel = self::LEVEL_DEBUG, ?string $logFile = null): void
    {
        if (in_array($minLevel, self::$levels, true)) {
            self::$minLevel = $minLevel;
        }
        
        self::$logFile = $logFile;
        
        // Criar diretório de logs se não existir
        if (self::$logFile !== null) {
            $logDir = dirname(self::$logFile);
            if (!is_dir($logDir)) {
                mkdir($logDir, 0755, true);
            }
        }
    }
    
    /**
     * Log de nível debug
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function debug(string $message, array $context = []): void
    {
        self::log(self::LEVEL_DEBUG, $message, $context);
    }
    
    /**
     * Log de nível info
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function info(string $message, array $context = []): void
    {
        self::log(self::LEVEL_INFO, $message, $context);
    }
    
    /**
     * Log de nível notice
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function notice(string $message, array $context = []): void
    {
        self::log(self::LEVEL_NOTICE, $message, $context);
    }
    
    /**
     * Log de nível warning
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function warning(string $message, array $context = []): void
    {
        self::log(self::LEVEL_WARNING, $message, $context);
    }
    
    /**
     * Log de nível error
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function error(string $message, array $context = []): void
    {
        self::log(self::LEVEL_ERROR, $message, $context);
    }
    
    /**
     * Log de nível critical
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function critical(string $message, array $context = []): void
    {
        self::log(self::LEVEL_CRITICAL, $message, $context);
    }
    
    /**
     * Log de nível alert
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function alert(string $message, array $context = []): void
    {
        self::log(self::LEVEL_ALERT, $message, $context);
    }
    
    /**
     * Log de nível emergency
     * 
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    public static function emergency(string $message, array $context = []): void
    {
        self::log(self::LEVEL_EMERGENCY, $message, $context);
    }
    
    /**
     * Registra uma entrada de log
     * 
     * @param string $level Nível de log
     * @param string $message Mensagem de log
     * @param array<string, mixed> $context Dados adicionais de contexto
     * @return void
     */
    private static function log(string $level, string $message, array $context = []): void
    {
        // Verificar nível mínimo
        if (array_search($level, self::$levels, true) < array_search(self::$minLevel, self::$levels, true)) {
            return;
        }
        
        // Sanitizar contexto para log seguro
        $sanitizedContext = self::sanitizeContext($context);
        
        // Formatar mensagem
        $timestamp = date('Y-m-d H:i:s');
        $contextJson = !empty($sanitizedContext) ? ' ' . json_encode($sanitizedContext) : '';
        $logMessage = "[{$timestamp}] [{$level}] {$message}{$contextJson}";
        
        // Escrever no arquivo ou usar error_log
        if (self::$logFile !== null) {
            file_put_contents(self::$logFile, $logMessage . PHP_EOL, FILE_APPEND);
        } else {
            error_log($logMessage);
        }
    }
    
    /**
     * Sanitiza contexto para evitar log de dados sensíveis
     * 
     * @param mixed $context Contexto a sanitizar
     * @return mixed Contexto sanitizado
     */
    private static function sanitizeContext(mixed $context): mixed
    {
        if (is_array($context)) {
            $sanitized = [];
            foreach ($context as $key => $value) {
                // Mascarar chaves potencialmente sensíveis
                if (is_string($key) && preg_match('/(password|token|key|secret|credential)/i', $key)) {
                    $sanitized[$key] = '[REDACTED]';
                } else {
                    $sanitized[$key] = self::sanitizeContext($value);
                }
            }
            return $sanitized;
        } elseif (is_object($context)) {
            // Converter para array para manter apenas dados serializáveis
            return self::sanitizeContext((array)$context);
        } else {
            return $context;
        }
    }
}
