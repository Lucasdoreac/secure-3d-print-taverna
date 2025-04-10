<?php
/**
 * Configurações de segurança da aplicação
 */

return [
    // Configurações de proteção CSRF
    'csrf' => [
        'enabled' => true,
        'token_expiration' => 3600, // 1 hora
        'token_length' => 64, // 32 bytes = 64 caracteres hex
        'strict_check' => true, // Verificar CSRF em todas requisições POST
    ],
    
    // Configurações de proteção contra ataques de força bruta
    'bruteforce' => [
        'enabled' => true,
        'max_attempts' => 5, // Número máximo de tentativas
        'lockout_time' => 1800, // Tempo de bloqueio em segundos (30 minutos)
        'monitored_routes' => [
            'login',
            'admin/login',
            'reset-password',
        ],
    ],
    
    // Configurações de sanitização de saída
    'output_sanitization' => [
        'enabled' => true,
        'default_strategy' => 'html', // html, text, json
    ],
    
    // Configurações para uploads de arquivos
    'file_uploads' => [
        'max_size' => 20 * 1024 * 1024, // 20MB
        'allowed_image_types' => [
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
        ],
        'allowed_model_types' => [
            'model/stl',
            'model/obj',
            'application/octet-stream', // STL binário às vezes é detectado assim
        ],
        'disallowed_extensions' => [
            'php', 'phtml', 'php3', 'php4', 'php5', 'php7',
            'exe', 'sh', 'bat', 'cmd', 'com', 'js',
            'jar', 'jsp', 'phar', 'py', 'pl', 'rb',
        ],
        'scan_for_threats' => true, // Escanear uploads para ameaças
    ],
    
    // Configurações de senha
    'password' => [
        'min_length' => 12,
        'require_uppercase' => true,
        'require_lowercase' => true,
        'require_number' => true,
        'require_special' => true,
        'hash_algorithm' => PASSWORD_ARGON2ID,
        'hash_options' => [
            'memory_cost' => 65536, // 64MB
            'time_cost' => 4,
            'threads' => 3,
        ],
    ],
    
    // Configurações Content Security Policy (CSP)
    'csp' => [
        'default-src' => "'self'",
        'script-src' => "'self'",
        'style-src' => "'self' 'unsafe-inline'",
        'img-src' => "'self' data:",
        'font-src' => "'self'",
        'connect-src' => "'self'",
        'media-src' => "'self'",
        'object-src' => "'none'",
        'frame-src' => "'none'",
        'base-uri' => "'self'",
        'form-action' => "'self'",
    ],
    
    // Modos de segurança
    'security_modes' => [
        'development' => [
            'display_errors' => true,
            'debug_trace' => true,
            'disable_csrf' => false,
            'detailed_errors' => true,
        ],
        'production' => [
            'display_errors' => false,
            'debug_trace' => false,
            'disable_csrf' => false,
            'detailed_errors' => false,
        ],
    ],
    
    // Sandbox para processamento de modelos 3D
    'model_processing' => [
        'sandbox_enabled' => true,
        'resource_limits' => [
            'max_memory' => '512M',
            'max_execution_time' => 120,
        ],
    ],
    
    // Configurações de auditoria de segurança
    'audit' => [
        'enabled' => true,
        'log_dir' => BASE_PATH . '/logs/security',
        'log_level' => 'warning', // debug, info, warning, error, critical
        'events' => [
            'login_success',
            'login_failure',
            'sensitive_data_access',
            'admin_actions',
            'password_reset',
            'file_upload',
        ],
    ],
    
    // Configurações de anti-XSS
    'xss_protection' => [
        'enabled' => true,
        'filter_input' => true,
        'filter_cookies' => true,
        'filter_server_vars' => true,
    ],
];