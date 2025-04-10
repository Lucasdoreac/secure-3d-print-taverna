<?php

/**
 * Configurações gerais da aplicação
 */
return [
    // Informações básicas da aplicação
    'name' => 'Secure 3D Print Taverna',
    'version' => '0.1.0',
    'env' => $_ENV['APP_ENV'] ?? 'development',
    'debug' => filter_var($_ENV['APP_DEBUG'] ?? true, FILTER_VALIDATE_BOOLEAN),
    'url' => $_ENV['APP_URL'] ?? 'http://localhost:8080',
    
    // Definições de rotas
    'routes' => [
        'default_controller' => 'HomeController',
        'default_action' => 'index',
        'error_controller' => 'ErrorController',
        'login_route' => '/auth/login',
    ],
    
    // Configurações de visualização
    'views' => [
        'path' => BASE_PATH . '/app/views',
        'layout' => 'layouts/main',
        'errors' => [
            '404' => 'errors/404',
            '500' => 'errors/500',
        ],
    ],
    
    // Configurações de log
    'logging' => [
        'channel' => $_ENV['LOG_CHANNEL'] ?? 'file',
        'level' => $_ENV['LOG_LEVEL'] ?? 'debug',
        'path' => $_ENV['LOG_PATH'] ?? BASE_PATH . '/logs/app.log',
    ],
    
    // Configurações de upload
    'uploads' => [
        'max_size' => $_ENV['UPLOAD_MAX_SIZE'] ?? '25M',
        'allowed_types' => explode(',', $_ENV['UPLOAD_ALLOWED_TYPES'] ?? 'stl,obj,zip'),
        'storage_path' => BASE_PATH . '/storage/uploads',
    ],
    
    // Processamento de modelos 3D
    'model_processing' => [
        'processing_path' => BASE_PATH . '/storage/processing',
        'completed_path' => BASE_PATH . '/storage/completed',
        'max_dimensions' => [
            'x' => 200, // mm
            'y' => 200, // mm
            'z' => 200, // mm
        ],
        'default_scale' => 1.0,
    ],
    
    // Componentes ativos da aplicação
    'components' => [
        'csrf_protection' => true,
        'input_validation' => true,
        'security_headers' => true,
        'secure_session' => true,
        'prepared_statements' => true,
    ],
    
    // Configurações de template e renderização
    'template' => [
        'sanitize_output' => true,
        'cache_enabled' => false,
        'cache_path' => BASE_PATH . '/storage/cache/views',
    ],
];
