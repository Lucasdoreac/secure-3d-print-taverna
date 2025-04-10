<?php

/**
 * Constantes globais da aplicação
 * 
 * Este arquivo contém definições de constantes utilizadas por toda a aplicação.
 * É carregado automaticamente pelo Composer através do autoload.
 */

// Path para o diretório raiz do projeto
if (!defined('BASE_PATH')) {
    define('BASE_PATH', dirname(__DIR__));
}

// Ambiente de aplicação (production, development, testing)
if (!defined('APP_ENV')) {
    define('APP_ENV', getenv('APP_ENV') ?: 'development');
}

// Modo de debug (true em desenvolvimento, false em produção)
if (!defined('DEBUG_MODE')) {
    define('DEBUG_MODE', APP_ENV !== 'production');
}

// URL base da aplicação
if (!defined('BASE_URL')) {
    define('BASE_URL', getenv('BASE_URL') ?: 'http://localhost:8080');
}

// Versão da aplicação (obtida do composer.json)
if (!defined('APP_VERSION')) {
    $composerJson = json_decode(file_get_contents(BASE_PATH . '/composer.json'), true);
    define('APP_VERSION', $composerJson['version'] ?? '1.0.0');
}

// Timezone padrão
date_default_timezone_set('UTC');

// Configuração de exibição de erros baseada no ambiente
if (DEBUG_MODE) {
    ini_set('display_errors', 1);
    ini_set('display_startup_errors', 1);
    error_reporting(E_ALL);
} else {
    ini_set('display_errors', 0);
    ini_set('display_startup_errors', 0);
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
}
