<?php
/**
 * Ponto de entrada principal da aplicação
 * 
 * Este arquivo é o único ponto de entrada público da aplicação,
 * implementando medidas de segurança e inicializando o framework.
 */

// Definir caminho base da aplicação
define('BASE_PATH', dirname(__DIR__));

// Carregamento do Autoloader do Composer
require BASE_PATH . '/vendor/autoload.php';

// Inicializar gerenciamento de sessão segura
session_start([
    'cookie_httponly' => true,     // Prevenir acesso ao cookie via JavaScript
    'cookie_secure' => true,       // Cookies apenas em HTTPS
    'use_strict_mode' => true,     // Modo estrito de sessão
    'cookie_samesite' => 'Lax',    // Proteção SameSite contra CSRF
    'gc_maxlifetime' => 3600,      // Tempo máximo de vida da sessão (1 hora)
]);

// Carregar configurações da aplicação
$config = require BASE_PATH . '/config/app.php';

// Aplicar headers de segurança
\App\Lib\Security\SecurityHeaders::applyHeaders();

// Inicializar router e processar requisição
$router = new \App\Router();
$router->processRequest();