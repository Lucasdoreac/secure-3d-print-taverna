<?php

/**
 * Bootstrap file para testes do Secure 3D Print Taverna
 * 
 * Este arquivo configura o ambiente para execução de testes
 * e inicializa componentes críticos necessários.
 */

// Definir constantes
define('BASE_PATH', dirname(__DIR__));
define('APP_ENV', 'testing');

// Carregar autoloader do Composer
require_once BASE_PATH . '/vendor/autoload.php';

// Inicializar sessão para testes que dependem de sessão
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Configurar manipulação de erro para testes
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Inicializar funções de utilidade para testes
require_once __DIR__ . '/TestUtilities.php';
