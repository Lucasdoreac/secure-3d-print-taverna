<?php

/**
 * Bootstrap para testes unitários
 * 
 * Carrega autoloader, constantes e configurações para ambiente de testes
 */

// Path para o diretório raiz do projeto
$projectRoot = dirname(__DIR__);

// Carrega o autoloader do Composer
require $projectRoot . '/vendor/autoload.php';

// Define constantes para o ambiente de testes
define('BASE_PATH', $projectRoot);
define('APP_ENV', 'testing');

// Inicializa suporte para sessões em testes
if (!isset($_SESSION) && !headers_sent()) {
    session_start();
}

// Stub para funções que manipulam saída
if (!function_exists('header')) {
    function header($header, $replace = true, $http_response_code = null) {
        // Stub para evitar erros ao chamar header() nos testes
        return;
    }
}

// Mock da função error_log para testes
if (!function_exists('error_log')) {
    function error_log($message, $message_type = 0, $destination = null, $extra_headers = null) {
        // Stub para evitar logging real durante testes
        return true;
    }
}

/**
 * Função auxiliar para criar mocks de classe com métodos estáticos
 * 
 * @param string $className Nome da classe a ser mockada
 * @param array $methods Métodos estáticos a serem mockados
 * @return void
 */
function createStaticMock(string $className, array $methods): void {
    // Criar classe temporária que estende a original
    $mockClassName = $className . '_Mock_' . md5(uniqid('', true));
    
    $classCode = "class $mockClassName extends $className {";
    
    foreach ($methods as $methodName => $returnValue) {
        $returnStatement = is_callable($returnValue) 
            ? 'return call_user_func_array($returnValue, func_get_args());'
            : 'return ' . var_export($returnValue, true) . ';';
            
        $classCode .= "
            public static function $methodName() {
                $returnStatement
            }
        ";
    }
    
    $classCode .= "}";
    
    // Avaliar código da classe mock
    eval($classCode);
    
    // Substituir classe original pelo mock
    class_alias($mockClassName, $className, true);
}
