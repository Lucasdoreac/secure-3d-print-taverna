<?php

namespace Tests;

/**
 * Classe de utilidades para auxiliar testes
 * 
 * Fornece funções utilitárias para configurar ambiente de teste,
 * simular requisições HTTP, gerar dados fictícios seguros e
 * garantir isolamento adequado entre casos de teste.
 */
class TestUtilities
{
    /**
     * Simula uma requisição HTTP com método e parâmetros específicos
     * 
     * @param string $method Método HTTP (GET, POST, PUT, DELETE)
     * @param array $params Parâmetros da requisição
     * @param array $server Variáveis de servidor
     * @param array $cookies Cookies
     * @param array $files Arquivos enviados
     * @return void
     */
    public static function simulateRequest(
        string $method, 
        array $params = [], 
        array $server = [], 
        array $cookies = [], 
        array $files = []
    ): void {
        // Limpar variáveis globais
        $_GET = [];
        $_POST = [];
        $_REQUEST = [];
        $_SERVER = array_merge([
            'REQUEST_METHOD' => $method,
            'REMOTE_ADDR' => '127.0.0.1',
            'HTTP_USER_AGENT' => 'PHPUnit Test',
            'HTTP_HOST' => 'localhost',
            'SERVER_NAME' => 'localhost',
            'SERVER_PORT' => '80',
            'SCRIPT_NAME' => '/index.php',
            'REQUEST_URI' => '/',
            'HTTPS' => 'off'
        ], $server);
        
        $_COOKIE = $cookies;
        $_FILES = $files;
        
        // Definir parâmetros conforme método
        if ($method === 'GET') {
            $_GET = $params;
            $_REQUEST = $params;
        } elseif ($method === 'POST') {
            $_POST = $params;
            $_REQUEST = $params;
        }
    }
    
    /**
     * Gera um token CSRF para testes
     * 
     * @return string Token CSRF
     */
    public static function generateTestCsrfToken(): string
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_tokens'][$token] = time();
        return $token;
    }
    
    /**
     * Gera um usuário de teste
     * 
     * @param array $attributes Atributos personalizados
     * @return array Dados do usuário
     */
    public static function createTestUser(array $attributes = []): array
    {
        $defaultUser = [
            'id' => 9999,
            'username' => 'test_user_' . uniqid(),
            'email' => 'test_' . uniqid() . '@example.com',
            'password_hash' => password_hash('Test@Password123', PASSWORD_ARGON2ID),
            'is_active' => 1,
            'role' => 'customer'
        ];
        
        return array_merge($defaultUser, $attributes);
    }
    
    /**
     * Simula uma sessão de usuário autenticado
     * 
     * @param array $user Dados do usuário
     * @return void
     */
    public static function simulateAuthentication(array $user): void
    {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['last_activity'] = time();
    }
    
    /**
     * Limpa a sessão de testes
     * 
     * @return void
     */
    public static function clearSession(): void
    {
        $_SESSION = [];
    }
}
