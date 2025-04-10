<?php

namespace App;

/**
 * Router da aplicação
 * 
 * Esta classe gerencia o roteamento de requisições HTTP,
 * direcionando cada URL para o controller e ação apropriados.
 */
class Router
{
    /**
     * Rotas registradas para cada método HTTP
     * 
     * @var array
     */
    protected $routes = [
        'GET' => [],
        'POST' => [],
        'PUT' => [],
        'DELETE' => []
    ];
    
    /**
     * Registra uma rota para o método GET
     * 
     * @param string $path Caminho da URL
     * @param array $handler Controller e método para processar a requisição
     * @return void
     */
    public function get(string $path, array $handler): void
    {
        $this->routes['GET'][$path] = $handler;
    }
    
    /**
     * Registra uma rota para o método POST
     * 
     * @param string $path Caminho da URL
     * @param array $handler Controller e método para processar a requisição
     * @return void
     */
    public function post(string $path, array $handler): void
    {
        $this->routes['POST'][$path] = $handler;
    }
    
    /**
     * Registra uma rota para o método PUT
     * 
     * @param string $path Caminho da URL
     * @param array $handler Controller e método para processar a requisição
     * @return void
     */
    public function put(string $path, array $handler): void
    {
        $this->routes['PUT'][$path] = $handler;
    }
    
    /**
     * Registra uma rota para o método DELETE
     * 
     * @param string $path Caminho da URL
     * @param array $handler Controller e método para processar a requisição
     * @return void
     */
    public function delete(string $path, array $handler): void
    {
        $this->routes['DELETE'][$path] = $handler;
    }
    
    /**
     * Processa a requisição HTTP e direciona para o controller apropriado
     * 
     * @return void
     */
    public function processRequest(): void
    {
        // Obter método e caminho da requisição
        $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH) ?? '/';
        
        // Verificar se rota existe
        if (!isset($this->routes[$method][$path])) {
            $this->handleNotFound();
            return;
        }
        
        // Obter e executar handler
        $handler = $this->routes[$method][$path];
        $this->executeHandler($handler);
    }
    
    /**
     * Executa o controller e método especificados no handler
     * 
     * @param array $handler [Controller, método]
     * @return void
     */
    protected function executeHandler(array $handler): void
    {
        // Verificar formato do handler
        if (count($handler) != 2) {
            $this->handleError();
            return;
        }
        
        // Extrair controller e método
        [$controllerClass, $method] = $handler;
        
        // Verificar se controller existe
        if (!class_exists($controllerClass)) {
            $this->handleError();
            return;
        }
        
        // Instanciar controller e verificar se método existe
        $controller = new $controllerClass();
        if (!method_exists($controller, $method)) {
            $this->handleError();
            return;
        }
        
        // Executar método no controller
        $controller->$method();
    }
    
    /**
     * Trata requisições para rotas não encontradas
     * 
     * @return void
     */
    protected function handleNotFound(): void
    {
        header('HTTP/1.1 404 Not Found');
        echo '404 - Página não encontrada';
    }
    
    /**
     * Trata erros internos do servidor
     * 
     * @return void
     */
    protected function handleError(): void
    {
        header('HTTP/1.1 500 Internal Server Error');
        echo '500 - Erro interno do servidor';
    }
}
