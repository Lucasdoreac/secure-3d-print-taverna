<?php

namespace App\Controllers;

use App\Lib\Security\SecurityManager;
use App\Lib\Security\InputValidationTrait;
use App\Models\User;

/**
 * Controller base com guardrails de segurança integrados
 * 
 * Fornece funcionalidades comuns para todos os controllers
 * incluindo validação de entrada, proteção CSRF e gestão de sessão
 */
abstract class BaseController
{
    use InputValidationTrait;
    
    /** @var User|null Usuário autenticado atual */
    protected ?User $currentUser = null;
    
    /** @var array<string, mixed> Dados a serem compartilhados com a view */
    protected array $viewData = [];
    
    /**
     * Construtor do controller base
     * 
     * Inicializa componentes de segurança e carrega o usuário da sessão
     */
    public function __construct()
    {
        // Aplicar headers de segurança em todas as respostas
        SecurityManager::applySecurityHeaders();
        
        // Inicializar sessão de forma segura
        $this->initializeSecureSession();
        
        // Carregar usuário da sessão se autenticado
        $this->loadCurrentUser();
        
        // Adicionar token CSRF para views
        $this->viewData['csrf_token'] = SecurityManager::generateCsrfToken();
        $this->viewData['csrf_field'] = SecurityManager::generateCsrfField();
    }
    
    /**
     * Verifica token CSRF para operações não-idempotentes
     * 
     * @throws \Exception Se a validação falhar
     * @return void
     */
    protected function verifyCsrfToken(): void
    {
        $token = $_POST['csrf_token'] ?? null;
        
        if (!SecurityManager::validateCsrfToken($token)) {
            http_response_code(403);
            $this->renderError('Falha na validação de segurança', 403);
            exit;
        }
    }
    
    /**
     * Verifica se o método HTTP da requisição corresponde ao esperado
     * 
     * @param string|array<string> $methods Método(s) HTTP esperado(s)
     * @throws \Exception Se o método não corresponder
     * @return void
     */
    protected function requireHttpMethod(string|array $methods): void
    {
        $currentMethod = $_SERVER['REQUEST_METHOD'] ?? '';
        $allowedMethods = is_array($methods) ? $methods : [$methods];
        
        if (!in_array($currentMethod, $allowedMethods, true)) {
            $allowedStr = implode(', ', $allowedMethods);
            http_response_code(405);
            header("Allow: {$allowedStr}");
            $this->renderError("Método {$currentMethod} não permitido", 405);
            exit;
        }
    }
    
    /**
     * Verifica se usuário está autenticado
     * 
     * @throws \Exception Se o usuário não estiver autenticado
     * @return User Usuário autenticado
     */
    protected function requireAuthentication(): User
    {
        if ($this->currentUser === null) {
            http_response_code(401);
            $this->renderError('Autenticação requerida', 401);
            exit;
        }
        
        return $this->currentUser;
    }
    
    /**
     * Verifica se o usuário possui permissão específica
     * 
     * @param string $permission Permissão requerida
     * @throws \Exception Se o usuário não tiver a permissão
     * @return void
     */
    protected function requirePermission(string $permission): void
    {
        $user = $this->requireAuthentication();
        
        if (!$user->hasPermission($permission)) {
            http_response_code(403);
            $this->renderError('Permissão negada', 403);
            exit;
        }
    }
    
    /**
     * Renderiza uma view com dados sanitizados
     * 
     * @param string $view Caminho para o arquivo de view
     * @param array<string, mixed> $data Dados adicionais para a view
     * @return void
     */
    protected function renderView(string $view, array $data = []): void
    {
        // Mesclar dados da view com dados específicos
        $viewData = array_merge($this->viewData, $data);
        
        // Sanitizar todos os dados da view para prevenir XSS
        $sanitizedData = $this->sanitizeViewData($viewData);
        
        // Extrair variáveis para a view
        extract($sanitizedData, EXTR_SKIP);
        
        // Capturar saída da view
        ob_start();
        $viewFile = dirname(__DIR__) . "/views/{$view}.php";
        
        if (!file_exists($viewFile)) {
            throw new \Exception("View não encontrada: {$view}");
        }
        
        include $viewFile;
        $content = ob_get_clean();
        
        // Renderizar layout principal com conteúdo da view
        $layoutFile = dirname(__DIR__) . "/views/layouts/main.php";
        
        if (file_exists($layoutFile)) {
            include $layoutFile;
        } else {
            echo $content;
        }
    }
    
    /**
     * Renderiza resposta JSON com dados sanitizados
     * 
     * @param array<string, mixed> $data Dados a serem retornados
     * @param int $statusCode Código HTTP de status
     * @return void
     */
    protected function renderJson(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        
        // Sanitizar dados de saída
        $sanitizedData = $this->sanitizeViewData($data);
        
        echo json_encode($sanitizedData);
        exit;
    }
    
    /**
     * Renderiza erro em formato consistente
     * 
     * @param string $message Mensagem de erro
     * @param int $statusCode Código HTTP de status
     * @return void
     */
    protected function renderError(string $message, int $statusCode = 400): void
    {
        // Determinar formato de resposta com base no Accept header
        $acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
        
        if (strpos($acceptHeader, 'application/json') !== false) {
            $this->renderJson([
                'error' => true,
                'message' => $message
            ], $statusCode);
        } else {
            $this->renderView('error', [
                'message' => $message,
                'code' => $statusCode
            ]);
        }
    }
    
    /**
     * Inicializa sessão com configurações seguras
     * 
     * @return void
     */
    private function initializeSecureSession(): void
    {
        if (session_status() === PHP_SESSION_NONE) {
            // Configurar cookies de sessão seguros
            SecurityManager::secureSessionCookies();
            
            // Iniciar sessão
            session_start();
        }
    }
    
    /**
     * Carrega o usuário atual da sessão
     * 
     * @return void
     */
    private function loadCurrentUser(): void
    {
        if (isset($_SESSION['user_id'])) {
            // Implementar carregamento do usuário da sessão
            // $this->currentUser = User::findById($_SESSION['user_id']);
        }
    }
    
    /**
     * Sanitiza dados para a view para prevenir XSS
     * 
     * @param mixed $data Dados a serem sanitizados
     * @return mixed Dados sanitizados
     */
    private function sanitizeViewData(mixed $data): mixed
    {
        if (is_string($data)) {
            return SecurityManager::sanitizeOutput($data);
        }
        
        if (is_array($data)) {
            $sanitized = [];
            foreach ($data as $key => $value) {
                $sanitized[$key] = $this->sanitizeViewData($value);
            }
            return $sanitized;
        }
        
        return $data;
    }
}
