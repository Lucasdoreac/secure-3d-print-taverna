<?php

namespace App\Controllers;

use App\Lib\Security\SecurityManager;
use App\Lib\Validation\InputValidationTrait;
use App\Models\User;

/**
 * Controlador base com funcionalidades de segurança
 * 
 * Este controlador implementa funcionalidades de segurança essenciais
 * que devem ser herdadas por todos os controladores específicos.
 */
abstract class BaseController
{
    use InputValidationTrait;
    
    /**
     * Usuário autenticado atualmente
     * 
     * @var User|null
     */
    protected ?User $currentUser = null;
    
    /**
     * Construtor do controlador base
     * 
     * Inicializa componentes de segurança e carrega usuário da sessão
     */
    public function __construct()
    {
        // Aplicar headers de segurança em todas as respostas
        SecurityManager::applySecurityHeaders();
        
        // Carregar usuário da sessão se autenticado
        $this->loadCurrentUser();
    }
    
    /**
     * Verifica token CSRF para operações não-idempotentes
     * 
     * @return void
     */
    protected function verifyCsrfToken(): void
    {
        $token = $_POST['csrf_token'] ?? null;
        
        if (!SecurityManager::validateCsrfToken($token)) {
            $this->renderError(403, 'Falha na validação de segurança');
            exit;
        }
    }
    
    /**
     * Verifica se usuário está autenticado
     * 
     * @return User|null Usuário autenticado ou null
     */
    protected function requireAuthentication(): ?User
    {
        if ($this->currentUser === null) {
            $this->renderError(401, 'Autenticação requerida');
            exit;
        }
        
        return $this->currentUser;
    }
    
    /**
     * Verifica permissão específica
     * 
     * @param string $permission Nome da permissão
     * @return void
     */
    protected function requirePermission(string $permission): void
    {
        $user = $this->requireAuthentication();
        
        if (!method_exists($user, 'hasPermission') || !$user->hasPermission($permission)) {
            $this->renderError(403, 'Permissão negada');
            exit;
        }
    }
    
    /**
     * Carrega usuário da sessão
     * 
     * @return void
     */
    protected function loadCurrentUser(): void
    {
        // Esta é uma implementação simulada
        // Em um ambiente real, você carregaria o usuário do banco de dados
        if (isset($_SESSION['user_id'])) {
            // $this->currentUser = User::findById($_SESSION['user_id']);
        }
    }
    
    /**
     * Renderiza resposta JSON com saída sanitizada
     * 
     * @param array $data Dados a serem renderizados
     * @param int $statusCode Código de status HTTP
     * @return void
     */
    protected function renderJson(array $data, int $statusCode = 200): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json');
        echo json_encode($data);
        exit;
    }
    
    /**
     * Renderiza erro em formato JSON
     * 
     * @param int $statusCode Código de status HTTP
     * @param string $message Mensagem de erro
     * @return void
     */
    protected function renderError(int $statusCode, string $message): void
    {
        $this->renderJson([
            'error' => true,
            'message' => $message
        ], $statusCode);
    }
    
    /**
     * Renderiza view com dados sanitizados
     * 
     * @param string $view Nome da view
     * @param array $data Dados para a view
     * @return void
     */
    protected function renderView(string $view, array $data = []): void
    {
        // Extrair dados para a view
        extract($data);
        
        // Iniciar buffer de saída
        ob_start();
        
        // Incluir template
        include BASE_PATH . "/app/views/{$view}.php";
        
        // Obter conteúdo do buffer
        $content = ob_get_clean();
        
        // Renderizar layout principal com conteúdo
        include BASE_PATH . "/app/views/layouts/main.php";
        exit;
    }
}
