<?php

namespace App\Models;

use App\Lib\Security\SecurityManager;
use App\Lib\Database\DatabaseConnection;

/**
 * Modelo de usuário com autenticação segura e controle de acesso
 */
class User
{
    /** @var int ID único do usuário */
    private int $id;
    
    /** @var string Nome de usuário */
    private string $username;
    
    /** @var string Hash da senha */
    private string $passwordHash;
    
    /** @var array<string> Lista de permissões do usuário */
    private array $permissions = [];
    
    /**
     * Construtor privado - utilizar métodos estáticos para instanciar
     */
    private function __construct() 
    {
    }
    
    /**
     * Autentica um usuário com nome e senha
     * 
     * @param string $username Nome de usuário
     * @param string $password Senha em texto puro
     * @return User|null Usuário autenticado ou null se falhar
     */
    public static function authenticate(string $username, string $password): ?self
    {
        $db = DatabaseConnection::getInstance();
        
        // Prepared statement para evitar SQL injection
        $query = "SELECT id, username, password_hash, permissions FROM users WHERE username = :username";
        $params = [':username' => $username];
        
        $userData = $db->fetchOne($query, $params);
        if (!$userData) {
            // Log de tentativa sem expor informação sensível
            error_log("Tentativa de login com usuário inexistente: {$username}");
            return null;
        }
        
        // Verificação de senha com timing constante
        if (!SecurityManager::verifyPassword($password, $userData['password_hash'])) {
            error_log("Tentativa de login com senha incorreta para usuário: {$username}");
            return null;
        }
        
        $user = new self();
        $user->id = $userData['id'];
        $user->username = $userData['username'];
        $user->passwordHash = $userData['password_hash'];
        
        // Carregar permissões
        if (!empty($userData['permissions'])) {
            $user->permissions = is_string($userData['permissions']) 
                ? json_decode($userData['permissions'], true) 
                : $userData['permissions'];
        }
        
        // Regenerar ID de sessão após autenticação bem-sucedida
        SecurityManager::regenerateSessionId(true);
        
        return $user;
    }
    
    /**
     * Busca um usuário pelo ID
     * 
     * @param int $id ID do usuário
     * @return User|null Usuário ou null se não encontrado
     */
    public static function findById(int $id): ?self
    {
        $db = DatabaseConnection::getInstance();
        
        $query = "SELECT id, username, password_hash, permissions FROM users WHERE id = :id";
        $params = [':id' => $id];
        
        $userData = $db->fetchOne($query, $params);
        if (!$userData) {
            return null;
        }
        
        $user = new self();
        $user->id = $userData['id'];
        $user->username = $userData['username'];
        $user->passwordHash = $userData['password_hash'];
        
        // Carregar permissões
        if (!empty($userData['permissions'])) {
            $user->permissions = is_string($userData['permissions']) 
                ? json_decode($userData['permissions'], true) 
                : $userData['permissions'];
        }
        
        return $user;
    }
    
    /**
     * Verifica se o usuário tem uma permissão específica
     * 
     * @param string $permission Permissão a verificar
     * @return bool True se tem a permissão
     */
    public function hasPermission(string $permission): bool
    {
        // Permissões especiais que concedem acesso a tudo
        if (in_array('admin', $this->permissions, true)) {
            return true;
        }
        
        return in_array($permission, $this->permissions, true);
    }
    
    /**
     * Cria um hash seguro de senha usando Argon2id
     * 
     * @param string $password Senha em texto puro
     * @return string Hash da senha
     */
    public static function hashPassword(string $password): string
    {
        return SecurityManager::hashPassword($password);
    }
    
    /**
     * Retorna o ID do usuário
     * 
     * @return int ID do usuário
     */
    public function getId(): int
    {
        return $this->id;
    }
    
    /**
     * Retorna o nome de usuário
     * 
     * @return string Nome de usuário
     */
    public function getUsername(): string
    {
        return $this->username;
    }
    
    /**
     * Retorna as permissões do usuário
     * 
     * @return array<string> Lista de permissões
     */
    public function getPermissions(): array
    {
        return $this->permissions;
    }
}
