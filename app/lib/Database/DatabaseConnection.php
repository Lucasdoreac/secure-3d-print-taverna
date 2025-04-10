<?php

namespace App\Lib\Database;

/**
 * Abstração de conexão com banco de dados com Prepared Statements obrigatórios
 */
class DatabaseConnection
{
    private static ?self $instance = null;
    private \PDO $pdo;
    
    /**
     * Construtor privado (padrão Singleton)
     */
    private function __construct()
    {
        $config = $this->loadConfig();
        
        try {
            $dsn = sprintf(
                'mysql:host=%s;dbname=%s;charset=utf8mb4',
                $config['host'],
                $config['database']
            );
            
            $options = [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_DEFAULT_FETCH_MODE => \PDO::FETCH_ASSOC,
                \PDO::ATTR_EMULATE_PREPARES => false, // Use prepared statements nativos
                \PDO::MYSQL_ATTR_FOUND_ROWS => true
            ];
            
            $this->pdo = new \PDO($dsn, $config['username'], $config['password'], $options);
        } catch (\PDOException $e) {
            // Log detalhado do erro sem expor detalhes sensíveis externamente
            $this->logError('Falha na conexão com banco de dados', [
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ]);
            
            throw new DatabaseException('Erro ao conectar ao banco de dados');
        }
    }
    
    /**
     * Retorna instância única da conexão (padrão Singleton)
     * 
     * @return self Instância única
     */
    public static function getInstance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        
        return self::$instance;
    }
    
    /**
     * Executa uma query com Prepared Statement
     * 
     * @param string $query SQL query com placeholders
     * @param array<string|int, mixed> $params Parâmetros para a query
     * @return int Número de linhas afetadas
     * @throws DatabaseException Em caso de erro
     */
    public function execute(string $query, array $params = []): int
    {
        try {
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            return $stmt->rowCount();
        } catch (\PDOException $e) {
            $this->logError('Erro ao executar query', [
                'query' => $this->maskSensitiveData($query),
                'params' => $this->maskSensitiveData($params),
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ]);
            
            throw new DatabaseException('Erro ao executar operação no banco de dados');
        }
    }
    
    /**
     * Busca um único registro
     * 
     * @param string $query SQL query com placeholders
     * @param array<string|int, mixed> $params Parâmetros para a query
     * @return array<string, mixed>|null Resultado ou null se não encontrado
     * @throws DatabaseException Em caso de erro
     */
    public function fetchOne(string $query, array $params = []): ?array
    {
        try {
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            $result = $stmt->fetch();
            
            return $result !== false ? $result : null;
        } catch (\PDOException $e) {
            $this->logError('Erro ao buscar registro', [
                'query' => $this->maskSensitiveData($query),
                'params' => $this->maskSensitiveData($params),
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ]);
            
            throw new DatabaseException('Erro ao buscar dados no banco de dados');
        }
    }
    
    /**
     * Busca múltiplos registros
     * 
     * @param string $query SQL query com placeholders
     * @param array<string|int, mixed> $params Parâmetros para a query
     * @return array<int, array<string, mixed>> Array de resultados
     * @throws DatabaseException Em caso de erro
     */
    public function fetchAll(string $query, array $params = []): array
    {
        try {
            $stmt = $this->pdo->prepare($query);
            $stmt->execute($params);
            return $stmt->fetchAll();
        } catch (\PDOException $e) {
            $this->logError('Erro ao buscar múltiplos registros', [
                'query' => $this->maskSensitiveData($query),
                'params' => $this->maskSensitiveData($params),
                'error' => $e->getMessage(),
                'code' => $e->getCode()
            ]);
            
            throw new DatabaseException('Erro ao buscar dados no banco de dados');
        }
    }
    
    /**
     * Executa uma transação com múltiplas operações
     * 
     * @param callable $callback Função que recebe a conexão e executa operações
     * @return mixed Resultado do callback
     * @throws DatabaseException Em caso de erro
     */
    public function transaction(callable $callback): mixed
    {
        try {
            $this->pdo->beginTransaction();
            $result = $callback($this);
            $this->pdo->commit();
            
            return $result;
        } catch (\Exception $e) {
            $this->pdo->rollBack();
            
            if ($e instanceof DatabaseException) {
                throw $e;
            }
            
            $this->logError('Erro durante transação', [
                'error' => $e->getMessage(),
                'code' => $e->getCode(),
                'file' => $e->getFile(),
                'line' => $e->getLine()
            ]);
            
            throw new DatabaseException('Erro ao processar transação no banco de dados');
        }
    }
    
    /**
     * Obtém o último ID inserido
     * 
     * @return string Último ID inserido
     */
    public function lastInsertId(): string
    {
        return $this->pdo->lastInsertId();
    }
    
    /**
     * Carrega configurações de banco de dados
     * 
     * @return array<string, string> Configurações
     */
    private function loadConfig(): array
    {
        $configFile = dirname(__DIR__, 3) . '/config/database.php';
        
        if (!file_exists($configFile)) {
            throw new DatabaseException('Arquivo de configuração do banco de dados não encontrado');
        }
        
        $config = require $configFile;
        
        $requiredKeys = ['host', 'database', 'username', 'password'];
        foreach ($requiredKeys as $key) {
            if (!isset($config[$key])) {
                throw new DatabaseException("Configuração de banco de dados incompleta: '{$key}' ausente");
            }
        }
        
        return $config;
    }
    
    /**
     * Registra erro de forma segura
     * 
     * @param string $message Mensagem do erro
     * @param array<string, mixed> $context Contexto do erro
     * @return void
     */
    private function logError(string $message, array $context = []): void
    {
        // Implementação básica de logging - idealmente, usar PSR-3 LoggerInterface
        error_log("[DatabaseError] {$message}: " . json_encode($context));
    }
    
    /**
     * Mascara dados sensíveis para logging seguro
     * 
     * @param mixed $data Dados a serem mascarados
     * @return mixed Dados mascarados
     */
    private function maskSensitiveData(mixed $data): mixed
    {
        if (is_string($data)) {
            // Mascarar potenciais senhas em consultas SQL
            $masked = preg_replace(
                "/(password\s*=\s*['\"]\s*)([^'\"]*)(['\"]\s*)/i",
                "$1****$3",
                $data
            );
            
            // Mascarar outros dados potencialmente sensíveis
            return preg_replace(
                "/(api[_-]?key|token|secret|password)\s*=\s*['\"]\s*([^'\"]*)(['\"]\s*)/i",
                "$1=****$3",
                $masked ?? $data
            );
        }
        
        if (is_array($data)) {
            $result = [];
            foreach ($data as $key => $value) {
                // Mascarar valores de chaves sensíveis em arrays
                if (is_string($key) && preg_match("/(password|secret|token|api[_-]?key)/i", $key)) {
                    $result[$key] = "****";
                } else {
                    $result[$key] = $this->maskSensitiveData($value);
                }
            }
            return $result;
        }
        
        return $data;
    }
}
