<?php
namespace App\Lib\Resilience;

use App\Lib\Logging\Logger;

/**
 * Implementação do padrão Circuit Breaker para operações sujeitas a falhas
 * 
 * Circuit Breaker implementa um mecanismo de isolamento de falhas que previne
 * tentativas repetidas de operações com falha, permitindo degradação gradual
 * do sistema e recuperação automática após períodos de timeout.
 */
class CircuitBreaker 
{
    // Estados possíveis do circuit breaker
    private const STATE_CLOSED = 'closed';      // Operação normal, permitida
    private const STATE_OPEN = 'open';          // Operação proibida temporariamente
    private const STATE_HALF_OPEN = 'half_open'; // Testando recuperação
    
    private string $serviceName;
    private string $state = self::STATE_CLOSED;
    private int $failureCount = 0;
    private int $failureThreshold;
    private int $resetTimeout;
    private ?int $lastFailureTime = null;
    private array $metrics = [
        'success_count' => 0,
        'failure_count' => 0,
        'rejection_count' => 0,
        'last_status_change' => null
    ];
    
    /**
     * Inicializa um novo circuit breaker
     * 
     * @param string $serviceName Identificador do serviço protegido
     * @param int $failureThreshold Número de falhas consecutivas para abrir o circuito
     * @param int $resetTimeout Tempo em segundos antes de tentar recuperação
     */
    public function __construct(
        string $serviceName,
        int $failureThreshold = 3,
        int $resetTimeout = 30
    ) {
        $this->serviceName = $serviceName;
        $this->failureThreshold = $failureThreshold;
        $this->resetTimeout = $resetTimeout;
        $this->metrics['last_status_change'] = time();
    }
    
    /**
     * Executa operação com proteção de circuit breaker
     * 
     * @param callable $operation Função a ser executada
     * @param callable|null $fallback Função de fallback em caso de falha
     * @param array $context Dados de contexto para logging e fallback
     * @return mixed Resultado da operação ou fallback
     * @throws \Exception Se falhar e não houver fallback
     */
    public function execute(callable $operation, ?callable $fallback = null, array $context = []) 
    {
        $this->updateState();
        
        if ($this->state === self::STATE_OPEN) {
            $this->metrics['rejection_count']++;
            Logger::info('Circuit breaker aberto, operação negada', [
                'service' => $this->serviceName,
                'state' => $this->state,
                'metrics' => $this->metrics,
                'context' => $context
            ]);
            
            return $this->handleFallback($fallback, 
                new \Exception("Serviço temporariamente indisponível: {$this->serviceName}"), 
                $context
            );
        }
        
        try {
            $result = $operation();
            
            // Operação bem-sucedida
            $this->metrics['success_count']++;
            
            if ($this->state === self::STATE_HALF_OPEN) {
                $this->reset();
                Logger::info('Circuit breaker restaurado após sucesso', [
                    'service' => $this->serviceName,
                    'metrics' => $this->metrics
                ]);
            }
            
            // Resetar contador de falhas se estiver fechado
            if ($this->state === self::STATE_CLOSED) {
                $this->failureCount = 0;
            }
            
            return $result;
        } catch (\Exception $e) {
            return $this->handleFailure($e, $fallback, $context);
        }
    }
    
    /**
     * Processa falha de operação
     * 
     * @param \Exception $e Exceção capturada
     * @param callable|null $fallback Função de fallback
     * @param array $context Dados de contexto
     * @return mixed Resultado do fallback ou exceção lançada
     * @throws \Exception
     */
    private function handleFailure(\Exception $e, ?callable $fallback, array $context) 
    {
        $this->failureCount++;
        $this->lastFailureTime = time();
        $this->metrics['failure_count']++;
        
        $previousState = $this->state;
        
        Logger::warning('Falha em operação protegida', [
            'service' => $this->serviceName,
            'failureCount' => $this->failureCount,
            'error' => $e->getMessage(),
            'state' => $this->state,
            'context' => $context
        ]);
        
        if ($this->failureCount >= $this->failureThreshold) {
            $this->state = self::STATE_OPEN;
            $this->metrics['last_status_change'] = time();
            
            if ($previousState !== self::STATE_OPEN) {
                Logger::error('Circuit breaker aberto após múltiplas falhas', [
                    'service' => $this->serviceName,
                    'failures' => $this->failureCount,
                    'threshold' => $this->failureThreshold,
                    'metrics' => $this->metrics
                ]);
            }
        }
        
        return $this->handleFallback($fallback, $e, $context);
    }
    
    /**
     * Executa fallback ou propaga exceção
     * 
     * @param callable|null $fallback Função de fallback
     * @param \Exception $exception Exceção original
     * @param array $context Dados de contexto
     * @return mixed Resultado do fallback
     * @throws \Exception Se não houver fallback
     */
    private function handleFallback(?callable $fallback, \Exception $exception, array $context) 
    {
        if ($fallback !== null) {
            try {
                return $fallback($exception, $context);
            } catch (\Exception $fallbackException) {
                Logger::error('Falha no fallback do circuit breaker', [
                    'service' => $this->serviceName,
                    'originalError' => $exception->getMessage(),
                    'fallbackError' => $fallbackException->getMessage()
                ]);
                throw $fallbackException;
            }
        }
        
        throw $exception;
    }
    
    /**
     * Atualiza estado do circuit breaker baseado em timeout
     */
    private function updateState(): void 
    {
        if ($this->state === self::STATE_OPEN && $this->lastFailureTime !== null) {
            $elapsed = time() - $this->lastFailureTime;
            
            if ($elapsed >= $this->resetTimeout) {
                $previousState = $this->state;
                $this->state = self::STATE_HALF_OPEN;
                $this->metrics['last_status_change'] = time();
                
                Logger::info('Circuit breaker em half-open para teste', [
                    'service' => $this->serviceName,
                    'elapsedTime' => $elapsed,
                    'resetTimeout' => $this->resetTimeout
                ]);
            }
        }
    }
    
    /**
     * Reseta o circuit breaker para estado fechado
     */
    public function reset(): void 
    {
        $previousState = $this->state;
        $this->state = self::STATE_CLOSED;
        $this->failureCount = 0;
        $this->lastFailureTime = null;
        $this->metrics['last_status_change'] = time();
        
        if ($previousState !== self::STATE_CLOSED) {
            Logger::info('Circuit breaker resetado manualmente', [
                'service' => $this->serviceName,
                'previousState' => $previousState,
                'metrics' => $this->metrics
            ]);
        }
    }
    
    /**
     * Obtém o estado atual do circuit breaker
     * 
     * @return string Estado atual (closed, open, half_open)
     */
    public function getState(): string 
    {
        return $this->state;
    }
    
    /**
     * Obtém métricas do circuit breaker
     * 
     * @return array Dados estatísticos de operação
     */
    public function getMetrics(): array 
    {
        $currentMetrics = $this->metrics;
        $currentMetrics['current_state'] = $this->state;
        $currentMetrics['failure_threshold'] = $this->failureThreshold;
        $currentMetrics['reset_timeout'] = $this->resetTimeout;
        $currentMetrics['current_failure_count'] = $this->failureCount;
        
        if ($this->lastFailureTime !== null) {
            $currentMetrics['seconds_since_last_failure'] = time() - $this->lastFailureTime;
        }
        
        return $currentMetrics;
    }
}
