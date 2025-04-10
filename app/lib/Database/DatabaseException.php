<?php

namespace App\Lib\Database;

/**
 * Exceção específica para erros de banco de dados
 * 
 * Utilizada para encapsular erros internos e evitar vazamento de informações sensíveis
 */
class DatabaseException extends \Exception
{
    /**
     * Código de erro genérico para erros de banco de dados
     */
    private const DEFAULT_ERROR_CODE = 10000;
    
    /**
     * Construtor da exceção
     * 
     * @param string $message Mensagem de erro (segura para exibição ao usuário)
     * @param int $code Código de erro (opcional)
     * @param \Throwable|null $previous Exceção anterior que causou esta exceção
     */
    public function __construct(
        string $message,
        int $code = 0,
        ?\Throwable $previous = null
    ) {
        // Garantir um código de erro genérico se nenhum for fornecido
        $code = $code === 0 ? self::DEFAULT_ERROR_CODE : $code;
        
        // Certificar que a mensagem seja adequada para o usuário final
        $sanitizedMessage = $this->sanitizeMessage($message);
        
        parent::__construct($sanitizedMessage, $code, $previous);
    }
    
    /**
     * Sanitiza a mensagem de erro para remover detalhes sensíveis
     * 
     * @param string $message Mensagem original
     * @return string Mensagem sanitizada
     */
    private function sanitizeMessage(string $message): string
    {
        // Lista de padrões sensíveis que devem ser substituídos
        $patterns = [
            // Credenciais em strings de conexão
            '/mysql:host=([^;]+);/i' => 'mysql:host=REDACTED;',
            '/user=[^;]+/i' => 'user=REDACTED',
            '/password=[^;]+/i' => 'password=REDACTED',
            
            // Erros de SQL com detalhes de implementação
            '/SQL error: .*/i' => 'Erro de banco de dados',
            '/Table \'([^\']+)\' doesn\'t exist/' => 'Tabela não encontrada',
            '/column \'([^\']+)\' .* exist/' => 'Problema com estrutura do banco de dados',
            
            // Remover caminhos de arquivos e números de linha
            '/ in \/([^:]+):(\d+)/' => '',
            '/at line (\d+)/' => ''
        ];
        
        // Aplicar substituições
        $sanitized = preg_replace(
            array_keys($patterns),
            array_values($patterns),
            $message
        );
        
        // Mensagem de fallback se a sanitização removeu tudo importante
        if (empty(trim($sanitized)) || $sanitized === $message) {
            return 'Ocorreu um erro no banco de dados';
        }
        
        return $sanitized;
    }
}
