<?php

namespace App\Lib\Security;

/**
 * Trait para validação robusta de entrada em controladores
 * 
 * Fornece métodos para validação tipada de parâmetros de requisição
 * com suporte a regras personalizáveis e mensagens de erro legíveis.
 */
trait InputValidationTrait
{
    /** @var array<string, string> Mensagens de erro de validação */
    protected array $validationErrors = [];

    /**
     * Valida e retorna um parâmetro GET com tipagem forte
     * 
     * @param string $name Nome do parâmetro
     * @param string $type Tipo esperado (InputValidator::TYPE_*)
     * @param array<string, mixed> $rules Regras adicionais de validação
     * @return mixed Valor validado e convertido para o tipo apropriado
     */
    protected function getValidatedParam(string $name, string $type, array $rules = []): mixed
    {
        $value = $_GET[$name] ?? null;
        return $this->validateParam($name, $value, $type, $rules);
    }
    
    /**
     * Valida e retorna um parâmetro POST com tipagem forte
     * 
     * @param string $name Nome do parâmetro
     * @param string $type Tipo esperado (InputValidator::TYPE_*)
     * @param array<string, mixed> $rules Regras adicionais de validação
     * @return mixed Valor validado e convertido para o tipo apropriado
     */
    protected function postValidatedParam(string $name, string $type, array $rules = []): mixed
    {
        $value = $_POST[$name] ?? null;
        return $this->validateParam($name, $value, $type, $rules);
    }
    
    /**
     * Valida e retorna um valor JSON da requisição com tipagem forte
     * 
     * @param string $name Nome do parâmetro
     * @param string $type Tipo esperado (InputValidator::TYPE_*)
     * @param array<string, mixed> $rules Regras adicionais de validação
     * @return mixed Valor validado e convertido para o tipo apropriado
     */
    protected function jsonValidatedParam(string $name, string $type, array $rules = []): mixed
    {
        $jsonData = $this->getJsonData();
        $value = $jsonData[$name] ?? null;
        return $this->validateParam($name, $value, $type, $rules);
    }
    
    /**
     * Obtém os dados JSON do corpo da requisição
     * 
     * @return array<string, mixed> Dados decodificados
     */
    protected function getJsonData(): array
    {
        $rawInput = file_get_contents('php://input');
        if (empty($rawInput)) {
            return [];
        }
        
        $jsonData = json_decode($rawInput, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            return [];
        }
        
        return is_array($jsonData) ? $jsonData : [];
    }
    
    /**
     * Valida um valor de acordo com tipo e regras específicas
     * 
     * @param string $name Nome do parâmetro
     * @param mixed $value Valor a ser validado
     * @param string $type Tipo esperado
     * @param array<string, mixed> $rules Regras adicionais
     * @return mixed Valor validado ou null se inválido
     */
    protected function validateParam(string $name, mixed $value, string $type, array $rules = []): mixed
    {
        $validator = new InputValidator();
        $result = $validator->validate($name, $value, $type, $rules);
        
        if (!$result->isValid()) {
            $this->validationErrors[$name] = $result->getErrorMessage();
            return null;
        }
        
        return $result->getValue();
    }
    
    /**
     * Verifica se existem erros de validação
     * 
     * @return bool True se houver erros
     */
    protected function hasValidationErrors(): bool
    {
        return !empty($this->validationErrors);
    }
    
    /**
     * Retorna todos os erros de validação
     * 
     * @return array<string, string> Array de erros [campo => mensagem]
     */
    protected function getValidationErrors(): array
    {
        return $this->validationErrors;
    }
    
    /**
     * Limpa todos os erros de validação
     * 
     * @return void
     */
    protected function clearValidationErrors(): void
    {
        $this->validationErrors = [];
    }
}
