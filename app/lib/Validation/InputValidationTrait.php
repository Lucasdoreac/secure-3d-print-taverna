<?php

namespace App\Lib\Validation;

use App\Lib\Security\InputValidator;

/**
 * Trait para fácil integração de validação de entrada em controllers
 * 
 * Facilita a validação de entrada em controllers com métodos
 * para diferentes fontes de dados (GET, POST, FILES)
 */
trait InputValidationTrait {
    /** @var array Erros de validação */
    protected $validationErrors = [];
    
    /**
     * Valida parâmetro da requisição GET
     * 
     * @param string $name Nome do parâmetro
     * @param string $type Tipo esperado
     * @param array $options Opções adicionais
     * @return mixed Valor validado ou null se inválido
     */
    protected function getValidatedParam(string $name, string $type, array $options = []): mixed {
        if (!isset($_GET[$name]) && !empty($options['required'])) {
            $this->validationErrors[$name] = 'Campo obrigatório';
            return null;
        }
        
        $value = $_GET[$name] ?? null;
        
        return $this->validateValue($name, $value, $type, $options);
    }
    
    /**
     * Valida parâmetro da requisição POST
     * 
     * @param string $name Nome do parâmetro
     * @param string $type Tipo esperado
     * @param array $options Opções adicionais
     * @return mixed Valor validado ou null se inválido
     */
    protected function postValidatedParam(string $name, string $type, array $options = []): mixed {
        if (!isset($_POST[$name]) && !empty($options['required'])) {
            $this->validationErrors[$name] = 'Campo obrigatório';
            return null;
        }
        
        $value = $_POST[$name] ?? null;
        
        return $this->validateValue($name, $value, $type, $options);
    }
    
    /**
     * Valida um valor de acordo com o tipo esperado
     * 
     * @param string $name Nome do campo
     * @param mixed $value Valor a validar
     * @param string $type Tipo esperado
     * @param array $options Opções adicionais
     * @return mixed Valor validado ou null se inválido
     */
    protected function validateValue(string $name, mixed $value, string $type, array $options = []): mixed {
        $result = InputValidator::validate($value, $type, $options);
        
        if ($result === null) {
            $this->validationErrors[$name] = InputValidator::getLastError();
        }
        
        return $result;
    }
    
    /**
     * Verifica se houve erros de validação
     * 
     * @return bool True se houver erros
     */
    protected function hasValidationErrors(): bool {
        return !empty($this->validationErrors);
    }
    
    /**
     * Obtém todos os erros de validação
     * 
     * @return array Erros de validação
     */
    protected function getValidationErrors(): array {
        return $this->validationErrors;
    }
}