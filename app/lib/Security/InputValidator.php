<?php

namespace App\Lib\Security;

/**
 * Validador centralizado de entrada com suporte a tipos e regras
 */
class InputValidator
{
    // Constantes de tipo
    public const TYPE_INT = 'int';
    public const TYPE_FLOAT = 'float';
    public const TYPE_STRING = 'string';
    public const TYPE_BOOL = 'bool';
    public const TYPE_EMAIL = 'email';
    public const TYPE_URL = 'url';
    public const TYPE_DATE = 'date';
    public const TYPE_ARRAY = 'array';
    public const TYPE_JSON = 'json';
    public const TYPE_FILE = 'file';
    
    /**
     * Valida um valor de acordo com tipo e regras específicas
     * 
     * @param string $name Nome do parâmetro
     * @param mixed $value Valor a ser validado
     * @param string $type Tipo esperado
     * @param array<string, mixed> $rules Regras adicionais
     * @return ValidationResult Resultado da validação
     */
    public function validate(string $name, mixed $value, string $type, array $rules = []): ValidationResult
    {
        // Verificar se é obrigatório
        $isRequired = $rules['required'] ?? false;
        if ($isRequired && ($value === null || $value === '')) {
            return new ValidationResult(false, null, "O campo '{$name}' é obrigatório");
        }
        
        // Se não for obrigatório e estiver vazio, retornar válido
        if (!$isRequired && ($value === null || $value === '')) {
            return new ValidationResult(true, null);
        }
        
        // Validar tipo e converter valor
        $validatedValue = $this->validateType($value, $type);
        if ($validatedValue === null) {
            return new ValidationResult(false, null, "O campo '{$name}' deve ser do tipo {$type}");
        }
        
        // Aplicar regras específicas
        $ruleResult = $this->applyRules($validatedValue, $type, $rules);
        if (!$ruleResult->isValid()) {
            return new ValidationResult(false, null, "O campo '{$name}': " . $ruleResult->getErrorMessage());
        }
        
        return new ValidationResult(true, $validatedValue);
    }
    
    /**
     * Valida e converte um valor para o tipo especificado
     * 
     * @param mixed $value Valor a ser validado
     * @param string $type Tipo esperado
     * @return mixed Valor convertido ou null se inválido
     */
    private function validateType(mixed $value, string $type): mixed
    {
        switch ($type) {
            case self::TYPE_INT:
                if (is_numeric($value) && (string)(int)$value === (string)$value) {
                    return (int)$value;
                }
                return null;
                
            case self::TYPE_FLOAT:
                if (is_numeric($value)) {
                    return (float)$value;
                }
                return null;
                
            case self::TYPE_STRING:
                if (is_string($value) || is_numeric($value)) {
                    return (string)$value;
                }
                return null;
                
            case self::TYPE_BOOL:
                if (is_bool($value) || $value === 0 || $value === 1 || $value === '0' || $value === '1') {
                    return (bool)$value;
                }
                return null;
                
            case self::TYPE_EMAIL:
                $value = (string)$value;
                if (filter_var($value, FILTER_VALIDATE_EMAIL)) {
                    return $value;
                }
                return null;
                
            case self::TYPE_URL:
                $value = (string)$value;
                if (filter_var($value, FILTER_VALIDATE_URL)) {
                    return $value;
                }
                return null;
                
            case self::TYPE_DATE:
                $value = (string)$value;
                $date = \DateTime::createFromFormat('Y-m-d', $value);
                if ($date && $date->format('Y-m-d') === $value) {
                    return $date;
                }
                return null;
                
            case self::TYPE_ARRAY:
                if (is_array($value)) {
                    return $value;
                }
                return null;
                
            case self::TYPE_JSON:
                if (is_string($value)) {
                    $decoded = json_decode($value, true);
                    if (json_last_error() === JSON_ERROR_NONE) {
                        return $decoded;
                    }
                }
                return null;
                
            default:
                return $value;
        }
    }
    
    /**
     * Aplica regras específicas ao valor validado
     * 
     * @param mixed $value Valor já validado por tipo
     * @param string $type Tipo do valor
     * @param array<string, mixed> $rules Regras a aplicar
     * @return ValidationResult Resultado da validação
     */
    private function applyRules(mixed $value, string $type, array $rules): ValidationResult
    {
        // Regras para números (int/float)
        if (in_array($type, [self::TYPE_INT, self::TYPE_FLOAT])) {
            // Verificar valor mínimo
            if (isset($rules['min']) && $value < $rules['min']) {
                return new ValidationResult(false, null, "deve ser maior ou igual a {$rules['min']}");
            }
            
            // Verificar valor máximo
            if (isset($rules['max']) && $value > $rules['max']) {
                return new ValidationResult(false, null, "deve ser menor ou igual a {$rules['max']}");
            }
        }
        
        // Regras para strings
        if ($type === self::TYPE_STRING) {
            // Verificar comprimento mínimo
            if (isset($rules['minLength']) && mb_strlen($value) < $rules['minLength']) {
                return new ValidationResult(false, null, "deve ter pelo menos {$rules['minLength']} caracteres");
            }
            
            // Verificar comprimento máximo
            if (isset($rules['maxLength']) && mb_strlen($value) > $rules['maxLength']) {
                return new ValidationResult(false, null, "deve ter no máximo {$rules['maxLength']} caracteres");
            }
            
            // Verificar regex
            if (isset($rules['pattern']) && !preg_match($rules['pattern'], $value)) {
                return new ValidationResult(false, null, "formato inválido");
            }
        }
        
        // Regras para arrays
        if ($type === self::TYPE_ARRAY) {
            // Verificar tamanho mínimo
            if (isset($rules['minSize']) && count($value) < $rules['minSize']) {
                return new ValidationResult(false, null, "deve conter pelo menos {$rules['minSize']} itens");
            }
            
            // Verificar tamanho máximo
            if (isset($rules['maxSize']) && count($value) > $rules['maxSize']) {
                return new ValidationResult(false, null, "deve conter no máximo {$rules['maxSize']} itens");
            }
        }
        
        // Regra de valores permitidos
        if (isset($rules['allowedValues']) && is_array($rules['allowedValues'])) {
            if (!in_array($value, $rules['allowedValues'], true)) {
                $allowedStr = implode(', ', $rules['allowedValues']);
                return new ValidationResult(false, null, "deve ser um dos seguintes valores: {$allowedStr}");
            }
        }
        
        return new ValidationResult(true, $value);
    }
}

/**
 * Classe para armazenar o resultado de uma validação
 */
class ValidationResult
{
    /**
     * @param bool $valid Indica se a validação foi bem-sucedida
     * @param mixed $value Valor validado (null se inválido)
     * @param string|null $errorMessage Mensagem de erro se inválido
     */
    public function __construct(
        private bool $valid,
        private mixed $value,
        private ?string $errorMessage = null
    ) {
    }
    
    /**
     * Verifica se a validação foi bem-sucedida
     * 
     * @return bool True se válido
     */
    public function isValid(): bool
    {
        return $this->valid;
    }
    
    /**
     * Retorna o valor validado
     * 
     * @return mixed Valor validado ou null se inválido
     */
    public function getValue(): mixed
    {
        return $this->value;
    }
    
    /**
     * Retorna a mensagem de erro
     * 
     * @return string|null Mensagem de erro ou null se válido
     */
    public function getErrorMessage(): ?string
    {
        return $this->errorMessage;
    }
}
