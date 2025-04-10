<?php

namespace App\Lib\Security;

/**
 * Validador de entrada robusto
 * 
 * Esta classe implementa validação rigorosa de diversos tipos de entrada
 * para prevenir injeção de dados maliciosos.
 */
class InputValidator
{
    /** @var string Última mensagem de erro */
    private static $lastError = '';
    
    /**
     * Tipos de validação suportados
     */
    public const TYPE_INT = 'int';
    public const TYPE_FLOAT = 'float';
    public const TYPE_STRING = 'string';
    public const TYPE_EMAIL = 'email';
    public const TYPE_URL = 'url';
    public const TYPE_DATE = 'date';
    public const TYPE_BOOL = 'bool';
    public const TYPE_ALPHANUM = 'alphanum';
    public const TYPE_USERNAME = 'username';
    public const TYPE_PASSWORD = 'password';
    public const TYPE_UPLOAD = 'upload';
    public const TYPE_JSON = 'json';
    
    /**
     * Valida um valor de acordo com o tipo especificado
     * 
     * @param mixed $value Valor a ser validado
     * @param string $type Tipo de validação
     * @param array $options Opções de validação adicionais
     * @return mixed Valor validado ou null se inválido
     */
    public static function validate($value, string $type, array $options = [])
    {
        self::$lastError = '';
        
        // Verificar valores vazios
        if ($value === null || $value === '') {
            if (!empty($options['required'])) {
                self::$lastError = 'Campo obrigatório';
                return null;
            }
            
            // Valor vazio mas não obrigatório
            return $value;
        }
        
        // Validar com base no tipo
        switch ($type) {
            case self::TYPE_INT:
                return self::validateInt($value, $options);
                
            case self::TYPE_FLOAT:
                return self::validateFloat($value, $options);
                
            case self::TYPE_STRING:
                return self::validateString($value, $options);
                
            case self::TYPE_EMAIL:
                return self::validateEmail($value, $options);
                
            case self::TYPE_URL:
                return self::validateUrl($value, $options);
                
            case self::TYPE_DATE:
                return self::validateDate($value, $options);
                
            case self::TYPE_BOOL:
                return self::validateBool($value);
                
            case self::TYPE_ALPHANUM:
                return self::validateAlphanum($value, $options);
                
            case self::TYPE_USERNAME:
                return self::validateUsername($value, $options);
                
            case self::TYPE_PASSWORD:
                return self::validatePassword($value, $options);
                
            case self::TYPE_JSON:
                return self::validateJson($value);
                
            default:
                self::$lastError = 'Tipo de validação inválido';
                return null;
        }
    }
    
    /**
     * Valida e filtra um valor inteiro
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções (min, max)
     * @return int|null Valor filtrado ou null se inválido
     */
    private static function validateInt($value, array $options): ?int
    {
        // Converter para inteiro e verificar se é válido
        $filtered = filter_var($value, FILTER_VALIDATE_INT);
        
        if ($filtered === false) {
            self::$lastError = 'Valor deve ser um número inteiro';
            return null;
        }
        
        // Verificar min/max
        if (isset($options['min']) && $filtered < $options['min']) {
            self::$lastError = "Valor mínimo é {$options['min']}";
            return null;
        }
        
        if (isset($options['max']) && $filtered > $options['max']) {
            self::$lastError = "Valor máximo é {$options['max']}";
            return null;
        }
        
        return $filtered;
    }
    
    /**
     * Valida e filtra um valor decimal
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções (min, max)
     * @return float|null Valor filtrado ou null se inválido
     */
    private static function validateFloat($value, array $options): ?float
    {
        // Normalizar: aceitar vírgula ou ponto como separador decimal
        if (is_string($value)) {
            $value = str_replace(',', '.', $value);
        }
        
        // Converter para float e verificar se é válido
        $filtered = filter_var($value, FILTER_VALIDATE_FLOAT);
        
        if ($filtered === false) {
            self::$lastError = 'Valor deve ser um número decimal';
            return null;
        }
        
        // Verificar min/max
        if (isset($options['min']) && $filtered < $options['min']) {
            self::$lastError = "Valor mínimo é {$options['min']}";
            return null;
        }
        
        if (isset($options['max']) && $filtered > $options['max']) {
            self::$lastError = "Valor máximo é {$options['max']}";
            return null;
        }
        
        return $filtered;
    }
    
    /**
     * Valida e filtra uma string
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções (minLength, maxLength)
     * @return string|null Valor filtrado ou null se inválido
     */
    private static function validateString($value, array $options): ?string
    {
        if (!is_string($value) && !is_numeric($value)) {
            self::$lastError = 'Valor deve ser texto';
            return null;
        }
        
        $value = (string)$value;
        
        // Verificar comprimento
        $length = mb_strlen($value, 'UTF-8');
        
        if (isset($options['minLength']) && $length < $options['minLength']) {
            self::$lastError = "Texto deve ter pelo menos {$options['minLength']} caracteres";
            return null;
        }
        
        if (isset($options['maxLength']) && $length > $options['maxLength']) {
            self::$lastError = "Texto não pode exceder {$options['maxLength']} caracteres";
            return null;
        }
        
        // Verificar regex personalizado
        if (isset($options['pattern']) && !preg_match($options['pattern'], $value)) {
            self::$lastError = $options['patternError'] ?? 'Formato de texto inválido';
            return null;
        }
        
        return $value;
    }
    
    /**
     * Valida e filtra um email
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções adicionais
     * @return string|null Email validado ou null se inválido
     */
    private static function validateEmail($value, array $options): ?string
    {
        if (!is_string($value)) {
            self::$lastError = 'Email deve ser texto';
            return null;
        }
        
        $email = filter_var($value, FILTER_VALIDATE_EMAIL);
        
        if ($email === false) {
            self::$lastError = 'Email inválido';
            return null;
        }
        
        // Verificar domínios proibidos (opcional)
        if (!empty($options['blockedDomains']) && is_array($options['blockedDomains'])) {
            $domain = substr(strrchr($email, "@"), 1);
            
            if (in_array($domain, $options['blockedDomains'], true)) {
                self::$lastError = 'Este provedor de email não é permitido';
                return null;
            }
        }
        
        return $email;
    }
    
    /**
     * Valida e filtra uma URL
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções adicionais
     * @return string|null URL validada ou null se inválida
     */
    private static function validateUrl($value, array $options): ?string
    {
        if (!is_string($value)) {
            self::$lastError = 'URL deve ser texto';
            return null;
        }
        
        $url = filter_var($value, FILTER_VALIDATE_URL);
        
        if ($url === false) {
            self::$lastError = 'URL inválida';
            return null;
        }
        
        // Verificar esquemas permitidos
        if (!empty($options['schemes']) && is_array($options['schemes'])) {
            $scheme = parse_url($url, PHP_URL_SCHEME);
            
            if (!in_array($scheme, $options['schemes'], true)) {
                $allowedSchemes = implode(', ', $options['schemes']);
                self::$lastError = "Esquema de URL não permitido. Use: $allowedSchemes";
                return null;
            }
        }
        
        return $url;
    }
    
    /**
     * Valida e filtra uma data
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções (format, min, max)
     * @return string|null Data validada ou null se inválida
     */
    private static function validateDate($value, array $options): ?string
    {
        if (!is_string($value) && !is_numeric($value)) {
            self::$lastError = 'Data deve ser texto';
            return null;
        }
        
        $format = $options['format'] ?? 'Y-m-d';
        
        // Criar objeto DateTime
        $date = \DateTime::createFromFormat($format, (string)$value);
        
        if ($date === false) {
            self::$lastError = "Data inválida. Use o formato: $format";
            return null;
        }
        
        // Verificação adicional para garantir que a data é válida
        $errors = \DateTime::getLastErrors();
        if ($errors['warning_count'] > 0 || $errors['error_count'] > 0) {
            self::$lastError = 'Data inválida';
            return null;
        }
        
        // Verificar data mínima
        if (!empty($options['min'])) {
            $minDate = \DateTime::createFromFormat($format, $options['min']);
            if ($date < $minDate) {
                self::$lastError = "Data deve ser após {$options['min']}";
                return null;
            }
        }
        
        // Verificar data máxima
        if (!empty($options['max'])) {
            $maxDate = \DateTime::createFromFormat($format, $options['max']);
            if ($date > $maxDate) {
                self::$lastError = "Data deve ser antes de {$options['max']}";
                return null;
            }
        }
        
        // Retornar data no formato original
        return $date->format($format);
    }
    
    /**
     * Valida e filtra um valor booleano
     * 
     * @param mixed $value Valor a validar
     * @return bool Valor booleano
     */
    private static function validateBool($value): bool
    {
        return filter_var($value, FILTER_VALIDATE_BOOLEAN);
    }
    
    /**
     * Valida e filtra um valor alfanumérico
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções adicionais
     * @return string|null Valor validado ou null se inválido
     */
    private static function validateAlphanum($value, array $options): ?string
    {
        if (!is_string($value) && !is_numeric($value)) {
            self::$lastError = 'Valor deve ser texto';
            return null;
        }
        
        $value = (string)$value;
        
        // Verificar se contém apenas caracteres alfanuméricos
        if (!ctype_alnum($value)) {
            self::$lastError = 'Valor deve conter apenas letras e números';
            return null;
        }
        
        // Verificar comprimento
        return self::validateString($value, $options);
    }
    
    /**
     * Valida e filtra um nome de usuário
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções adicionais
     * @return string|null Nome de usuário validado ou null se inválido
     */
    private static function validateUsername($value, array $options): ?string
    {
        if (!is_string($value)) {
            self::$lastError = 'Nome de usuário deve ser texto';
            return null;
        }
        
        // Verificar caracteres permitidos (letras, números, underscore, hífen)
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $value)) {
            self::$lastError = 'Nome de usuário pode conter apenas letras, números, underscore e hífen';
            return null;
        }
        
        // Verificar comprimento
        $options['minLength'] = $options['minLength'] ?? 3;
        $options['maxLength'] = $options['maxLength'] ?? 30;
        
        return self::validateString($value, $options);
    }
    
    /**
     * Valida e filtra uma senha
     * 
     * @param mixed $value Valor a validar
     * @param array $options Opções adicionais
     * @return string|null Senha validada ou null se inválida
     */
    private static function validatePassword($value, array $options): ?string
    {
        if (!is_string($value)) {
            self::$lastError = 'Senha deve ser texto';
            return null;
        }
        
        // Verificar comprimento
        $options['minLength'] = $options['minLength'] ?? 8;
        $options['maxLength'] = $options['maxLength'] ?? 100;
        
        $length = mb_strlen($value, 'UTF-8');
        
        if ($length < $options['minLength']) {
            self::$lastError = "Senha deve ter pelo menos {$options['minLength']} caracteres";
            return null;
        }
        
        if ($length > $options['maxLength']) {
            self::$lastError = "Senha não pode exceder {$options['maxLength']} caracteres";
            return null;
        }
        
        // Verificar requisitos de complexidade
        $strength = $options['strength'] ?? 'medium';
        
        switch ($strength) {
            case 'high':
                // Exigir letras maiúsculas, minúsculas, números e símbolos
                if (!preg_match('/[A-Z]/', $value) || 
                    !preg_match('/[a-z]/', $value) || 
                    !preg_match('/[0-9]/', $value) || 
                    !preg_match('/[^A-Za-z0-9]/', $value)) {
                    self::$lastError = 'Senha deve conter letras maiúsculas, minúsculas, números e símbolos';
                    return null;
                }
                break;
                
            case 'medium':
                // Exigir pelo menos 3 dos 4 tipos: maiúsculas, minúsculas, números e símbolos
                $score = 0;
                if (preg_match('/[A-Z]/', $value)) {
                    $score++;
                }
                if (preg_match('/[a-z]/', $value)) {
                    $score++;
                }
                if (preg_match('/[0-9]/', $value)) {
                    $score++;
                }
                if (preg_match('/[^A-Za-z0-9]/', $value)) {
                    $score++;
                }
                
                if ($score < 3) {
                    self::$lastError = 'Senha deve conter pelo menos 3 dos seguintes: letras maiúsculas, letras minúsculas, números e símbolos';
                    return null;
                }
                break;
                
            case 'low':
                // Exigir pelo menos 2 tipos
                $score = 0;
                if (preg_match('/[A-Z]/', $value)) {
                    $score++;
                }
                if (preg_match('/[a-z]/', $value)) {
                    $score++;
                }
                if (preg_match('/[0-9]/', $value)) {
                    $score++;
                }
                if (preg_match('/[^A-Za-z0-9]/', $value)) {
                    $score++;
                }
                
                if ($score < 2) {
                    self::$lastError = 'Senha deve conter pelo menos 2 dos seguintes: letras maiúsculas, letras minúsculas, números e símbolos';
                    return null;
                }
                break;
        }
        
        return $value;
    }
    
    /**
     * Valida e filtra um JSON
     * 
     * @param mixed $value Valor a validar
     * @return array|null Dados JSON decodificados ou null se inválido
     */
    private static function validateJson($value): ?array
    {
        if (!is_string($value)) {
            self::$lastError = 'JSON deve ser texto';
            return null;
        }
        
        $data = json_decode($value, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            self::$lastError = 'JSON inválido: ' . json_last_error_msg();
            return null;
        }
        
        if (!is_array($data)) {
            self::$lastError = 'JSON deve decodificar para um array';
            return null;
        }
        
        return $data;
    }
    
    /**
     * Obtém a última mensagem de erro
     * 
     * @return string Mensagem de erro
     */
    public static function getLastError(): string
    {
        return self::$lastError;
    }
}
