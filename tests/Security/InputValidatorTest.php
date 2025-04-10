<?php

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use App\Lib\Security\InputValidator;
use App\Lib\Security\ValidationResult;

/**
 * Testes unitários para o componente InputValidator
 */
class InputValidatorTest extends TestCase
{
    /** @var InputValidator Instância do validador para testes */
    private InputValidator $validator;
    
    /**
     * Configuração inicial para cada teste
     */
    protected function setUp(): void
    {
        $this->validator = new InputValidator();
    }
    
    /**
     * Testa validação básica de tipos
     */
    public function testBasicTypeValidation(): void
    {
        // Teste de validação de inteiro
        $intResult = $this->validator->validate('age', '25', InputValidator::TYPE_INT);
        $this->assertTrue($intResult->isValid());
        $this->assertSame(25, $intResult->getValue());
        
        // Teste de validação de float
        $floatResult = $this->validator->validate('price', '19.99', InputValidator::TYPE_FLOAT);
        $this->assertTrue($floatResult->isValid());
        $this->assertSame(19.99, $floatResult->getValue());
        
        // Teste de validação de string
        $stringResult = $this->validator->validate('name', 'John Doe', InputValidator::TYPE_STRING);
        $this->assertTrue($stringResult->isValid());
        $this->assertSame('John Doe', $stringResult->getValue());
        
        // Teste de validação de boolean
        $boolResult = $this->validator->validate('active', '1', InputValidator::TYPE_BOOL);
        $this->assertTrue($boolResult->isValid());
        $this->assertSame(true, $boolResult->getValue());
    }
    
    /**
     * Testa validação de email
     */
    public function testEmailValidation(): void
    {
        // Email válido
        $validResult = $this->validator->validate('email', 'user@example.com', InputValidator::TYPE_EMAIL);
        $this->assertTrue($validResult->isValid());
        $this->assertSame('user@example.com', $validResult->getValue());
        
        // Email inválido
        $invalidResult = $this->validator->validate('email', 'invalid-email', InputValidator::TYPE_EMAIL);
        $this->assertFalse($invalidResult->isValid());
        $this->assertNull($invalidResult->getValue());
    }
    
    /**
     * Testa validação de URL
     */
    public function testUrlValidation(): void
    {
        // URL válida
        $validResult = $this->validator->validate('website', 'https://example.com', InputValidator::TYPE_URL);
        $this->assertTrue($validResult->isValid());
        $this->assertSame('https://example.com', $validResult->getValue());
        
        // URL inválida
        $invalidResult = $this->validator->validate('website', 'not a url', InputValidator::TYPE_URL);
        $this->assertFalse($invalidResult->isValid());
        $this->assertNull($invalidResult->getValue());
    }
    
    /**
     * Testa validação de data
     */
    public function testDateValidation(): void
    {
        // Data válida
        $validResult = $this->validator->validate('birthdate', '2000-01-01', InputValidator::TYPE_DATE);
        $this->assertTrue($validResult->isValid());
        $this->assertInstanceOf(\DateTime::class, $validResult->getValue());
        
        // Data inválida
        $invalidResult = $this->validator->validate('birthdate', '2000-13-01', InputValidator::TYPE_DATE);
        $this->assertFalse($invalidResult->isValid());
        $this->assertNull($invalidResult->getValue());
    }
    
    /**
     * Testa validação de array
     */
    public function testArrayValidation(): void
    {
        // Array válido
        $validResult = $this->validator->validate('items', ['a', 'b', 'c'], InputValidator::TYPE_ARRAY);
        $this->assertTrue($validResult->isValid());
        $this->assertSame(['a', 'b', 'c'], $validResult->getValue());
        
        // Não-array
        $invalidResult = $this->validator->validate('items', 'not an array', InputValidator::TYPE_ARRAY);
        $this->assertFalse($invalidResult->isValid());
        $this->assertNull($invalidResult->getValue());
    }
    
    /**
     * Testa validação de campo obrigatório
     */
    public function testRequiredValidation(): void
    {
        // Campo obrigatório presente
        $validResult = $this->validator->validate('name', 'John', InputValidator::TYPE_STRING, ['required' => true]);
        $this->assertTrue($validResult->isValid());
        
        // Campo obrigatório ausente
        $invalidResult = $this->validator->validate('name', '', InputValidator::TYPE_STRING, ['required' => true]);
        $this->assertFalse($invalidResult->isValid());
        $this->assertStringContainsString('obrigatório', $invalidResult->getErrorMessage());
        
        // Campo não obrigatório ausente
        $optionalResult = $this->validator->validate('name', '', InputValidator::TYPE_STRING, ['required' => false]);
        $this->assertTrue($optionalResult->isValid());
    }
    
    /**
     * Testa regras de validação numérica
     */
    public function testNumericRules(): void
    {
        // Validação de valor mínimo
        $minValidResult = $this->validator->validate('age', 18, InputValidator::TYPE_INT, ['min' => 18]);
        $this->assertTrue($minValidResult->isValid());
        
        $minInvalidResult = $this->validator->validate('age', 17, InputValidator::TYPE_INT, ['min' => 18]);
        $this->assertFalse($minInvalidResult->isValid());
        
        // Validação de valor máximo
        $maxValidResult = $this->validator->validate('age', 65, InputValidator::TYPE_INT, ['max' => 65]);
        $this->assertTrue($maxValidResult->isValid());
        
        $maxInvalidResult = $this->validator->validate('age', 66, InputValidator::TYPE_INT, ['max' => 65]);
        $this->assertFalse($maxInvalidResult->isValid());
        
        // Validação de intervalo
        $rangeValidResult = $this->validator->validate('age', 30, InputValidator::TYPE_INT, ['min' => 18, 'max' => 65]);
        $this->assertTrue($rangeValidResult->isValid());
    }
    
    /**
     * Testa regras de validação de string
     */
    public function testStringRules(): void
    {
        // Validação de comprimento mínimo
        $minLengthValidResult = $this->validator->validate('password', 'secret123', InputValidator::TYPE_STRING, ['minLength' => 8]);
        $this->assertTrue($minLengthValidResult->isValid());
        
        $minLengthInvalidResult = $this->validator->validate('password', 'short', InputValidator::TYPE_STRING, ['minLength' => 8]);
        $this->assertFalse($minLengthInvalidResult->isValid());
        
        // Validação de comprimento máximo
        $maxLengthValidResult = $this->validator->validate('username', 'john', InputValidator::TYPE_STRING, ['maxLength' => 10]);
        $this->assertTrue($maxLengthValidResult->isValid());
        
        $maxLengthInvalidResult = $this->validator->validate('username', 'johndoeverylong', InputValidator::TYPE_STRING, ['maxLength' => 10]);
        $this->assertFalse($maxLengthInvalidResult->isValid());
    }
    
    /**
     * Testa validação de valores permitidos
     */
    public function testAllowedValues(): void
    {
        // Valor na lista de permitidos
        $validResult = $this->validator->validate('status', 'active', InputValidator::TYPE_STRING, ['allowedValues' => ['active', 'inactive', 'pending']]);
        $this->assertTrue($validResult->isValid());
        
        // Valor fora da lista de permitidos
        $invalidResult = $this->validator->validate('status', 'deleted', InputValidator::TYPE_STRING, ['allowedValues' => ['active', 'inactive', 'pending']]);
        $this->assertFalse($invalidResult->isValid());
    }
    
    /**
     * Testa o comportamento da classe ValidationResult
     */
    public function testValidationResult(): void
    {
        // Resultado válido
        $validResult = new ValidationResult(true, 'test-value');
        $this->assertTrue($validResult->isValid());
        $this->assertEquals('test-value', $validResult->getValue());
        $this->assertNull($validResult->getErrorMessage());
        
        // Resultado inválido
        $invalidResult = new ValidationResult(false, null, 'Test error message');
        $this->assertFalse($invalidResult->isValid());
        $this->assertNull($invalidResult->getValue());
        $this->assertEquals('Test error message', $invalidResult->getErrorMessage());
    }
}
