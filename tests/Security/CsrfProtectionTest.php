<?php

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use App\Lib\Security\CsrfProtection;

class CsrfProtectionTest extends TestCase
{
    protected function setUp(): void
    {
        // Inicializar sessão para testes
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Limpar tokens anteriores
        $_SESSION['csrf_tokens'] = [];
    }
    
    protected function tearDown(): void
    {
        // Limpar após testes
        $_SESSION['csrf_tokens'] = [];
    }
    
    public function testGenerateTokenCreatesValidTokens(): void
    {
        $token = CsrfProtection::generateToken();
        
        $this->assertIsString($token);
        $this->assertEquals(64, strlen($token));
        $this->assertArrayHasKey($token, $_SESSION['csrf_tokens']);
    }
    
    public function testValidateTokenReturnsTrue(): void
    {
        $token = CsrfProtection::generateToken();
        
        $this->assertTrue(CsrfProtection::validateToken($token));
    }
    
    public function testValidateTokenReturnsFalseForInvalidToken(): void
    {
        // Token inválido (não gerado)
        $this->assertFalse(CsrfProtection::validateToken('invalid_token_123456789'));
    }
    
    public function testTokenCanOnlyBeUsedOnce(): void
    {
        $token = CsrfProtection::generateToken();
        
        // Primeira validação deve passar
        $this->assertTrue(CsrfProtection::validateToken($token));
        
        // Segunda validação deve falhar (token já usado)
        $this->assertFalse(CsrfProtection::validateToken($token));
    }
    
    public function testTokenExpiresAfterTimeout(): void
    {
        $token = CsrfProtection::generateToken();
        
        // Simular token expirado definindo timestamp para 2 horas atrás
        $_SESSION['csrf_tokens'][$token] = time() - 7200;
        
        $this->assertFalse(CsrfProtection::validateToken($token));
    }
    
    public function testMultipleTokenGeneration(): void
    {
        $token1 = CsrfProtection::generateToken();
        $token2 = CsrfProtection::generateToken();
        $token3 = CsrfProtection::generateToken();
        
        $this->assertNotEquals($token1, $token2);
        $this->assertNotEquals($token2, $token3);
        $this->assertNotEquals($token1, $token3);
        
        $this->assertTrue(CsrfProtection::validateToken($token1));
        $this->assertTrue(CsrfProtection::validateToken($token2));
        $this->assertTrue(CsrfProtection::validateToken($token3));
    }
}
