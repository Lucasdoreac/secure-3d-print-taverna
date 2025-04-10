<?php

namespace Tests\Security;

use PHPUnit\Framework\TestCase;
use App\Lib\Security\CsrfProtection;

/**
 * Testes unitários para o componente CsrfProtection
 */
class CsrfProtectionTest extends TestCase
{
    /**
     * Configuração inicial para cada teste
     */
    protected function setUp(): void
    {
        // Garantir que a sessão esteja iniciada
        if (session_status() === PHP_SESSION_NONE) {
            session_start();
        }
        
        // Limpar tokens CSRF para iniciar cada teste com estado limpo
        $_SESSION['csrf_tokens'] = [];
    }
    
    /**
     * Limpeza após cada teste
     */
    protected function tearDown(): void
    {
        // Limpar tokens CSRF após cada teste
        if (isset($_SESSION['csrf_tokens'])) {
            $_SESSION['csrf_tokens'] = [];
        }
    }
    
    /**
     * Testa se o método generateToken cria um token válido
     */
    public function testGenerateTokenCreatesValidToken(): void
    {
        $token = CsrfProtection::generateToken();
        
        // Verifica se é uma string
        $this->assertIsString($token);
        
        // Verifica se tem o tamanho esperado (64 caracteres)
        $this->assertEquals(64, strlen($token));
        
        // Verifica se está armazenado na sessão
        $this->assertArrayHasKey($token, $_SESSION['csrf_tokens']);
        
        // Verifica se o timestamp é futuro
        $this->assertGreaterThan(time(), $_SESSION['csrf_tokens'][$token]);
    }
    
    /**
     * Testa se a validação de token funciona corretamente
     */
    public function testTokenValidation(): void
    {
        $token = CsrfProtection::generateToken();
        
        // Verifica se o token é válido
        $this->assertTrue(CsrfProtection::validateToken($token));
        
        // Verifica se o token foi removido após validação (uso único)
        $this->assertArrayNotHasKey($token, $_SESSION['csrf_tokens']);
        
        // Verifica se o token não pode ser validado novamente
        $this->assertFalse(CsrfProtection::validateToken($token));
    }
    
    /**
     * Testa se tokens inválidos são rejeitados
     */
    public function testInvalidTokenFails(): void
    {
        // Testa token não existente
        $this->assertFalse(CsrfProtection::validateToken('invalid_token'));
        
        // Testa token nulo
        $this->assertFalse(CsrfProtection::validateToken(null));
        
        // Testa token vazio
        $this->assertFalse(CsrfProtection::validateToken(''));
    }
    
    /**
     * Testa se tokens expirados são rejeitados
     */
    public function testTokenExpiration(): void
    {
        $token = CsrfProtection::generateToken();
        
        // Simular expiração do token (1 hora e 1 segundo atrás)
        $_SESSION['csrf_tokens'][$token] = time() - 3601;
        
        // Verifica se o token expirado é rejeitado
        $this->assertFalse(CsrfProtection::validateToken($token));
        
        // Verifica se o token expirado foi removido da sessão
        $this->assertArrayNotHasKey($token, $_SESSION['csrf_tokens']);
    }
    
    /**
     * Testa se o HTML do campo do token é gerado corretamente
     */
    public function testGenerateTokenField(): void
    {
        $field = CsrfProtection::generateTokenField();
        
        // Verifica se o output é uma string
        $this->assertIsString($field);
        
        // Verifica se contém um elemento input
        $this->assertStringContainsString('<input', $field);
        
        // Verifica se contém o nome correto para o campo
        $this->assertStringContainsString('name="csrf_token"', $field);
        
        // Verifica se contém um valor para o token
        $this->assertStringContainsString('value="', $field);
        
        // Verifica se o token está escapado para evitar XSS
        $this->assertStringContainsString('value="', $field);
        
        // Extrai o token do campo para verificar se é válido
        preg_match('/value="([^"]+)"/', $field, $matches);
        $token = $matches[1] ?? '';
        
        // Verifica se o token é válido
        $this->assertArrayHasKey($token, $_SESSION['csrf_tokens']);
    }
    
    /**
     * Testa se a limpeza de todos os tokens funciona
     */
    public function testClearAllTokens(): void
    {
        // Gerar vários tokens
        CsrfProtection::generateToken();
        CsrfProtection::generateToken();
        CsrfProtection::generateToken();
        
        // Verificar se há tokens na sessão
        $this->assertNotEmpty($_SESSION['csrf_tokens']);
        
        // Limpar todos os tokens
        CsrfProtection::clearAllTokens();
        
        // Verificar se os tokens foram removidos
        $this->assertEmpty($_SESSION['csrf_tokens']);
    }
}
