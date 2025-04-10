<?php
namespace Tests\Unit\Models;

use PHPUnit\Framework\TestCase;
use App\Lib\Models\ModelValidator;
use App\Lib\Models\ValidationResult;
use ReflectionClass;
use ReflectionMethod;

class ModelValidatorTest extends TestCase
{
    private ModelValidator $validator;
    private string $fixturesDir;
    private string $tempDir;
    
    protected function setUp(): void
    {
        parent::setUp();
        
        $this->validator = new ModelValidator();
        
        // Diretórios para fixtures e arquivos temporários
        $this->fixturesDir = __DIR__ . '/../../fixtures/models';
        $this->tempDir = __DIR__ . '/../../fixtures/temp';
        
        // Garantir existência dos diretórios
        if (!is_dir($this->fixturesDir)) {
            mkdir($this->fixturesDir, 0755, true);
        }
        
        if (!is_dir($this->tempDir)) {
            mkdir($this->tempDir, 0755, true);
        }
        
        // Criar arquivos de teste
        $this->createTestFiles();
    }
    
    /**
     * Cria arquivos de teste para os diferentes formatos
     */
    private function createTestFiles(): void
    {
        // STL ASCII válido
        $validStlAscii = $this->tempDir . '/test_valid_ascii.stl';
        file_put_contents($validStlAscii, $this->getValidStlAsciiContent());
        
        // STL ASCII inválido (sintaxe incorreta)
        $invalidStlAscii = $this->tempDir . '/test_invalid_ascii.stl';
        file_put_contents($invalidStlAscii, $this->getInvalidStlAsciiContent());
        
        // STL Binário válido
        $validStlBinary = $this->tempDir . '/test_valid_binary.stl';
        file_put_contents($validStlBinary, $this->getValidStlBinaryContent());
        
        // STL Binário inválido (cabeçalho corrompido)
        $invalidStlBinary = $this->tempDir . '/test_invalid_binary.stl';
        file_put_contents($invalidStlBinary, $this->getInvalidStlBinaryContent());
        
        // OBJ válido
        $validObj = $this->tempDir . '/test_valid.obj';
        file_put_contents($validObj, $this->getValidObjContent());
        
        // OBJ inválido
        $invalidObj = $this->tempDir . '/test_invalid.obj';
        file_put_contents($invalidObj, $this->getInvalidObjContent());
        
        // Arquivo não suportado
        $unsupportedFile = $this->tempDir . '/test_unsupported.txt';
        file_put_contents($unsupportedFile, "Este não é um formato de modelo 3D suportado");
        
        // Arquivo vazio
        $emptyFile = $this->tempDir . '/test_empty.stl';
        file_put_contents($emptyFile, "");
        
        // Arquivo com extensão inválida
        $invalidExtension = $this->tempDir . '/test_invalid_extension.xyz';
        file_put_contents($invalidExtension, "Conteúdo com extensão não suportada");
    }
    
    /**
     * Prepara conteúdo ASCII STL válido simplificado
     */
    private function getValidStlAsciiContent(): string
    {
        return "solid test\n" .
               "  facet normal 0 0 1\n" .
               "    outer loop\n" .
               "      vertex 0 0 0\n" .
               "      vertex 1 0 0\n" .
               "      vertex 0 1 0\n" .
               "    endloop\n" .
               "  endfacet\n" .
               "endsolid test\n";
    }
    
    /**
     * Prepara conteúdo ASCII STL inválido
     */
    private function getInvalidStlAsciiContent(): string
    {
        return "solid test\n" .
               "  facet normal 0 0 1\n" .
               "    outer loop\n" .
               "      vertex 0 0\n" . // Coordenada Z ausente
               "      vertex 1 0 0\n" .
               "    endloop\n" . // Falta um vértice
               "  endfacet\n" .
               "endsolid test\n";
    }
    
    /**
     * Prepara conteúdo STL binário válido simplificado
     */
    private function getValidStlBinaryContent(): string
    {
        // Cabeçalho de 80 bytes
        $header = str_pad("Binary STL Test File", 80, "\0");
        
        // 1 triângulo
        $numTriangles = pack("V", 1);
        
        // Um triângulo (normal + 3 vértices + atributos)
        // Normal
        $normal = pack("f*", 0, 0, 1);
        
        // Vértices
        $vertex1 = pack("f*", 0, 0, 0);
        $vertex2 = pack("f*", 1, 0, 0);
        $vertex3 = pack("f*", 0, 1, 0);
        
        // Atributos (geralmente não usado, 2 bytes)
        $attr = pack("v", 0);
        
        return $header . $numTriangles . $normal . $vertex1 . $vertex2 . $vertex3 . $attr;
    }
    
    /**
     * Prepara conteúdo STL binário inválido
     */
    private function getInvalidStlBinaryContent(): string
    {
        // Cabeçalho de 80 bytes
        $header = str_pad("Invalid Binary STL Test File", 80, "\0");
        
        // Número de triângulos inconsistente com o tamanho do arquivo
        $numTriangles = pack("V", 10); // Diz que tem 10 triângulos
        
        // Mas só contém dados para 1 triângulo
        $normal = pack("f*", 0, 0, 1);
        $vertex1 = pack("f*", 0, 0, 0);
        $vertex2 = pack("f*", 1, 0, 0);
        $vertex3 = pack("f*", 0, 1, 0);
        $attr = pack("v", 0);
        
        return $header . $numTriangles . $normal . $vertex1 . $vertex2 . $vertex3 . $attr;
    }
    
    /**
     * Prepara conteúdo OBJ válido simplificado
     */
    private function getValidObjContent(): string
    {
        return "# Valid OBJ file\n" .
               "v 0 0 0\n" .
               "v 1 0 0\n" .
               "v 0 1 0\n" .
               "f 1 2 3\n";
    }
    
    /**
     * Prepara conteúdo OBJ inválido
     */
    private function getInvalidObjContent(): string
    {
        return "# Invalid OBJ file\n" .
               "v 0 0 0\n" .
               "v 1 0\n" . // Coordenada ausente
               "v 0 1 0\n" .
               "f 1 2 5\n"; // Referência a vértice inexistente
    }
    
    /**
     * Testa validação de arquivo STL ASCII válido
     */
    public function testValidateStructureWithValidAsciiStl(): void
    {
        $filePath = $this->tempDir . '/test_valid_ascii.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertTrue($result->isValid(), "STL ASCII válido deve passar na validação");
        $this->assertEmpty($result->getErrors(), "Não deve haver erros para STL ASCII válido");
    }
    
    /**
     * Testa validação de arquivo STL ASCII inválido
     */
    public function testValidateStructureWithInvalidAsciiStl(): void
    {
        $filePath = $this->tempDir . '/test_invalid_ascii.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "STL ASCII inválido deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para STL ASCII inválido");
    }
    
    /**
     * Testa validação de arquivo STL binário válido
     */
    public function testValidateStructureWithValidBinaryStl(): void
    {
        $filePath = $this->tempDir . '/test_valid_binary.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertTrue($result->isValid(), "STL binário válido deve passar na validação");
        $this->assertEmpty($result->getErrors(), "Não deve haver erros para STL binário válido");
    }
    
    /**
     * Testa validação de arquivo STL binário inválido
     */
    public function testValidateStructureWithInvalidBinaryStl(): void
    {
        $filePath = $this->tempDir . '/test_invalid_binary.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "STL binário inválido deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para STL binário inválido");
    }
    
    /**
     * Testa validação de arquivo OBJ válido
     */
    public function testValidateStructureWithValidObj(): void
    {
        $filePath = $this->tempDir . '/test_valid.obj';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertTrue($result->isValid(), "OBJ válido deve passar na validação");
        $this->assertEmpty($result->getErrors(), "Não deve haver erros para OBJ válido");
    }
    
    /**
     * Testa validação de arquivo OBJ inválido
     */
    public function testValidateStructureWithInvalidObj(): void
    {
        $filePath = $this->tempDir . '/test_invalid.obj';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "OBJ inválido deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para OBJ inválido");
    }
    
    /**
     * Testa validação de arquivo com extensão não suportada
     */
    public function testValidateStructureWithUnsupportedExtension(): void
    {
        $filePath = $this->tempDir . '/test_unsupported.txt';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "Arquivo com extensão não suportada deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para arquivo com extensão não suportada");
        $this->assertStringContainsString("não suportado", implode(' ', $result->getErrors()), "Erro deve mencionar formato não suportado");
    }
    
    /**
     * Testa validação de arquivo vazio
     */
    public function testValidateStructureWithEmptyFile(): void
    {
        $filePath = $this->tempDir . '/test_empty.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "Arquivo vazio deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para arquivo vazio");
    }
    
    /**
     * Testa validação de arquivo inexistente
     */
    public function testValidateStructureWithNonExistentFile(): void
    {
        $filePath = $this->tempDir . '/non_existent_file.stl';
        $result = $this->validator->validateStructure($filePath);
        
        $this->assertFalse($result->isValid(), "Arquivo inexistente deve falhar na validação");
        $this->assertNotEmpty($result->getErrors(), "Deve haver erros para arquivo inexistente");
        $this->assertStringContainsString("não encontrado", implode(' ', $result->getErrors()), "Erro deve mencionar arquivo não encontrado");
    }
    
    /**
     * Testa análise profunda de estrutura STL
     */
    public function testPerformDeepStructuralAnalysis(): void
    {
        $filePath = $this->tempDir . '/test_valid_binary.stl';
        $result = $this->validator->performDeepStructuralAnalysis($filePath);
        
        $this->assertTrue($result->isValid(), "Análise profunda deve passar para STL binário válido");
    }
    
    /**
     * Testa a classe ValidationResult
     */
    public function testValidationResultClass(): void
    {
        // Resultado válido
        $validResult = new ValidationResult(true);
        $this->assertTrue($validResult->isValid());
        $this->assertEmpty($validResult->getErrors());
        $this->assertEmpty($validResult->getWarnings());
        
        // Resultado inválido com erros
        $errors = ['Erro 1', 'Erro 2'];
        $invalidResult = new ValidationResult(false, $errors);
        $this->assertFalse($invalidResult->isValid());
        $this->assertEquals($errors, $invalidResult->getErrors());
        
        // Adicionar aviso a resultado válido
        $validResult->addWarning('Aviso de teste');
        $this->assertCount(1, $validResult->getWarnings());
        $this->assertContains('Aviso de teste', $validResult->getWarnings());
        
        // Adicionar erro a resultado válido (deve torná-lo inválido)
        $validResult->addError('Novo erro');
        $this->assertFalse($validResult->isValid());
        $this->assertCount(1, $validResult->getErrors());
        $this->assertContains('Novo erro', $validResult->getErrors());
    }
    
    /**
     * Testa o método de detecção de pontos coincidentes
     */
    public function testArePointsCoincident(): void
    {
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($this->validator);
        $method = $reflection->getMethod('arePointsCoincident');
        $method->setAccessible(true);
        
        // Pontos coincidentes
        $point1 = [1 => 1.0, 2 => 2.0, 3 => 3.0];
        $point2 = [1 => 1.0, 2 => 2.0, 3 => 3.0];
        $this->assertTrue($method->invoke($this->validator, $point1, $point2), "Pontos idênticos devem ser coincidentes");
        
        // Pontos próximos dentro da tolerância
        $point3 = [1 => 1.0000001, 2 => 2.0000001, 3 => 3.0000001];
        $this->assertTrue($method->invoke($this->validator, $point1, $point3), "Pontos dentro da tolerância devem ser coincidentes");
        
        // Pontos diferentes
        $point4 = [1 => 1.1, 2 => 2.2, 3 => 3.3];
        $this->assertFalse($method->invoke($this->validator, $point1, $point4), "Pontos diferentes não devem ser coincidentes");
    }
    
    /**
     * Testa o cálculo de entropia
     */
    public function testCalculateEntropy(): void
    {
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($this->validator);
        $method = $reflection->getMethod('calculateEntropy');
        $method->setAccessible(true);
        
        // String com entropia baixa (caracteres repetidos)
        $lowEntropyData = str_repeat('A', 1000);
        $lowEntropy = $method->invoke($this->validator, $lowEntropyData);
        $this->assertLessThan(1.0, $lowEntropy, "Dados repetitivos devem ter entropia baixa");
        
        // String com entropia alta (dados pseudo-aleatórios)
        $highEntropyData = '';
        for ($i = 0; $i < 1000; $i++) {
            $highEntropyData .= chr(rand(0, 255));
        }
        $highEntropy = $method->invoke($this->validator, $highEntropyData);
        $this->assertGreaterThan(7.0, $highEntropy, "Dados aleatórios devem ter entropia alta");
    }
    
    /**
     * Testa a detecção de anomalias estruturais
     */
    public function testHasStructuralAnomaly(): void
    {
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($this->validator);
        $method = $reflection->getMethod('hasStructuralAnomaly');
        $method->setAccessible(true);
        
        // Dados normais
        $normalData = "Normal data without any suspicious patterns";
        $this->assertFalse($method->invoke($this->validator, $normalData), "Dados normais não devem ter anomalias");
        
        // Dados com padrões suspeitos (NOP sled usado em exploits)
        $suspiciousData = "Some data with " . str_repeat("\x90", 20) . " NOP sled";
        $this->assertTrue($method->invoke($this->validator, $suspiciousData), "Dados com NOP sled devem ser detectados como anômalos");
        
        // Dados com tags de script
        $scriptData = "Data with <script>alert('xss')</script> embedded";
        $this->assertTrue($method->invoke($this->validator, $scriptData), "Dados com tags de script devem ser detectados como anômalos");
    }
    
    /**
     * Limpar arquivos temporários após os testes
     */
    protected function tearDown(): void
    {
        // Remover arquivos de teste
        $files = glob($this->tempDir . '/test_*');
        foreach ($files as $file) {
            if (is_file($file)) {
                unlink($file);
            }
        }
        
        parent::tearDown();
    }
}
