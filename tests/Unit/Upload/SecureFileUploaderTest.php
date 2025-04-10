<?php
namespace Tests\Unit\Upload;

use PHPUnit\Framework\TestCase;
use App\Lib\Upload\SecureFileUploader;
use App\Lib\Models\ModelValidator;
use App\Lib\Resilience\CircuitBreaker;
use ReflectionClass;
use ReflectionMethod;
use PHPUnit\Framework\MockObject\MockObject;

class SecureFileUploaderTest extends TestCase
{
    private string $tempDir;
    private string $storagePath;
    private MockObject $validatorMock;
    private MockObject $circuitBreakerMock;
    private array $validFileData;
    
    protected function setUp(): void
    {
        parent::setUp();
        
        // Diretório temporário para testes
        $this->tempDir = sys_get_temp_dir() . '/secure_uploader_test_' . uniqid();
        mkdir($this->tempDir, 0755, true);
        
        // Diretório de armazenamento para testes
        $this->storagePath = $this->tempDir . '/storage';
        mkdir($this->storagePath, 0755, true);
        
        // Mock de validador
        $this->validatorMock = $this->createMock(ModelValidator::class);
        
        // Mock de circuit breaker
        $this->circuitBreakerMock = $this->createMock(CircuitBreaker::class);
        
        // Prepara dados de arquivo válidos para testes
        $testFilePath = $this->tempDir . '/test_upload.stl';
        file_put_contents($testFilePath, $this->getValidStlBinaryContent());
        
        $this->validFileData = [
            'name' => 'test_model.stl',
            'type' => 'model/stl',
            'tmp_name' => $testFilePath,
            'error' => UPLOAD_ERR_OK,
            'size' => filesize($testFilePath)
        ];
    }
    
    /**
     * Prepara conteúdo de arquivo STL para teste
     */
    private function getValidStlBinaryContent(): string
    {
        // Cabeçalho de 80 bytes
        $header = str_pad("Binary STL Test File", 80, "\0");
        
        // 1 triângulo
        $numTriangles = pack("V", 1);
        
        // Um triângulo (normal + 3 vértices + atributos)
        $normal = pack("f*", 0, 0, 1);
        $vertex1 = pack("f*", 0, 0, 0);
        $vertex2 = pack("f*", 1, 0, 0);
        $vertex3 = pack("f*", 0, 1, 0);
        $attr = pack("v", 0);
        
        return $header . $numTriangles . $normal . $vertex1 . $vertex2 . $vertex3 . $attr;
    }
    
    /**
     * Cria instância do uploader com mocks para testes isolados
     */
    private function createUploaderWithMocks(): SecureFileUploader
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Substituir propriedades privadas pelos mocks usando Reflection API
        $reflection = new ReflectionClass($uploader);
        
        $modelValidatorProp = $reflection->getProperty('modelValidator');
        $modelValidatorProp->setAccessible(true);
        $modelValidatorProp->setValue($uploader, $this->validatorMock);
        
        $threatScanCircuitProp = $reflection->getProperty('threatScanCircuit');
        $threatScanCircuitProp->setAccessible(true);
        $threatScanCircuitProp->setValue($uploader, $this->circuitBreakerMock);
        
        $storageCircuitProp = $reflection->getProperty('storageCircuit');
        $storageCircuitProp->setAccessible(true);
        $storageCircuitProp->setValue($uploader, $this->circuitBreakerMock);
        
        return $uploader;
    }
    
    /**
     * Testa validação básica de dados de upload
     */
    public function testIsValidUploadData(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('isValidUploadData');
        $method->setAccessible(true);
        
        // Dados de upload válidos
        $this->assertTrue($method->invoke($uploader, $this->validFileData), "Dados de upload válidos devem retornar true");
        
        // Dados de upload inválidos: faltando campos obrigatórios
        $invalidData1 = $this->validFileData;
        unset($invalidData1['tmp_name']);
        $this->assertFalse($method->invoke($uploader, $invalidData1), "Dados sem tmp_name devem retornar false");
        
        // Dados de upload inválidos: erro no upload
        $invalidData2 = $this->validFileData;
        $invalidData2['error'] = UPLOAD_ERR_INI_SIZE;
        $this->assertFalse($method->invoke($uploader, $invalidData2), "Dados com código de erro devem retornar false");
        
        // Dados de upload inválidos: arquivo não existe
        $invalidData3 = $this->validFileData;
        $invalidData3['tmp_name'] = '/tmp/non_existent_file_' . uniqid();
        $this->assertFalse($method->invoke($uploader, $invalidData3), "Dados com arquivo inexistente devem retornar false");
    }
    
    /**
     * Testa validação de tamanho do arquivo
     */
    public function testValidateFileSize(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('validateFileSize');
        $method->setAccessible(true);
        
        // Arquivo com tamanho válido
        $result1 = $method->invoke($uploader, $this->validFileData, 1, 'regular');
        $this->assertTrue($result1->isValid(), "Arquivo com tamanho dentro do limite deve ser válido");
        
        // Arquivo vazio
        $emptyFileData = $this->validFileData;
        $emptyFileData['size'] = 0;
        $result2 = $method->invoke($uploader, $emptyFileData, 1, 'regular');
        $this->assertFalse($result2->isValid(), "Arquivo vazio deve ser inválido");
        
        // Arquivo muito grande
        $largeFileData = $this->validFileData;
        $largeFileData['size'] = 100 * 1024 * 1024; // 100MB
        $result3 = $method->invoke($uploader, $largeFileData, 1, 'regular');
        $this->assertFalse($result3->isValid(), "Arquivo muito grande deve ser inválido");
        
        // Verificar se o erro contém informação sobre o tamanho
        $this->assertStringContainsString("tamanho máximo", $result3->getErrors()[0], "Erro deve mencionar tamanho máximo");
    }
    
    /**
     * Testa validação de tipo de arquivo
     */
    public function testValidateFileType(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('validateFileType');
        $method->setAccessible(true);
        
        // Tipo de arquivo válido
        $result1 = $method->invoke($uploader, $this->validFileData);
        $this->assertTrue($result1->isValid(), "Arquivo STL deve ser válido");
        
        // Tipo de arquivo inválido
        $invalidTypeData = $this->validFileData;
        $invalidTypeData['name'] = 'test.xyz';
        $result2 = $method->invoke($uploader, $invalidTypeData);
        $this->assertFalse($result2->isValid(), "Arquivo com extensão não suportada deve ser inválido");
        $this->assertStringContainsString("não permitida", $result2->getErrors()[0], "Erro deve mencionar extensão não permitida");
    }
    
    /**
     * Testa detecção de MIME type com vários métodos
     */
    public function testDetectMimeType(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('detectMimeType');
        $method->setAccessible(true);
        
        // Detectar MIME type de arquivo STL
        $mimeType = $method->invoke($uploader, $this->validFileData['tmp_name']);
        
        // Deve retornar um tipo MIME válido para STL, que pode variar dependendo do sistema
        $this->assertNotEmpty($mimeType, "Detecção de MIME deve retornar um valor não vazio");
        
        // Criar arquivo de teste com outros formatos para testar a detecção
        $objFilePath = $this->tempDir . '/test_obj.obj';
        file_put_contents($objFilePath, "v 0 0 0\nv 1 0 0\nv 0 1 0\nf 1 2 3");
        
        $objMimeType = $method->invoke($uploader, $objFilePath);
        $this->assertNotEmpty($objMimeType, "Detecção de MIME para OBJ deve retornar um valor não vazio");
    }
    
    /**
     * Testa verificação básica de segurança de arquivo
     */
    public function testPerformBasicSafetyCheck(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('performBasicSafetyCheck');
        $method->setAccessible(true);
        
        // Verificação de segurança de arquivo válido
        $result = $method->invoke($uploader, $this->validFileData['tmp_name']);
        
        $this->assertTrue($result->isSecure(), "Arquivo STL válido deve passar na verificação básica de segurança");
        $this->assertNotEmpty($result->getWarnings(), "Verificação básica deve gerar avisos");
    }
    
    /**
     * Testa o cálculo de entropia
     */
    public function testCalculateEntropy(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('calculateEntropy');
        $method->setAccessible(true);
        
        // String com entropia baixa (caracteres repetidos)
        $lowEntropyData = str_repeat('A', 1000);
        $lowEntropy = $method->invoke($uploader, $lowEntropyData);
        $this->assertLessThan(1.0, $lowEntropy, "Dados repetitivos devem ter entropia baixa");
        
        // String com entropia alta (dados pseudo-aleatórios)
        $highEntropyData = '';
        for ($i = 0; $i < 1000; $i++) {
            $highEntropyData .= chr(rand(0, 255));
        }
        $highEntropy = $method->invoke($uploader, $highEntropyData);
        $this->assertGreaterThan(7.0, $highEntropy, "Dados aleatórios devem ter entropia alta");
    }
    
    /**
     * Testa formatação de bytes
     */
    public function testFormatBytes(): void
    {
        $uploader = new SecureFileUploader($this->storagePath);
        
        // Acessar método privado via Reflection API
        $reflection = new ReflectionClass($uploader);
        $method = $reflection->getMethod('formatBytes');
        $method->setAccessible(true);
        
        // Testar conversões
        $this->assertEquals("1 KB", $method->invoke($uploader, 1024, 0), "1024 bytes deve formatar como 1 KB");
        $this->assertEquals("1.50 MB", $method->invoke($uploader, 1572864, 2), "1.5MB deve formatar corretamente");
        $this->assertEquals("1 GB", $method->invoke($uploader, 1073741824, 0), "1GB deve formatar corretamente");
        $this->assertEquals("0 B", $method->invoke($uploader, 0, 0), "0 bytes deve formatar corretamente");
    }
    
    /**
     * Testa processamento completo de upload com mocks
     */
    public function testProcessUploadSuccess(): void
    {
        // Criar uploader com mocks
        $uploader = $this->createUploaderWithMocks();
        
        // Configurar mock do validator para retornar resultado válido
        $validationResultMock = $this->getMockBuilder(\App\Lib\Models\ValidationResult::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $validationResultMock->method('isValid')->willReturn(true);
        $validationResultMock->method('getErrors')->willReturn([]);
        $validationResultMock->method('getWarnings')->willReturn([]);
        
        $this->validatorMock->method('validateStructure')->willReturn($validationResultMock);
        $this->validatorMock->method('performDeepStructuralAnalysis')->willReturn($validationResultMock);
        
        // Configurar mock de circuit breaker para executar callbacks
        $this->circuitBreakerMock->method('execute')->willReturnCallback(
            function($operation, $fallback = null, $context = []) {
                return $operation();
            }
        );
        
        // Modificar método moveToSecureTempLocation para evitar movimentação real de arquivo
        $uploaderReflection = new ReflectionClass($uploader);
        
        $moveToSecureTempLocationMethod = $uploaderReflection->getMethod('moveToSecureTempLocation');
        $moveToSecureTempLocationMethod->setAccessible(true);
        
        // Substituir implementação do método via PHPUnit getMockBuilder
        $uploaderPartialMock = $this->getMockBuilder(SecureFileUploader::class)
                                  ->setConstructorArgs([$this->storagePath])
                                  ->onlyMethods(['moveToSecureTempLocation', 'scanForThreats', 'storeSecurely'])
                                  ->getMock();
        
        // Configurar comportamento dos métodos mockados
        $tempFileResultMock = new \App\Lib\Upload\TempFileResult(true, $this->validFileData['tmp_name']);
        $uploaderPartialMock->method('moveToSecureTempLocation')->willReturn($tempFileResultMock);
        
        $threatScanResultMock = new \App\Lib\Upload\ThreatScanResult(true, 'Arquivo seguro');
        $uploaderPartialMock->method('scanForThreats')->willReturn($threatScanResultMock);
        
        $storageResultMock = new \App\Lib\Upload\StorageResult(true, '/storage/path/file.stl', 'abcdef123456');
        $uploaderPartialMock->method('storeSecurely')->willReturn($storageResultMock);
        
        // Substituir validador e circuit breakers no mock parcial
        $modelValidatorProp = $uploaderReflection->getProperty('modelValidator');
        $modelValidatorProp->setAccessible(true);
        $modelValidatorProp->setValue($uploaderPartialMock, $this->validatorMock);
        
        $threatScanCircuitProp = $uploaderReflection->getProperty('threatScanCircuit');
        $threatScanCircuitProp->setAccessible(true);
        $threatScanCircuitProp->setValue($uploaderPartialMock, $this->circuitBreakerMock);
        
        $storageCircuitProp = $uploaderReflection->getProperty('storageCircuit');
        $storageCircuitProp->setAccessible(true);
        $storageCircuitProp->setValue($uploaderPartialMock, $this->circuitBreakerMock);
        
        // Executar o processamento de upload
        $result = $uploaderPartialMock->processUpload($this->validFileData, 1, 'regular');
        
        // Verificar resultado
        $this->assertTrue($result->isSuccess(), "Upload deve ser bem-sucedido");
        $this->assertNotNull($result->getMetadata(), "Metadados devem estar presentes");
        $this->assertArrayHasKey('file_hash', $result->getMetadata(), "Metadados devem conter hash do arquivo");
    }
    
    /**
     * Testa processamento de upload com falha
     */
    public function testProcessUploadFailure(): void
    {
        // Criar uploader com mocks
        $uploader = $this->createUploaderWithMocks();
        
        // Configurar mock do validator para retornar resultado inválido
        $validationResultMock = $this->getMockBuilder(\App\Lib\Models\ValidationResult::class)
                                    ->disableOriginalConstructor()
                                    ->getMock();
        $validationResultMock->method('isValid')->willReturn(false);
        $validationResultMock->method('getErrors')->willReturn(['Erro na validação do modelo']);
        
        $this->validatorMock->method('validateStructure')->willReturn($validationResultMock);
        
        // Configurar mock de circuit breaker para executar callbacks
        $this->circuitBreakerMock->method('execute')->willReturnCallback(
            function($operation, $fallback = null, $context = []) {
                return $operation();
            }
        );
        
        // Modificar método moveToSecureTempLocation para evitar movimentação real de arquivo
        $tempFileResultMock = new \App\Lib\Upload\TempFileResult(true, $this->validFileData['tmp_name']);
        
        // Substituir implementação dos métodos via PHPUnit getMockBuilder
        $uploaderPartialMock = $this->getMockBuilder(SecureFileUploader::class)
                                  ->setConstructorArgs([$this->storagePath])
                                  ->onlyMethods(['moveToSecureTempLocation'])
                                  ->getMock();
        
        $uploaderPartialMock->method('moveToSecureTempLocation')->willReturn($tempFileResultMock);
        
        // Substituir validador e circuit breakers no mock parcial
        $reflection = new ReflectionClass($uploaderPartialMock);
        
        $modelValidatorProp = $reflection->getProperty('modelValidator');
        $modelValidatorProp->setAccessible(true);
        $modelValidatorProp->setValue($uploaderPartialMock, $this->validatorMock);
        
        // Executar o processamento de upload
        $result = $uploaderPartialMock->processUpload($this->validFileData, 1, 'regular');
        
        // Verificar resultado
        $this->assertFalse($result->isSuccess(), "Upload deve falhar");
        $this->assertNull($result->getMetadata(), "Metadados devem ser nulos");
        $this->assertNotNull($result->getErrorMessage(), "Mensagem de erro deve estar presente");
        $this->assertStringContainsString("Validação de modelo falhou", $result->getErrorMessage(), "Mensagem de erro deve mencionar falha na validação");
    }
    
    /**
     * Testa classes de resultado (UploadResult, StorageResult, ThreatScanResult, TempFileResult)
     */
    public function testResultClasses(): void
    {
        // Testar UploadResult
        $uploadResult1 = new \App\Lib\Upload\UploadResult(true, ['key' => 'value']);
        $this->assertTrue($uploadResult1->isSuccess());
        $this->assertEquals(['key' => 'value'], $uploadResult1->getMetadata());
        $this->assertNull($uploadResult1->getErrorMessage());
        
        $uploadResult2 = new \App\Lib\Upload\UploadResult(false, null, 'Mensagem de erro');
        $this->assertFalse($uploadResult2->isSuccess());
        $this->assertNull($uploadResult2->getMetadata());
        $this->assertEquals('Mensagem de erro', $uploadResult2->getErrorMessage());
        
        // Testar StorageResult
        $storageResult1 = new \App\Lib\Upload\StorageResult(true, '/path/to/file', 'hash123');
        $this->assertTrue($storageResult1->isSuccess());
        $this->assertEquals('/path/to/file', $storageResult1->getFilePath());
        $this->assertEquals('hash123', $storageResult1->getFileHash());
        $this->assertNull($storageResult1->getErrorMessage());
        
        $storageResult2 = new \App\Lib\Upload\StorageResult(false, '', '', 'Erro de armazenamento');
        $this->assertFalse($storageResult2->isSuccess());
        $this->assertEquals('', $storageResult2->getFilePath());
        $this->assertEquals('', $storageResult2->getFileHash());
        $this->assertEquals('Erro de armazenamento', $storageResult2->getErrorMessage());
        
        // Testar ThreatScanResult
        $threatResult1 = new \App\Lib\Upload\ThreatScanResult(true, 'Arquivo seguro');
        $this->assertTrue($threatResult1->isSecure());
        $this->assertEquals('Arquivo seguro', $threatResult1->getMessage());
        $this->assertEmpty($threatResult1->getWarnings());
        
        $threatResult1->addWarning('Aviso de teste');
        $this->assertCount(1, $threatResult1->getWarnings());
        $this->assertContains('Aviso de teste', $threatResult1->getWarnings());
        
        $threatResult2 = new \App\Lib\Upload\ThreatScanResult(false, 'Ameaça detectada');
        $this->assertFalse($threatResult2->isSecure());
        $this->assertEquals('Ameaça detectada', $threatResult2->getMessage());
        
        // Testar TempFileResult
        $tempResult1 = new \App\Lib\Upload\TempFileResult(true, '/tmp/file');
        $this->assertTrue($tempResult1->isValid());
        $this->assertEquals('/tmp/file', $tempResult1->getFilePath());
        $this->assertEmpty($tempResult1->getErrors());
        
        $tempResult2 = new \App\Lib\Upload\TempFileResult(false, null, ['Erro 1', 'Erro 2']);
        $this->assertFalse($tempResult2->isValid());
        $this->assertNull($tempResult2->getFilePath());
        $this->assertCount(2, $tempResult2->getErrors());
    }
    
    /**
     * Limpar recursos temporários após os testes
     */
    protected function tearDown(): void
    {
        // Remover diretório temporário recursivamente
        $this->rrmdir($this->tempDir);
        
        parent::tearDown();
    }
    
    /**
     * Remove diretório recursivamente
     */
    private function rrmdir($dir) 
    {
        if (is_dir($dir)) {
            $objects = scandir($dir);
            foreach ($objects as $object) {
                if ($object != "." && $object != "..") {
                    if (is_dir($dir . "/" . $object)) {
                        $this->rrmdir($dir . "/" . $object);
                    } else {
                        unlink($dir . "/" . $object);
                    }
                }
            }
            rmdir($dir);
        }
    }
}
