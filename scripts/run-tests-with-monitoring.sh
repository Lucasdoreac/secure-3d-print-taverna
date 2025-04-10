#!/bin/bash
set -e

echo "========================================"
echo "Iniciando suite de testes com monitoramento"
echo "========================================"

# Diretório para logs específicos do teste
TEST_LOG_DIR="logs/test-$(date +'%Y%m%d_%H%M%S')"
mkdir -p $TEST_LOG_DIR

# Função para monitorar e capturar falhas
monitor_and_capture() {
  "$@" 2> >(tee "$TEST_LOG_DIR/error.log") | tee "$TEST_LOG_DIR/output.log"
  local exit_code=${PIPESTATUS[0]}
  
  if [ $exit_code -ne 0 ]; then
    echo "❌ FALHA: O comando '$*' falhou com código $exit_code"
    echo "Detalhes da falha capturados em $TEST_LOG_DIR"
    
    # Capturar estado do sistema para análise pós-falha
    echo "Capturando estado do sistema..."
    top -b -n 1 > "$TEST_LOG_DIR/top.log"
    free -h > "$TEST_LOG_DIR/memory.log"
    df -h > "$TEST_LOG_DIR/disk.log"
    
    # Capturar configuração relevante
    cp config/security.php "$TEST_LOG_DIR/security_config.php"
    
    # Capturar informações de ambiente
    env | grep -v "PASSWORD\|SECRET\|KEY" > "$TEST_LOG_DIR/environment.log"
    php -i > "$TEST_LOG_DIR/php_info.log"
    
    # Capturar informações sobre conexões abertas
    netstat -tuln > "$TEST_LOG_DIR/network_connections.log" 2>/dev/null || true
    
    # Verificar por arquivos temporários órfãos
    find /tmp -name "secure_3d_print_*" -mtime -1 > "$TEST_LOG_DIR/temp_files.log" 2>/dev/null || true
    
    echo "Estado do sistema capturado para análise pós-falha"
  fi
  
  return $exit_code
}

# Verificação de pré-requisitos
check_prerequisites() {
  echo "Verificando pré-requisitos..."
  
  # Verificar PHP
  if ! command -v php &> /dev/null; then
    echo "❌ PHP não encontrado"
    return 1
  fi
  
  # Verificar Composer
  if ! command -v composer &> /dev/null; then
    echo "❌ Composer não encontrado"
    return 1
  fi
  
  # Verificar PHPUnit
  if [ ! -f "vendor/bin/phpunit" ]; then
    echo "❌ PHPUnit não encontrado. Executando composer install..."
    composer install --no-interaction --prefer-dist
  fi
  
  # Verificar configuração de teste
  if [ ! -f ".env.testing" ]; then
    echo "❌ Arquivo .env.testing não encontrado, criando a partir do exemplo..."
    cp .env.example .env.testing
    echo "APP_ENV=testing" >> .env.testing
    echo "DB_DATABASE=testing" >> .env.testing
  fi
  
  # Verificar diretório de logs
  if [ ! -d "logs" ]; then
    mkdir -p logs
    chmod 755 logs
  fi
  
  return 0
}

# Preparar banco de dados para testes
prepare_database() {
  echo "Preparando banco de dados para testes..."
  
  # Determinar ambiente de execução (CI vs local)
  if [ -n "$CI" ]; then
    # Configurar para CI
    export DB_CONNECTION=mysql
    export DB_HOST=mysql
    export DB_DATABASE=testing
    export DB_USERNAME=root
    export DB_PASSWORD=secret
  else
    # Local: usar variáveis de .env.testing
    set -a
    source .env.testing
    set +a
  fi
  
  # Executar migrações com retry
  max_attempts=3
  current_attempt=1
  
  while [ $current_attempt -le $max_attempts ]; do
    echo "Executando migrações (tentativa $current_attempt/$max_attempts)..."
    
    if php artisan migrate:fresh --seed --env=testing; then
      echo "✅ Banco de dados preparado com sucesso"
      return 0
    else
      echo "⚠️ Falha na migração do banco (tentativa $current_attempt)"
      current_attempt=$((current_attempt + 1))
      
      if [ $current_attempt -le $max_attempts ]; then
        echo "Aguardando 5 segundos antes de tentar novamente..."
        sleep 5
      fi
    fi
  done
  
  echo "❌ Falha nas migrações após $max_attempts tentativas"
  return 1
}

# Função para limpar recursos após os testes
cleanup_resources() {
  echo "Limpando recursos temporários..."
  
  # Remover arquivos temporários de teste
  find tests/fixtures/temp -type f -name "test_*.stl" -delete 2>/dev/null || true
  
  # Limpar cache de teste
  php artisan cache:clear --env=testing
  
  echo "✅ Recursos temporários limpos"
}

# Registrar início dos testes com timestamp
echo "Iniciando testes em $(date)" > "$TEST_LOG_DIR/test_summary.log"

# Verificar pré-requisitos
if ! check_prerequisites; then
  echo "❌ Falha na verificação de pré-requisitos"
  exit 1
fi

# Preparar ambiente para testes
if ! prepare_database; then
  echo "❌ Falha na preparação do banco de dados"
  echo "Verifique as configurações de conexão e permissões"
  exit 1
fi

# Iniciar pipeline de testes com captura de falhas
echo "Executando testes unitários..."
monitor_and_capture vendor/bin/phpunit tests/Unit || true

echo "Executando testes de integração..."
monitor_and_capture vendor/bin/phpunit tests/Integration || true

echo "Executando testes de feature..."
monitor_and_capture vendor/bin/phpunit tests/Feature || true

echo "Executando verificações de segurança..."
monitor_and_capture composer run-script security-check || true

echo "Executando análise estática..."
monitor_and_capture vendor/bin/phpstan analyse app tests --level=5 || true

echo "Executando verificação de vulnerabilidades..."
monitor_and_capture composer audit || true

# Limpar recursos
cleanup_resources

echo "========================================"
echo "Resumo dos testes:"
echo "========================================"

# Gerar relatório de resultados
passed=0
failed=0

check_test_result() {
  local pattern=$1
  local name=$2
  
  if grep -q "$pattern" "$TEST_LOG_DIR/output.log"; then
    echo "❌ $name: FALHA"
    ((failed++))
    return 1
  else
    echo "✅ $name: SUCESSO"
    ((passed++))
    return 0
  fi
}

check_test_result "FAILURES" "Testes unitários"
check_test_result "FAILURES" "Testes de integração"
check_test_result "FAILURES" "Testes de feature"
check_test_result "Erro" "Verificação de segurança"
check_test_result "vulnerabilities" "Verificação de vulnerabilidades"

if grep -q "error" "$TEST_LOG_DIR/error.log"; then
  echo "⚠️ Erros detectados durante a execução"
fi

# Adicionar informações de ambiente ao relatório
echo "----- Informações de Ambiente -----" >> "$TEST_LOG_DIR/test_summary.log"
echo "PHP Version: $(php -r 'echo PHP_VERSION;')" >> "$TEST_LOG_DIR/test_summary.log"
echo "Composer Version: $(composer --version | awk '{print $3}')" >> "$TEST_LOG_DIR/test_summary.log"
echo "OS: $(uname -a)" >> "$TEST_LOG_DIR/test_summary.log"
echo "Memória Total: $(free -h | grep Mem | awk '{print $2}')" >> "$TEST_LOG_DIR/test_summary.log"

# Adicionar resumo final
echo "----- Resumo Final -----" >> "$TEST_LOG_DIR/test_summary.log"
echo "Testes Bem-Sucedidos: $passed" >> "$TEST_LOG_DIR/test_summary.log"
echo "Testes Falhos: $failed" >> "$TEST_LOG_DIR/test_summary.log"
echo "Data/Hora de Finalização: $(date)" >> "$TEST_LOG_DIR/test_summary.log"

echo "========================================"
echo "Resultado final: $passed passaram, $failed falharam"
echo "Logs detalhados disponíveis em: $TEST_LOG_DIR"
echo "========================================"

# Retornar código de saída para integração CI/CD
[ $failed -eq 0 ]
