#!/bin/bash
set -e

echo "===== Inicializando projeto Secure 3D Print Taverna ====="

# Verificar dependências
echo "Verificando dependências..."
command -v docker >/dev/null 2>&1 || { echo "Docker não encontrado. Instale-o antes de continuar."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || { echo "Docker Compose não encontrado. Instale-o antes de continuar."; exit 1; }
command -v composer >/dev/null 2>&1 || { echo "Composer não encontrado. Instale-o antes de continuar."; exit 1; }

# Criar diretório para logs
echo "Criando diretórios necessários..."
mkdir -p logs/security

# Instalar dependências via Composer
echo "Instalando dependências PHP..."
composer install

# Configurar ambiente
echo "Configurando ambiente..."
if [ ! -f .env ]; then
    cp .env.example .env
    # Gerar chave de aplicação
    APP_KEY=$(openssl rand -hex 32)
    sed -i "s/APP_KEY=/APP_KEY=$APP_KEY/" .env
fi

# Construir e iniciar containers Docker
echo "Iniciando ambiente de desenvolvimento..."
docker-compose up -d

# Esperar o banco de dados inicializar
echo "Aguardando o banco de dados..."
sleep 10

# Executar migrações iniciais
echo "Executando migrações do banco de dados..."
docker-compose exec app php scripts/migrate.php

# Executar testes de segurança iniciais
echo "Executando testes de segurança iniciais..."
docker-compose exec app ./vendor/bin/phpunit tests/Security

echo "===== Projeto inicializado com sucesso! ====="
echo "Acesse: http://localhost:8080"
echo "PHPMyAdmin: http://localhost:8081"
echo ""
echo "Guardrails de segurança implementados:"
echo "✓ Proteção CSRF"
echo "✓ Validação de entrada"
echo "✓ Headers HTTP de segurança"
echo "✓ Prepared statements para SQL"
echo "✓ Sanitização de saída"