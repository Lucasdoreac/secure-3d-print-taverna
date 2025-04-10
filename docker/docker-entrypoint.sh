#!/bin/bash
set -e

# Função para exibir mensagens
log() {
    echo "[Secure-3D-Print-Taverna] $1"
}

# Verificar se estamos em desenvolvimento ou produção
if [ "$APP_ENV" = "production" ]; then
    log "Ambiente: Produção"
    
    # Verificações adicionais de segurança para produção
    if [ -z "$APP_KEY" ]; then
        log "ERRO: APP_KEY não definido! Abortando inicialização por segurança."
        exit 1
    fi
    
    # Verificar conexão com banco de dados
    if [ ! -z "$DB_HOST" ]; then
        log "Verificando conexão com banco de dados..."
        # Tentativas de conexão
        ATTEMPTS=0
        MAX_ATTEMPTS=30
        
        until php -r "try { new PDO('mysql:host=$DB_HOST;dbname=$DB_NAME', '$DB_USER', '$DB_PASSWORD'); echo 'Conexão bem-sucedida!'; } catch (PDOException \$e) { echo \$e->getMessage(); exit(1); }" || [ $ATTEMPTS -ge $MAX_ATTEMPTS ]
        do
            ATTEMPTS=$((ATTEMPTS+1))
            log "Tentativa $ATTEMPTS de $MAX_ATTEMPTS: aguardando banco de dados... (5s)"
            sleep 5
        done
        
        if [ $ATTEMPTS -ge $MAX_ATTEMPTS ]; then
            log "ERRO: Não foi possível conectar ao banco de dados após $MAX_ATTEMPTS tentativas"
            exit 1
        fi
    fi
else
    log "Ambiente: Desenvolvimento"
fi

# Permissões corretas para logs e diretórios de cache
if [ -d /var/www/html/logs ]; then
    log "Configurando permissões para logs..."
    mkdir -p /var/www/html/logs/security
    chown -R www-data:www-data /var/www/html/logs
    chmod -R 755 /var/www/html/logs
fi

if [ -d /var/www/html/cache ]; then
    log "Configurando permissões para cache..."
    chown -R www-data:www-data /var/www/html/cache
    chmod -R 755 /var/www/html/cache
fi

# Verificar se o Composer já foi executado
if [ ! -d "/var/www/html/vendor" ] && [ -f "/var/www/html/composer.json" ]; then
    log "Instalando dependências via Composer..."
    composer install --no-interaction --no-plugins --no-scripts --prefer-dist
    
    if [ $? -ne 0 ]; then
        log "AVISO: Falha ao instalar dependências via Composer"
    fi
fi

# Executar migrações automáticas se script existir
if [ "$AUTO_MIGRATE" = "true" ] && [ -f "/var/www/html/scripts/migrate.php" ]; then
    log "Executando migrações automáticas..."
    php /var/www/html/scripts/migrate.php
fi

# Executar comando fornecido ou padrão
log "Inicializando servidor..."
exec "$@"