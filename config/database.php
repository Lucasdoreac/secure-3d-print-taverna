<?php

/**
 * Configuração de conexão com banco de dados
 * 
 * Valores sensíveis devem ser definidos através de variáveis de ambiente
 * em ambientes de produção
 */
return [
    // Configuração de host do banco de dados
    'host' => getenv('DB_HOST') ?: 'mysql',
    
    // Nome do banco de dados
    'database' => getenv('DB_DATABASE') ?: 'taverna_db',
    
    // Usuário para conexão
    'username' => getenv('DB_USERNAME') ?: 'taverna_user',
    
    // Senha para conexão (deve ser definida via variável de ambiente em produção)
    'password' => getenv('DB_PASSWORD') ?: 'dev_password',
    
    // Porta para conexão
    'port' => getenv('DB_PORT') ?: 3306,
    
    // Charset para conexão
    'charset' => 'utf8mb4',
    
    // Collation para conexão
    'collation' => 'utf8mb4_unicode_ci',
    
    // Prefixo para tabelas (opcional)
    'prefix' => '',
    
    // Timeout para conexão em segundos
    'timeout' => 5,
    
    // Opções adicionais para conexão PDO
    'options' => [
        // Forçar uso de Prepared Statements nativos
        PDO::ATTR_EMULATE_PREPARES => false,
        
        // Modo de erro para lançar exceções
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        
        // Tipo de retorno de consultas (array associativo)
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        
        // Converter strings vazias para NULL
        PDO::ATTR_ORACLE_NULLS => PDO::NULL_EMPTY_STRING,
        
        // Preservar nomes de colunas como retornados pelo banco
        PDO::ATTR_CASE => PDO::CASE_NATURAL,
        
        // Conversão de tipos de dados conforme especificações MySQL
        PDO::ATTR_STRINGIFY_FETCHES => false,
    ],
];
