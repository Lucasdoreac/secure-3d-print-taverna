-- Secure 3D Print Taverna - Esquema Inicial
-- Este script cria o esquema inicial do banco de dados com foco em segurança

-- Configurações de segurança
SET SQL_MODE = "STRICT_TRANS_TABLES,NO_ENGINE_SUBSTITUTION,ERROR_FOR_DIVISION_BY_ZERO,NO_AUTO_CREATE_USER,NO_ZERO_DATE,NO_ZERO_IN_DATE";
SET time_zone = '+00:00';
SET NAMES utf8mb4;

-- Tabela: users
CREATE TABLE IF NOT EXISTS `users` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `password_hash` varchar(255) NOT NULL COMMENT 'Argon2id hash',
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `role` enum('admin','customer','printer') NOT NULL DEFAULT 'customer',
  `failed_login_attempts` tinyint(4) NOT NULL DEFAULT 0,
  `last_login_attempt` datetime DEFAULT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`),
  UNIQUE KEY `email` (`email`),
  KEY `role_idx` (`role`),
  KEY `is_active_idx` (`is_active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela: user_sessions
CREATE TABLE IF NOT EXISTS `user_sessions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `session_id` varchar(255) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` varchar(255) NOT NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `session_id` (`session_id`),
  KEY `user_id_idx` (`user_id`),
  CONSTRAINT `fk_user_sessions_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela: security_audit_log
CREATE TABLE IF NOT EXISTS `security_audit_log` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NULL,
  `action` varchar(50) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `user_agent` varchar(255) NOT NULL,
  `details` text NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id_idx` (`user_id`),
  KEY `action_idx` (`action`),
  KEY `created_at_idx` (`created_at`),
  CONSTRAINT `fk_audit_log_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela: 3d_models
CREATE TABLE IF NOT EXISTS `models` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `name` varchar(100) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `filetype` varchar(10) NOT NULL,
  `filesize` int(11) UNSIGNED NOT NULL,
  `file_hash` varchar(64) NOT NULL COMMENT 'SHA-256 hash do arquivo',
  `status` enum('pending','approved','rejected') NOT NULL DEFAULT 'pending',
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id_idx` (`user_id`),
  KEY `status_idx` (`status`),
  CONSTRAINT `fk_models_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Tabela: orders
CREATE TABLE IF NOT EXISTS `orders` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id` int(11) UNSIGNED NOT NULL,
  `model_id` int(11) UNSIGNED NOT NULL,
  `status` enum('pending','processing','completed','canceled') NOT NULL DEFAULT 'pending',
  `total_amount` decimal(10,2) NOT NULL,
  `payment_status` enum('pending','paid','refunded') NOT NULL DEFAULT 'pending',
  `special_instructions` text NULL,
  `created_at` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id_idx` (`user_id`),
  KEY `model_id_idx` (`model_id`),
  KEY `status_idx` (`status`),
  CONSTRAINT `fk_orders_user_id` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_orders_model_id` FOREIGN KEY (`model_id`) REFERENCES `models` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Inserir usuário admin inicial com senha segura (senha temporária: Admin@Secure3DPrint)
INSERT INTO `users` (`username`, `email`, `password_hash`, `is_active`, `role`, `created_at`) VALUES 
('admin', 'admin@secure3dprint.example', '$argon2id$v=19$m=65536,t=4,p=3$L3ZhcmZpbGV4eXo$aCmODmcHoTeK0wHe6KeRcQ/RvXzNfAhzHjRApCCQpw0', 1, 'admin', NOW());

-- Registrar criação do usuário admin no log de auditoria
INSERT INTO `security_audit_log` (`user_id`, `action`, `ip_address`, `user_agent`, `details`, `created_at`) VALUES 
(1, 'user_creation', '127.0.0.1', 'MySQL Script', 'Initial admin user created during system setup', NOW());