# Secure 3D Print Taverna

Plataforma de e-commerce para serviços de impressão 3D com foco em segurança.

## Guardrails de Segurança

Este projeto implementa os seguintes guardrails de segurança:

1. Validação rigorosa de todas as entradas via InputValidationTrait
2. Proteção CSRF em todos os formulários POST
3. Prepared statements para todas consultas SQL
4. Sanitização de saída para prevenção de XSS
5. Verificação de permissões para operações sensíveis
6. Headers HTTP de segurança em todas as respostas
7. Armazenamento seguro de senhas com hash e salt
8. Proteção contra path traversal em uploads
9. Mensagens de erro genéricas para usuários
10. Logging detalhado para depuração interna

## Instalação

```bash
git clone https://github.com/Lucasdoreac/secure-3d-print-taverna.git
cd secure-3d-print-taverna
./scripts/setup.sh
```

## Testes

```bash
./scripts/test.sh
```

## Contribuição

Veja [CONTRIBUTING.md](CONTRIBUTING.md) para orientações detalhadas.