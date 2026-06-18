# SecureChain Audit

**Plataforma de Auditoria Baseada em Blockchain**
Disciplina: Segurança de Sistemas com Blockchain, Criptografia e Auditoria de Eventos

SecureChain Audit é um sistema integrado de segurança e auditoria desenvolvido para
**Linux Debian 13** em **Python 3** e **Bash**, criado para resolver os problemas de
controle de acesso, integridade de arquivos e rastreabilidade de eventos da empresa
fictícia *SecureData Solutions*.

O sistema registra todo evento relevante (login, alteração de arquivo, backup, criação
de usuário, etc.) em uma **blockchain imutável**, garantindo uma trilha de auditoria
confiável e verificável.

---

## Funcionalidades

| Requisito | Descrição | Implementação |
|-----------|-----------|---------------|
| RF01 | Usuários e permissões do SO (menor privilégio) | `scripts/setup_usuarios.sh` |
| RF02 | Autenticação com hash de senha (PBKDF2-SHA256 + salt) | `autenticacao/auth.py` |
| RF03 | Monitoramento de integridade por hash SHA-256 | `monitoramento/monitor.py` |
| RF04 | Blockchain de auditoria (blocos encadeados) | `blockchain/blockchain.py` |
| RF05 | Backup compactado e criptografado com AES-256 | `backup/backup.sh` |
| RF06 | Auditoria do SO (`who`, `last`, `ss`, `ip a`) | `auditoria/auditor.py` |
| RF07 | Validação da cadeia e detecção de corrupção | `blockchain/blockchain.py` |
| 7.3 | Hacking ético da própria VM (nmap/ss/permissões) | `scripts/hacking_etico.sh` |

---

## Estrutura do Projeto

```
securechain/
├── blockchain/
│   ├── blockchain.py      # Blocos, encadeamento e validação da cadeia
│   └── chain.json         # Persistência da blockchain
├── autenticacao/
│   └── auth.py            # Cadastro, login, sessão e perfis (RF02)
├── monitoramento/
│   └── monitor.py         # Integridade de arquivos por SHA-256 (RF03)
├── auditoria/
│   ├── auditor.py         # Coleta de dados do SO (RF06)
│   └── relatorios/        # Relatórios gerados automaticamente
├── backup/
│   └── backup.sh          # Compactação + criptografia AES-256 + log (RF05)
├── scripts/
│   ├── setup_usuarios.sh  # Usuários e permissões do SO (RF01)
│   └── hacking_etico.sh   # Análise de segurança da VM (7.3)
├── logs/                  # Registros de eventos (backup.log, etc.)
├── documentos/            # Arquivos sigilosos monitorados pela integridade
├── integridade/           # Baseline de hashes de referência
├── usuarios/              # Credenciais (senhas em hash) — não versionado
├── main.py                # CLI integradora de todos os módulos
└── README.md
```

---

## Requisitos

- **Linux Debian 13** (ou compatível)
- **Python 3** (testado em 3.13) — usa apenas a biblioteca padrão (`hashlib`, `hmac`, `json`, `os`, `subprocess`, `datetime`)
- **Bash**, **openssl**, **tar**
- Para auditoria/hacking ético: `nmap`, `ss` (pacote `iproute2`), `coreutils`

> **Observação:** não há dependências externas via `pip`. O hash de senhas usa
> **PBKDF2-HMAC-SHA256** da biblioteca padrão, o que satisfaz o requisito
> *"SHA-256 com salt"* e garante execução mesmo sem acesso à internet.

---

## Como Usar

### 1. Configurar usuários e permissões do SO (RF01) — requer root
```bash
sudo bash scripts/setup_usuarios.sh
sudo passwd administrador   # definir senhas
sudo passwd analista
sudo passwd visitante
```

### 2. Executar a aplicação integrada
```bash
python3 main.py
```
No primeiro uso, crie o administrador inicial pela opção **[2]**.

### 3. Uso individual dos módulos

**Autenticação:**
```bash
python3 autenticacao/auth.py cadastrar admin1 SenhaForte123 admin
python3 autenticacao/auth.py login admin1 SenhaForte123
```

**Monitoramento de integridade (RF03):**
```bash
python3 monitoramento/monitor.py init        # gera baseline de hashes
python3 monitoramento/monitor.py verificar    # detecta alteração/exclusão/inclusão
```

**Blockchain (RF04 / RF07):**
```bash
python3 blockchain/blockchain.py registrar "Evento de teste"
python3 blockchain/blockchain.py listar
python3 blockchain/blockchain.py validar      # detecta adulteração
```

**Auditoria do SO (RF06):**
```bash
python3 auditoria/auditor.py
# -> gera auditoria/relatorios/auditoria_<data>.txt
```

**Backup seguro AES-256 (RF05):**
```bash
bash backup/backup.sh
# ou com senha via variável de ambiente:
SECURECHAIN_BACKUP_PASS="minhaSenha" bash backup/backup.sh
```

**Restaurar um backup:**
```bash
openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
    -in backup/arquivos/documentos_<data>.tar.gz.enc \
    -out restaurado.tar.gz -pass pass:minhaSenha
tar -xzf restaurado.tar.gz
```

**Análise de segurança da VM (7.3):**
```bash
bash scripts/hacking_etico.sh
```

---

## Segurança Aplicada

- **Senhas:** PBKDF2-HMAC-SHA256, salt de 16 bytes por usuário, 200.000 iterações; comparação em tempo constante (`hmac.compare_digest`).
- **Backup:** AES-256-CBC com derivação PBKDF2 (`openssl -pbkdf2 -iter 100000 -salt`).
- **Integridade:** SHA-256 de arquivos e dos blocos da blockchain.
- **Zero Trust:** identidade verificada a cada ação sensível (`exige_perfil`), todo acesso (sucesso ou falha) registrado de forma imutável.
- **Menor privilégio:** perfis admin/analista/visitante com permissões mínimas; `usuarios.json` em modo `600`.
- **Validação de entrada:** usuários/senhas/perfis validados; comandos do SO executados sem shell (lista de argumentos) para evitar injeção.

---

## Estrutura de um Bloco

```json
{
  "id": 3,
  "timestamp": "2026-06-17T23:47:34.123456+00:00",
  "evento": "Login realizado: 'admin1' (perfil=admin)",
  "hash_anterior": "ad169921762324e6...",
  "hash_atual": "e9f04b876575dc08..."
}
```
O `hash_atual` é o SHA-256 de `id + timestamp + evento + hash_anterior`. Alterar
qualquer campo muda o hash e quebra o encadeamento — detectado por `validar`.

---

## Equipe e Divisão de Módulos

| Integrante | RA | Módulo principal |
|------------|-----|------------------|
| Lucas Prata Pradella | 202210448 | Blockchain de auditoria (RF04/RF07) |
| Ricardo Almeida Amaro | 202210023 | Autenticação, Zero Trust e Backup (RF02/RF05) |
| Leandro Daniel Lopes Camargo | 202210110 | Monitoramento de integridade, auditoria e usuários do SO (RF01/RF03/RF06) |

---

## Licença

Projeto acadêmico desenvolvido para fins educacionais.
