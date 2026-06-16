#!/usr/bin/env bash
#
# SecureChain Audit - Backup Seguro Automatizado (RF05)
# ======================================================
#
# Executa:
#   1. Compactação dos documentos em .tar.gz
#   2. Criptografia simétrica AES-256-CBC do arquivo compactado (via openssl)
#   3. Registro do evento de backup na blockchain de auditoria
#   4. Log local com data, tamanho do arquivo e status da operação
#
# Escolha da criptografia (justificada no relatório):
#   AES-256-CBC com derivação de chave PBKDF2 (-pbkdf2 -iter 100000 -salt).
#   AES-256 é um padrão simétrico amplamente auditado, rápido e seguro; o salt
#   + PBKDF2 protegem contra ataques de dicionário/rainbow tables sobre a
#   senha do backup.
#
# Uso:
#   ./backup.sh                  # solicita a senha de criptografia
#   SECURECHAIN_BACKUP_PASS=... ./backup.sh   # senha via variável de ambiente
#
set -euo pipefail

# ---------------------------------------------------------------------- #
# Caminhos (resolvidos a partir da localização do próprio script)
# ---------------------------------------------------------------------- #
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$SCRIPT_DIR")"
DIR_DOCUMENTOS="$RAIZ/documentos"
DIR_BACKUP="$SCRIPT_DIR/arquivos"
DIR_LOGS="$RAIZ/logs"
BLOCKCHAIN_PY="$RAIZ/blockchain/blockchain.py"
LOG_FILE="$DIR_LOGS/backup.log"

mkdir -p "$DIR_BACKUP" "$DIR_LOGS"

CARIMBO="$(date +%Y%m%d_%H%M%S)"
DATA_LEGIVEL="$(date '+%d/%m/%Y %H:%M:%S')"
ARQ_TAR="$DIR_BACKUP/documentos_${CARIMBO}.tar.gz"
ARQ_ENC="${ARQ_TAR}.enc"

# ---------------------------------------------------------------------- #
# Função de log
# ---------------------------------------------------------------------- #
registrar_log() {
    local status="$1"
    local detalhe="$2"
    echo "[$DATA_LEGIVEL] status=$status | $detalhe" >> "$LOG_FILE"
}

falhar() {
    echo "[ERRO] $1" >&2
    registrar_log "FALHA" "$1"
    exit 1
}

# ---------------------------------------------------------------------- #
# Senha de criptografia
# ---------------------------------------------------------------------- #
if [[ -n "${SECURECHAIN_BACKUP_PASS:-}" ]]; then
    SENHA="$SECURECHAIN_BACKUP_PASS"
else
    read -r -s -p "Senha de criptografia do backup: " SENHA
    echo
fi
[[ -z "$SENHA" ]] && falhar "Senha vazia. Backup abortado."

# ---------------------------------------------------------------------- #
# 1. Compactação
# ---------------------------------------------------------------------- #
echo "[*] Compactando documentos..."
if [[ ! -d "$DIR_DOCUMENTOS" ]]; then
    falhar "Diretório de documentos não encontrado: $DIR_DOCUMENTOS"
fi
tar -czf "$ARQ_TAR" -C "$RAIZ" documentos \
    || falhar "Falha ao compactar os documentos."

# ---------------------------------------------------------------------- #
# 2. Criptografia simétrica AES-256-CBC
# ---------------------------------------------------------------------- #
echo "[*] Criptografando backup com AES-256-CBC..."
openssl enc -aes-256-cbc -salt -pbkdf2 -iter 100000 \
    -in "$ARQ_TAR" -out "$ARQ_ENC" -pass pass:"$SENHA" \
    || falhar "Falha na criptografia do backup."

# Remove o .tar.gz em texto claro; mantém apenas a versão criptografada.
rm -f "$ARQ_TAR"
chmod 600 "$ARQ_ENC"

TAMANHO="$(du -h "$ARQ_ENC" | cut -f1)"
TAMANHO_BYTES="$(stat -c%s "$ARQ_ENC")"

# ---------------------------------------------------------------------- #
# 3. Registro na blockchain
# ---------------------------------------------------------------------- #
echo "[*] Registrando evento na blockchain..."
if command -v python3 >/dev/null 2>&1 && [[ -f "$BLOCKCHAIN_PY" ]]; then
    python3 "$BLOCKCHAIN_PY" registrar \
        "Backup executado: $(basename "$ARQ_ENC") (${TAMANHO}, AES-256-CBC)" \
        || echo "[AVISO] Não foi possível registrar na blockchain."
fi

# ---------------------------------------------------------------------- #
# 4. Log final
# ---------------------------------------------------------------------- #
registrar_log "SUCESSO" "arquivo=$(basename "$ARQ_ENC") tamanho=${TAMANHO} (${TAMANHO_BYTES} bytes) cripto=AES-256-CBC"

echo
echo "[OK] Backup concluído com sucesso."
echo "     Arquivo:  $ARQ_ENC"
echo "     Tamanho:  $TAMANHO"
echo "     Log:      $LOG_FILE"
echo
echo "Para restaurar:"
echo "  openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 -in <arquivo>.enc -out restaurado.tar.gz -pass pass:<senha>"
echo "  tar -xzf restaurado.tar.gz"
