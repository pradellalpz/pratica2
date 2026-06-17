#!/usr/bin/env bash
#
# SecureChain Audit - Limpeza de Artefatos de Runtime
# ====================================================
#
# Remove dados gerados em execução (credenciais, baseline, relatórios, backups,
# logs) e reinicia a blockchain com apenas o bloco gênesis. Útil para começar
# uma demonstração do zero.
#
# Uso:  bash scripts/reset.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$SCRIPT_DIR")"

echo "==> Limpando artefatos de runtime em $RAIZ ..."
rm -f  "$RAIZ/usuarios/usuarios.json"
rm -f  "$RAIZ/integridade/baseline.json"
rm -f  "$RAIZ/auditoria/relatorios/"*.txt
rm -f  "$RAIZ/backup/arquivos/"*.enc
rm -f  "$RAIZ/logs/"*.log
rm -rf "$RAIZ/blockchain/__pycache__" "$RAIZ"/*/__pycache__

# Reinicia a blockchain (apenas gênesis).
rm -f "$RAIZ/blockchain/chain.json"
python3 -c "import sys; sys.path.insert(0, '$RAIZ/blockchain'); from blockchain import Blockchain; Blockchain()"

echo "[OK] Ambiente reiniciado. Blockchain contém apenas o bloco gênesis."
