#!/usr/bin/env bash
#
# SecureChain Audit - Roteiro de Demonstração Automatizada
# =========================================================
#
# Executa, em sequência, todas as funcionalidades do sistema. Útil para a
# gravação do vídeo demonstrativo (mostra login, geração de bloco, monitoramento
# de arquivo, validação da blockchain e backup criptografado).
#
# Uso:  bash scripts/demo.sh
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$SCRIPT_DIR")"
cd "$RAIZ"

linha() { echo; echo "############################################################"; echo "# $1"; echo "############################################################"; }
pausa() { echo; read -r -p ">> ENTER para o próximo passo..." _ || true; }

linha "1) AUTENTICAÇÃO (RF02) — cadastro e login"
python3 autenticacao/auth.py cadastrar demo_admin SenhaForte123 admin || true
python3 autenticacao/auth.py login demo_admin SenhaForte123
echo "-- tentativa com senha errada (deve ser negada e registrada) --"
python3 autenticacao/auth.py login demo_admin senhaErrada || true
pausa

linha "2) MONITORAMENTO DE INTEGRIDADE (RF03) — baseline e verificação"
python3 monitoramento/monitor.py init
echo "-- alterando um documento para simular ataque --"
echo "linha injetada $(date)" >> documentos/contrato_cliente_001.txt
python3 monitoramento/monitor.py verificar || true
echo "-- restaurando o documento --"
sed -i '/linha injetada/d' documentos/contrato_cliente_001.txt
pausa

linha "3) BLOCKCHAIN (RF04) — registrar evento e listar blocos"
python3 blockchain/blockchain.py registrar "Evento de demonstração para o vídeo"
python3 blockchain/blockchain.py listar | tail -20
pausa

linha "4) VALIDAÇÃO DA BLOCKCHAIN (RF07) — cadeia íntegra"
python3 blockchain/blockchain.py validar
pausa

linha "5) AUDITORIA DO SO (RF06)"
python3 auditoria/auditor.py
pausa

linha "6) BACKUP SEGURO AES-256 (RF05)"
SECURECHAIN_BACKUP_PASS="DemoBackup2026" bash backup/backup.sh
echo "-- log de backup --"; tail -3 logs/backup.log

linha "DEMONSTRAÇÃO CONCLUÍDA"
echo "Todos os módulos foram exercitados com sucesso."
