#!/usr/bin/env bash
#
# SecureChain Audit - Análise de Segurança da Própria VM (Requisito 7.3)
# =======================================================================
#
# Executa um levantamento de segurança ("hacking ético" defensivo) da própria
# máquina, reunindo evidências para o relatório técnico:
#
#   - nmap        : escaneamento de portas e serviços expostos (localhost)
#   - ss -tulpn   : sockets/serviços em escuta
#   - permissões  : revisão de arquivos e diretórios críticos do sistema
#                   e do próprio projeto
#
# O resultado é salvo em auditoria/relatorios/hacking_etico_<data>.txt
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$SCRIPT_DIR")"
DIR_RELATORIOS="$RAIZ/auditoria/relatorios"
mkdir -p "$DIR_RELATORIOS"

CARIMBO="$(date +%Y%m%d_%H%M%S)"
SAIDA="$DIR_RELATORIOS/hacking_etico_${CARIMBO}.txt"

cabecalho() {
    echo ""
    echo "======================================================================"
    echo "  $1"
    echo "======================================================================"
}

{
    echo "######################################################################"
    echo "  SECURECHAIN AUDIT - ANÁLISE DE SEGURANÇA DA VM (HACKING ÉTICO)"
    echo "  Data: $(date '+%d/%m/%Y %H:%M:%S')"
    echo "  Host: $(hostname)   |   Kernel: $(uname -r)"
    echo "######################################################################"

    cabecalho "1. ESCANEAMENTO DE PORTAS (nmap localhost)"
    if command -v nmap >/dev/null 2>&1; then
        nmap -sT -O --osscan-guess localhost 2>/dev/null || nmap -sT localhost
    else
        echo "[AVISO] nmap não instalado. Instale com: sudo apt install nmap"
    fi

    cabecalho "2. SERVIÇOS EM ESCUTA (ss -tulpn)"
    ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || echo "[ERRO] ss/netstat indisponíveis."

    cabecalho "3. CONEXÕES ESTABELECIDAS (ss -tn state established)"
    ss -tn state established 2>/dev/null || echo "(nenhuma)"

    cabecalho "4. PERMISSÕES DE ARQUIVOS CRÍTICOS DO SISTEMA"
    for arquivo in /etc/passwd /etc/shadow /etc/sudoers /etc/ssh/sshd_config; do
        if [[ -e "$arquivo" ]]; then
            ls -l "$arquivo" 2>/dev/null
        fi
    done

    cabecalho "5. ARQUIVOS COM SUID/SGID (potencial escalonamento de privilégio)"
    find /usr/bin /usr/sbin -perm /6000 -type f 2>/dev/null | head -30

    cabecalho "6. PERMISSÕES DO PROJETO SECURECHAIN"
    ls -lR "$RAIZ" 2>/dev/null | head -80

    cabecalho "7. ARQUIVOS GRAVÁVEIS POR TODOS (world-writable) NO PROJETO"
    find "$RAIZ" -perm -0002 -type f 2>/dev/null || echo "(nenhum - bom sinal)"

    cabecalho "RESUMO / RECOMENDAÇÕES"
    echo "- Verifique se há serviços desnecessários em escuta (item 2) e desative-os."
    echo "- /etc/shadow deve ser 640 root:shadow; credenciais nunca world-readable."
    echo "- usuarios.json do projeto deve ser 600 (somente o dono administrador)."
    echo "- Nenhum arquivo do projeto deve ser world-writable (item 7)."
    echo "- Revise binários SUID/SGID (item 5) e remova os não essenciais."

} | tee "$SAIDA"

echo ""
echo "[OK] Análise concluída. Relatório salvo em:"
echo "     $SAIDA"
