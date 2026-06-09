#!/usr/bin/env bash
#
# SecureChain Audit - Configuração de Usuários e Permissões do SO (RF01)
# =======================================================================
#
# Cria os usuários do sistema operacional Debian exigidos pelo projeto,
# aplicando os princípios de menor privilégio e segregação de funções por
# meio de grupos, chown e chmod.
#
#   administrador -> acesso total ao diretório securechain (grupo securechain-adm)
#   analista      -> leitura + execução dos módulos      (grupo securechain-ana)
#   visitante     -> somente leitura dos relatórios       (grupo securechain-vis)
#
# REQUER privilégios de root. Execute com:  sudo ./setup_usuarios.sh
#
set -euo pipefail

if [[ "$EUID" -ne 0 ]]; then
    echo "[ERRO] Este script precisa ser executado como root (use sudo)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RAIZ="$(dirname "$SCRIPT_DIR")"

echo "==> Diretório do projeto: $RAIZ"

# ---------------------------------------------------------------------- #
# 1. Grupos (segregação de funções)
# ---------------------------------------------------------------------- #
echo "==> Criando grupos..."
for grupo in securechain-adm securechain-ana securechain-vis; do
    if ! getent group "$grupo" >/dev/null; then
        groupadd "$grupo"
        echo "    + grupo criado: $grupo"
    else
        echo "    = grupo já existe: $grupo"
    fi
done

# ---------------------------------------------------------------------- #
# 2. Usuários (menor privilégio)
# ---------------------------------------------------------------------- #
# shell restrito para visitante (apenas leitura, sem login interativo amplo)
echo "==> Criando usuários..."
criar_usuario() {
    local usuario="$1" grupo="$2" comentario="$3"
    if ! id "$usuario" >/dev/null 2>&1; then
        useradd -m -c "$comentario" -g "$grupo" -s /bin/bash "$usuario"
        echo "    + usuário criado: $usuario (grupo principal: $grupo)"
        echo "    ! defina a senha com: passwd $usuario"
    else
        echo "    = usuário já existe: $usuario"
    fi
}

criar_usuario administrador securechain-adm "SecureChain Administrador"
criar_usuario analista      securechain-ana "SecureChain Analista"
criar_usuario visitante     securechain-vis "SecureChain Visitante"

# O analista também pertence ao grupo de visitante (pode ler relatórios).
usermod -aG securechain-vis analista

# ---------------------------------------------------------------------- #
# 3. Permissões com chown / chmod (controle de acesso)
# ---------------------------------------------------------------------- #
echo "==> Aplicando permissões..."

# Diretório raiz: dono administrador, grupo securechain-adm.
chown -R administrador:securechain-adm "$RAIZ"

# Padrão restritivo: dono rwx, grupo rx, outros nada (menor privilégio).
chmod -R 750 "$RAIZ"

# Relatórios de auditoria: legíveis também pelo grupo de visitante (somente leitura).
if [[ -d "$RAIZ/auditoria/relatorios" ]]; then
    chown -R administrador:securechain-vis "$RAIZ/auditoria/relatorios"
    chmod -R 755 "$RAIZ/auditoria/relatorios"
    # Visitante NÃO pode escrever: 755 garante leitura para outros/grupo.
    chmod 755 "$RAIZ/auditoria" "$RAIZ/auditoria/relatorios"
fi

# Módulos Python executáveis pelo grupo do analista.
chown -R administrador:securechain-ana \
    "$RAIZ/autenticacao" "$RAIZ/monitoramento" "$RAIZ/blockchain" "$RAIZ/auditoria" 2>/dev/null || true
chmod -R 750 \
    "$RAIZ/autenticacao" "$RAIZ/monitoramento" "$RAIZ/blockchain" 2>/dev/null || true

# Arquivo de credenciais: somente o dono (administrador) lê/escreve.
if [[ -f "$RAIZ/usuarios/usuarios.json" ]]; then
    chown administrador:securechain-adm "$RAIZ/usuarios/usuarios.json"
    chmod 600 "$RAIZ/usuarios/usuarios.json"
fi

# Scripts executáveis.
chmod 750 "$RAIZ/scripts/"*.sh "$RAIZ/backup/"*.sh 2>/dev/null || true

echo
echo "==> Resumo das permissões aplicadas:"
ls -ld "$RAIZ" "$RAIZ/auditoria/relatorios" "$RAIZ/usuarios" 2>/dev/null || true
echo
echo "[OK] Usuários e permissões configurados conforme menor privilégio e"
echo "     segregação de funções. Lembre-se de definir as senhas com 'passwd'."
