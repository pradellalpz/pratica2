#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChain Audit - Auditoria do Sistema Operacional (RF06)
============================================================

Coleta informações de segurança do sistema operacional e gera um relatório
datado no diretório `auditoria/relatorios/`. O evento de auditoria é
registrado na blockchain.

Comandos coletados:
    who          -> usuários atualmente conectados
    last         -> histórico de logins
    ss -tulpn    -> portas e serviços em escuta (sockets TCP/UDP)
    ip a         -> interfaces de rede e endereços IP
"""

import os
import subprocess
import sys
from datetime import datetime

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "blockchain"))
from blockchain import Blockchain  # noqa: E402

DIR_RELATORIOS = os.path.join(RAIZ, "auditoria", "relatorios")

# Comandos auditados. Listas (não strings) para evitar shell injection.
COMANDOS = [
    ("Usuários conectados (who)", ["who"]),
    ("Histórico de logins (last)", ["last", "-n", "25"]),
    ("Portas e serviços em escuta (ss -tulpn)", ["ss", "-tulpn"]),
    ("Interfaces de rede (ip a)", ["ip", "a"]),
]


def executar(comando):
    """Executa um comando do sistema e devolve a saída como texto."""
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        saida = resultado.stdout.strip()
        if resultado.stderr.strip():
            saida += "\n[stderr] " + resultado.stderr.strip()
        return saida or "(sem saída)"
    except FileNotFoundError:
        return f"[ERRO] Comando '{comando[0]}' não encontrado neste sistema."
    except subprocess.TimeoutExpired:
        return f"[ERRO] Comando '{comando[0]}' excedeu o tempo limite."


def gerar_relatorio():
    """Coleta os dados, grava o relatório datado e registra na blockchain."""
    os.makedirs(DIR_RELATORIOS, exist_ok=True)
    agora = datetime.now()
    carimbo = agora.strftime("%Y%m%d_%H%M%S")
    caminho = os.path.join(DIR_RELATORIOS, f"auditoria_{carimbo}.txt")

    linhas = []
    linhas.append("=" * 70)
    linhas.append("  SECURECHAIN AUDIT - RELATÓRIO DE AUDITORIA DO SISTEMA")
    linhas.append(f"  Gerado em: {agora.strftime('%d/%m/%Y %H:%M:%S')}")
    linhas.append(f"  Host: {os.uname().nodename}")
    linhas.append("=" * 70)

    for titulo, comando in COMANDOS:
        linhas.append("")
        linhas.append("-" * 70)
        linhas.append(f"# {titulo}")
        linhas.append(f"# comando: {' '.join(comando)}")
        linhas.append("-" * 70)
        linhas.append(executar(comando))

    conteudo = "\n".join(linhas) + "\n"
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)

    # Registra na blockchain.
    Blockchain().adicionar_evento(
        f"Auditoria do SO executada -> relatorio salvo em "
        f"auditoria/relatorios/auditoria_{carimbo}.txt"
    )
    return caminho


def main():
    caminho = gerar_relatorio()
    print(f"[OK] Relatório de auditoria gerado em:\n  {caminho}")
    print("[OK] Evento registrado na blockchain de auditoria.")


if __name__ == "__main__":
    main()
