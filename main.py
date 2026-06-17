#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChain Audit - Interface Integradora (CLI)
================================================

Menu interativo que reúne todos os módulos da plataforma:
    - Autenticação (login/cadastro)        -> autenticacao/auth.py
    - Monitoramento de integridade (RF03)  -> monitoramento/monitor.py
    - Blockchain de auditoria (RF04/RF07)  -> blockchain/blockchain.py
    - Auditoria do SO (RF06)               -> auditoria/auditor.py
    - Backup seguro (RF05)                 -> backup/backup.sh

O controle de acesso segue o princípio do menor privilégio: cada ação exige
um perfil mínimo (admin / analista / visitante).

Uso:
    python3 main.py
"""

import os
import subprocess
import sys

RAIZ = os.path.dirname(os.path.abspath(__file__))
for sub in ("blockchain", "autenticacao", "monitoramento", "auditoria"):
    sys.path.insert(0, os.path.join(RAIZ, sub))

from blockchain import Blockchain          # noqa: E402
from auth import GerenciadorAuth           # noqa: E402
from monitor import MonitorIntegridade, _alerta  # noqa: E402
import auditor                             # noqa: E402


def pausar():
    input("\nPressione ENTER para continuar...")


def cabecalho():
    print("\n" + "=" * 60)
    print("        SECURECHAIN AUDIT - Plataforma de Auditoria")
    print("=" * 60)


def tela_login(auth):
    cabecalho()
    print("  [1] Login")
    print("  [2] Cadastrar usuário (requer admin, ou primeiro usuário)")
    print("  [0] Sair")
    opcao = input("\n> ").strip()

    if opcao == "1":
        usuario = input("Usuário: ").strip()
        senha = input("Senha: ").strip()
        if auth.login(usuario, senha):
            print(f"\n[OK] Bem-vindo, {usuario}! Perfil ativo: {auth.perfil_ativo()}")
        else:
            print("\n[FALHA] Credenciais inválidas. Tentativa registrada na blockchain.")
        pausar()

    elif opcao == "2":
        # Primeiro usuário do sistema pode ser criado sem login (bootstrap admin);
        # depois disso, apenas administradores cadastram novos usuários.
        if auth.usuarios and not (auth.sessao_ativa() and auth.perfil_ativo() == "admin"):
            print("\n[NEGADO] Apenas administradores podem cadastrar novos usuários.")
            pausar()
            return
        usuario = input("Novo usuário: ").strip()
        senha = input("Senha (mín. 8 caracteres): ").strip()
        perfil = input("Perfil (admin/analista/visitante): ").strip()
        try:
            auth.cadastrar(usuario, senha, perfil)
            print(f"\n[OK] Usuário '{usuario}' cadastrado como '{perfil}'.")
        except ValueError as e:
            print(f"\n[ERRO] {e}")
        pausar()

    elif opcao == "0":
        sys.exit(0)


def menu_principal(auth):
    cabecalho()
    print(f"  Usuário: {auth.sessao['username']} | Perfil: {auth.perfil_ativo()}")
    print("-" * 60)
    print("  [1] Registrar evento manual na blockchain")
    print("  [2] Listar blocos da blockchain")
    print("  [3] Validar integridade da blockchain (RF07)")
    print("  [4] Inicializar baseline de integridade (RF03)   [admin]")
    print("  [5] Verificar integridade dos documentos (RF03)")
    print("  [6] Executar auditoria do SO (RF06)              [admin/analista]")
    print("  [7] Executar backup seguro (RF05)                [admin]")
    print("  [8] Cadastrar usuário                            [admin]")
    print("  [9] Logout")
    print("  [0] Sair")
    opcao = input("\n> ").strip()

    bc = Blockchain()

    try:
        if opcao == "1":
            evento = input("Descrição do evento: ").strip()
            bloco = bc.adicionar_evento(f"[{auth.sessao['username']}] {evento}")
            print(f"\n[OK] Bloco #{bloco.id} registrado.")

        elif opcao == "2":
            for b in bc.listar():
                print(f"#{b['id']:>3} | {b['timestamp']} | {b['evento']}")

        elif opcao == "3":
            valida, problemas = bc.validar_cadeia()
            if valida:
                print(f"\n[OK] Blockchain íntegra. {len(bc)} blocos validados.")
            else:
                print("\n[ALERTA] Blockchain comprometida:")
                for p in problemas:
                    print(f"  [BLOCO {p['bloco_id']}] {p['tipo']}: {p['detalhe']}")

        elif opcao == "4":
            auth.exige_perfil("admin")
            hashes = MonitorIntegridade().inicializar()
            print(f"\n[OK] Baseline gerado para {len(hashes)} arquivo(s).")

        elif opcao == "5":
            auth.exige_perfil("admin", "analista", "visitante")
            inconsistencias = MonitorIntegridade().verificar()
            _alerta(inconsistencias)

        elif opcao == "6":
            auth.exige_perfil("admin", "analista")
            caminho = auditor.gerar_relatorio()
            print(f"\n[OK] Relatório de auditoria salvo em:\n  {caminho}")

        elif opcao == "7":
            auth.exige_perfil("admin")
            script = os.path.join(RAIZ, "backup", "backup.sh")
            subprocess.run(["bash", script], check=False)

        elif opcao == "8":
            auth.exige_perfil("admin")
            usuario = input("Novo usuário: ").strip()
            senha = input("Senha (mín. 8): ").strip()
            perfil = input("Perfil (admin/analista/visitante): ").strip()
            auth.cadastrar(usuario, senha, perfil)
            print(f"\n[OK] Usuário '{usuario}' cadastrado.")

        elif opcao == "9":
            auth.logout()
            print("\n[OK] Sessão encerrada.")
            return

        elif opcao == "0":
            sys.exit(0)

    except PermissionError as e:
        print(f"\n[NEGADO] {e}")
    except (ValueError, FileNotFoundError) as e:
        print(f"\n[ERRO] {e}")

    pausar()


def main():
    auth = GerenciadorAuth()
    print("\nSecureChain Audit iniciado.")
    if not auth.usuarios:
        print("Nenhum usuário cadastrado ainda. Use a opção [2] para criar o admin inicial.")
    while True:
        if not auth.sessao_ativa():
            tela_login(auth)
        else:
            menu_principal(auth)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nEncerrando SecureChain Audit. Até logo.")
