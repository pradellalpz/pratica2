#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChain Audit - Sistema de Autenticação (RF02 e Zero Trust)
================================================================

Módulo responsável por cadastro, login, controle de sessão e perfis de
usuário da aplicação SecureChain. Todo acesso (bem-sucedido ou negado) é
registrado de forma imutável na blockchain de auditoria.

Segurança de senhas (RF02 / Requisito 7.1):
    As senhas NUNCA são armazenadas em texto puro. Utilizamos PBKDF2-HMAC-SHA256
    (hashlib.pbkdf2_hmac, biblioteca padrão do Python) com:
        - salt aleatório de 16 bytes por usuário (os.urandom);
        - 200.000 iterações (key stretching contra força bruta);
    Isso atende ao requisito "SHA-256 com salt" de forma robusta e sem
    dependências externas — o PBKDF2 é a forma recomendada de derivar/armazenar
    senhas usando SHA-256 como primitiva. A comparação usa hmac.compare_digest
    para evitar ataques de temporização (timing attacks).
"""

import hashlib
import hmac
import json
import os
import re
import sys
from datetime import datetime, timezone

# Permite importar o módulo da blockchain a partir de outro diretório.
RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "blockchain"))
from blockchain import Blockchain  # noqa: E402

# Perfis válidos e suas descrições (separação de funções).
PERFIS_VALIDOS = {
    "admin": "Administrador - acesso total ao sistema securechain",
    "analista": "Analista - leitura e execução dos módulos",
    "visitante": "Visitante - somente leitura dos relatórios",
}

CAMINHO_USUARIOS = os.path.join(RAIZ, "usuarios", "usuarios.json")

# Parâmetros do PBKDF2.
ALGORITMO = "sha256"
ITERACOES = 200_000
TAMANHO_SALT = 16


# ---------------------------------------------------------------------- #
# Funções de hash de senha
# ---------------------------------------------------------------------- #
def gerar_hash_senha(senha, salt=None):
    """
    Deriva o hash da senha com PBKDF2-HMAC-SHA256.
    Retorna (salt_hex, hash_hex).
    """
    if salt is None:
        salt = os.urandom(TAMANHO_SALT)
    derivado = hashlib.pbkdf2_hmac(
        ALGORITMO, senha.encode("utf-8"), salt, ITERACOES
    )
    return salt.hex(), derivado.hex()


def verificar_senha(senha, salt_hex, hash_hex):
    """Confere a senha informada contra o hash armazenado (tempo constante)."""
    salt = bytes.fromhex(salt_hex)
    _, hash_calculado = gerar_hash_senha(senha, salt)
    return hmac.compare_digest(hash_calculado, hash_hex)


# ---------------------------------------------------------------------- #
# Validação de entrada (mitiga injeção / dados malformados - Req. 7.4)
# ---------------------------------------------------------------------- #
def validar_username(username):
    """Aceita apenas letras, números, ponto, hífen e underscore (3-32)."""
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", username):
        raise ValueError(
            "Usuário inválido: use 3-32 caracteres [A-Za-z0-9._-]."
        )
    return username


def validar_senha(senha):
    """Exige senha minimamente forte (mínimo 8 caracteres)."""
    if not isinstance(senha, str) or len(senha) < 8:
        raise ValueError("Senha inválida: mínimo de 8 caracteres.")
    return senha


def validar_perfil(perfil):
    if perfil not in PERFIS_VALIDOS:
        raise ValueError(
            f"Perfil inválido: '{perfil}'. Use um de {list(PERFIS_VALIDOS)}."
        )
    return perfil


# ---------------------------------------------------------------------- #
# Gerenciador de usuários e autenticação
# ---------------------------------------------------------------------- #
class GerenciadorAuth:
    """Cadastro, login e controle de sessão integrados à blockchain."""

    def __init__(self):
        self.blockchain = Blockchain()
        self.usuarios = self._carregar_usuarios()
        self.sessao = None  # dict {username, perfil, login_em}

    # --------------------------- persistência --------------------------- #
    def _carregar_usuarios(self):
        if os.path.exists(CAMINHO_USUARIOS):
            with open(CAMINHO_USUARIOS, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _salvar_usuarios(self):
        os.makedirs(os.path.dirname(CAMINHO_USUARIOS), exist_ok=True)
        with open(CAMINHO_USUARIOS, "w", encoding="utf-8") as f:
            json.dump(self.usuarios, f, indent=2, ensure_ascii=False)
        # Restringe a leitura do arquivo de credenciais (menor privilégio).
        try:
            os.chmod(CAMINHO_USUARIOS, 0o600)
        except OSError:
            pass

    # ----------------------------- cadastro ----------------------------- #
    def cadastrar(self, username, senha, perfil):
        """Cadastra um novo usuário e registra o evento na blockchain."""
        validar_username(username)
        validar_senha(senha)
        validar_perfil(perfil)

        if username in self.usuarios:
            raise ValueError(f"Usuário '{username}' já existe.")

        salt_hex, hash_hex = gerar_hash_senha(senha)
        self.usuarios[username] = {
            "perfil": perfil,
            "salt": salt_hex,
            "hash": hash_hex,
            "algoritmo": f"pbkdf2_{ALGORITMO}",
            "iteracoes": ITERACOES,
            "criado_em": datetime.now(timezone.utc).isoformat(),
        }
        self._salvar_usuarios()
        self.blockchain.adicionar_evento(
            f"Usuário criado: '{username}' (perfil={perfil})"
        )
        return True

    def remover(self, username):
        """Remove um usuário e registra o evento na blockchain."""
        if username not in self.usuarios:
            raise ValueError(f"Usuário '{username}' não existe.")
        del self.usuarios[username]
        self._salvar_usuarios()
        self.blockchain.adicionar_evento(f"Usuário removido: '{username}'")
        return True

    # ------------------------------ login ------------------------------- #
    def login(self, username, senha):
        """
        Autentica o usuário. Registra na blockchain tanto o sucesso quanto a
        tentativa negada (Zero Trust: todo acesso é auditado).
        """
        usuario = self.usuarios.get(username)
        if usuario and verificar_senha(senha, usuario["salt"], usuario["hash"]):
            self.sessao = {
                "username": username,
                "perfil": usuario["perfil"],
                "login_em": datetime.now(timezone.utc).isoformat(),
            }
            self.blockchain.adicionar_evento(
                f"Login realizado: '{username}' (perfil={usuario['perfil']})"
            )
            return True

        # Falha — não revela se o usuário existe ou se a senha está errada.
        self.blockchain.adicionar_evento(
            f"Tentativa de acesso negada para o usuário '{username}'"
        )
        return False

    def logout(self):
        if self.sessao:
            usuario = self.sessao["username"]
            self.blockchain.adicionar_evento(f"Logout: '{usuario}'")
            self.sessao = None

    # -------------------------- controle de acesso ---------------------- #
    def sessao_ativa(self):
        return self.sessao is not None

    def perfil_ativo(self):
        return self.sessao["perfil"] if self.sessao else None

    def exige_perfil(self, *perfis_permitidos):
        """
        Verifica se o perfil ativo está autorizado. Lança PermissionError caso
        contrário (Zero Trust: a identidade é verificada a cada ação sensível).
        """
        if not self.sessao_ativa():
            raise PermissionError("Nenhuma sessão ativa. Faça login primeiro.")
        if self.perfil_ativo() not in perfis_permitidos:
            self.blockchain.adicionar_evento(
                f"Acesso negado: '{self.sessao['username']}' "
                f"(perfil={self.perfil_ativo()}) tentou ação restrita a {perfis_permitidos}"
            )
            raise PermissionError(
                f"Perfil '{self.perfil_ativo()}' não autorizado. "
                f"Requer: {perfis_permitidos}."
            )
        return True


# ---------------------------------------------------------------------- #
# CLI de teste do módulo
# ---------------------------------------------------------------------- #
def main():
    auth = GerenciadorAuth()
    comando = sys.argv[1] if len(sys.argv) > 1 else "ajuda"

    if comando == "cadastrar" and len(sys.argv) == 5:
        _, _, username, senha, perfil = sys.argv
        auth.cadastrar(username, senha, perfil)
        print(f"[OK] Usuário '{username}' cadastrado com perfil '{perfil}'.")

    elif comando == "login" and len(sys.argv) == 4:
        _, _, username, senha = sys.argv
        if auth.login(username, senha):
            print(f"[OK] Login bem-sucedido. Perfil ativo: {auth.perfil_ativo()}")
        else:
            print("[FALHA] Usuário ou senha inválidos. Evento registrado.")
            sys.exit(1)

    elif comando == "listar":
        for nome, dados in auth.usuarios.items():
            print(f"  {nome:<16} perfil={dados['perfil']:<10} criado_em={dados['criado_em']}")

    else:
        print("Uso:")
        print("  python3 auth.py cadastrar <usuario> <senha> <admin|analista|visitante>")
        print("  python3 auth.py login <usuario> <senha>")
        print("  python3 auth.py listar")


if __name__ == "__main__":
    main()
