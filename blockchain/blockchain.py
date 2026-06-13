#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChain Audit - Blockchain de Auditoria (RF04 e RF07)
==========================================================

Implementa uma blockchain simples, porém funcional, usada como trilha de
auditoria imutável. Cada evento relevante do sistema (login, alteração de
arquivo, backup, criação de usuário, etc.) gera um bloco encadeado por hash.

Estrutura de cada bloco (campos obrigatórios do enunciado):
    id            -> identificador sequencial único do bloco
    timestamp     -> data/hora em formato ISO 8601
    evento        -> descrição textual do evento ocorrido
    hash_anterior -> SHA-256 do bloco anterior (garante o encadeamento)
    hash_atual    -> SHA-256 calculado sobre todos os campos do bloco

A imutabilidade vem do encadeamento: alterar qualquer campo de um bloco muda o
seu hash_atual, o que quebra o campo hash_anterior do bloco seguinte. A função
validar_cadeia() detecta exatamente esse tipo de adulteração (RF07).
"""

import hashlib
import json
import os
from datetime import datetime, timezone

# Caminho padrão de persistência da cadeia (chain.json no mesmo diretório).
DIRETORIO_ATUAL = os.path.dirname(os.path.abspath(__file__))
CAMINHO_CHAIN_PADRAO = os.path.join(DIRETORIO_ATUAL, "chain.json")


def agora_iso():
    """Retorna o instante atual em ISO 8601 com fuso horário (UTC)."""
    return datetime.now(timezone.utc).isoformat()


class Bloco:
    """Representa um único bloco da cadeia de auditoria."""

    def __init__(self, indice, timestamp, evento, hash_anterior, hash_atual=None):
        self.id = indice
        self.timestamp = timestamp
        self.evento = evento
        self.hash_anterior = hash_anterior
        # Se o hash não for fornecido, é calculado a partir dos demais campos.
        self.hash_atual = hash_atual if hash_atual else self.calcular_hash()

    def calcular_hash(self):
        """
        Calcula o SHA-256 sobre os campos id, timestamp, evento e hash_anterior.

        Usamos json.dumps com sort_keys=True para obter uma representação
        canônica e determinística — o mesmo conteúdo produz sempre o mesmo hash,
        independentemente da ordem em que os campos aparecem.
        """
        conteudo = {
            "id": self.id,
            "timestamp": self.timestamp,
            "evento": self.evento,
            "hash_anterior": self.hash_anterior,
        }
        bloco_serializado = json.dumps(conteudo, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(bloco_serializado.encode("utf-8")).hexdigest()

    def to_dict(self):
        """Converte o bloco para dicionário (para persistência em JSON)."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "evento": self.evento,
            "hash_anterior": self.hash_anterior,
            "hash_atual": self.hash_atual,
        }

    @staticmethod
    def from_dict(dados):
        """Reconstrói um bloco a partir de um dicionário lido do chain.json."""
        return Bloco(
            indice=dados["id"],
            timestamp=dados["timestamp"],
            evento=dados["evento"],
            hash_anterior=dados["hash_anterior"],
            hash_atual=dados["hash_atual"],
        )


class Blockchain:
    """Gerencia a cadeia de blocos: criação, persistência e validação."""

    def __init__(self, caminho=CAMINHO_CHAIN_PADRAO):
        self.caminho = caminho
        self.cadeia = []
        self._carregar()

    # ------------------------------------------------------------------ #
    # Persistência
    # ------------------------------------------------------------------ #
    def _carregar(self):
        """Carrega a cadeia do disco; cria o bloco gênesis se não existir."""
        if os.path.exists(self.caminho):
            try:
                with open(self.caminho, "r", encoding="utf-8") as arquivo:
                    dados = json.load(arquivo)
                self.cadeia = [Bloco.from_dict(b) for b in dados]
            except (json.JSONDecodeError, KeyError):
                # chain.json corrompido a nível de arquivo. Preservamos para
                # análise forense e reiniciamos a cadeia em memória.
                self.cadeia = []
        if not self.cadeia:
            self._criar_genesis()
            self._salvar()

    def _salvar(self):
        """Persiste a cadeia atual no chain.json."""
        with open(self.caminho, "w", encoding="utf-8") as arquivo:
            json.dump(
                [b.to_dict() for b in self.cadeia],
                arquivo,
                indent=2,
                ensure_ascii=False,
            )

    # ------------------------------------------------------------------ #
    # Operações da cadeia
    # ------------------------------------------------------------------ #
    def _criar_genesis(self):
        """Cria o bloco gênesis (primeiro bloco, sem antecessor)."""
        genesis = Bloco(
            indice=0,
            timestamp=agora_iso(),
            evento="GENESIS - inicialização da blockchain de auditoria",
            hash_anterior="0" * 64,
        )
        self.cadeia = [genesis]

    def ultimo_bloco(self):
        """Retorna o bloco mais recente da cadeia."""
        return self.cadeia[-1]

    def adicionar_evento(self, evento):
        """
        Cria e encadeia um novo bloco para o evento informado.
        Retorna o bloco criado.
        """
        anterior = self.ultimo_bloco()
        novo = Bloco(
            indice=anterior.id + 1,
            timestamp=agora_iso(),
            evento=evento,
            hash_anterior=anterior.hash_atual,
        )
        self.cadeia.append(novo)
        self._salvar()
        return novo

    # ------------------------------------------------------------------ #
    # Validação (RF07)
    # ------------------------------------------------------------------ #
    def validar_cadeia(self):
        """
        Percorre toda a cadeia em busca de sinais de manipulação.

        Detecta:
          1. Bloco cujo hash recalculado difere do hash armazenado
             (adulteração direta do conteúdo de um bloco);
          2. hash_anterior de um bloco diferente do hash_atual do bloco anterior
             (quebra do encadeamento).

        Retorna uma tupla (valida, problemas), onde 'problemas' é uma lista de
        dicionários descrevendo cada inconsistência encontrada.
        """
        problemas = []

        for i, bloco in enumerate(self.cadeia):
            # (1) Adulteração direta: o hash não corresponde ao conteúdo.
            hash_recalculado = bloco.calcular_hash()
            if hash_recalculado != bloco.hash_atual:
                problemas.append({
                    "bloco_id": bloco.id,
                    "tipo": "ADULTERACAO_DIRETA",
                    "detalhe": (
                        f"Hash armazenado ({bloco.hash_atual[:16]}...) difere do "
                        f"hash recalculado ({hash_recalculado[:16]}...). O conteúdo "
                        f"do bloco foi alterado."
                    ),
                })

            if i == 0:
                # O bloco gênesis não tem antecessor real para comparar.
                continue

            anterior = self.cadeia[i - 1]

            # (2) Quebra de encadeamento.
            if bloco.hash_anterior != anterior.hash_atual:
                problemas.append({
                    "bloco_id": bloco.id,
                    "tipo": "QUEBRA_ENCADEAMENTO",
                    "detalhe": (
                        f"hash_anterior do bloco {bloco.id} não corresponde ao "
                        f"hash_atual do bloco {anterior.id}. A cadeia foi rompida."
                    ),
                })

        return (len(problemas) == 0, problemas)

    # ------------------------------------------------------------------ #
    # Utilidades
    # ------------------------------------------------------------------ #
    def listar(self):
        """Retorna a cadeia como lista de dicionários."""
        return [b.to_dict() for b in self.cadeia]

    def __len__(self):
        return len(self.cadeia)


# ---------------------------------------------------------------------- #
# Interface de linha de comando
# ---------------------------------------------------------------------- #
def _alerta_administrador(problemas):
    """Exibe um alerta claro para o administrador (RF07)."""
    print("\n" + "=" * 60)
    print("  ALERTA DE SEGURANÇA - INTEGRIDADE DA BLOCKCHAIN COMPROMETIDA")
    print("=" * 60)
    for p in problemas:
        print(f"  [BLOCO {p['bloco_id']}] {p['tipo']}")
        print(f"      -> {p['detalhe']}")
    print("=" * 60)
    print("  Ação recomendada: investigar imediatamente os blocos acima.")
    print("=" * 60 + "\n")


def main():
    import sys

    bc = Blockchain()
    comando = sys.argv[1] if len(sys.argv) > 1 else "ajuda"

    if comando == "validar":
        valida, problemas = bc.validar_cadeia()
        if valida:
            print(f"[OK] Blockchain íntegra. {len(bc)} blocos validados.")
        else:
            _alerta_administrador(problemas)
            sys.exit(1)

    elif comando == "listar":
        for b in bc.listar():
            print(f"#{b['id']:>3} | {b['timestamp']} | {b['evento']}")
            print(f"       hash_anterior: {b['hash_anterior']}")
            print(f"       hash_atual:    {b['hash_atual']}")
            print("-" * 70)

    elif comando == "registrar":
        evento = " ".join(sys.argv[2:]) or "evento manual de teste"
        bloco = bc.adicionar_evento(evento)
        print(f"[OK] Bloco #{bloco.id} registrado: {bloco.evento}")

    else:
        print("Uso: python3 blockchain.py [validar|listar|registrar <evento>]")


if __name__ == "__main__":
    main()
