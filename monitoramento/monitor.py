#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecureChain Audit - Monitoramento de Integridade de Arquivos (RF03)
====================================================================

Monitora o diretório `documentos/` calculando hashes SHA-256 de cada arquivo.
Na inicialização, gera um "baseline" (linha de base) com os hashes de
referência. Em verificações posteriores, compara o estado atual com o baseline
e detecta:

    - ALTERACAO : arquivo existente com hash diferente do de referência;
    - EXCLUSAO  : arquivo do baseline que não existe mais;
    - INCLUSAO  : arquivo novo que não constava no baseline.

Cada inconsistência gera um alerta e um bloco na blockchain de auditoria.
"""

import hashlib
import json
import os
import sys
from datetime import datetime, timezone

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(RAIZ, "blockchain"))
from blockchain import Blockchain  # noqa: E402

DIR_DOCUMENTOS = os.path.join(RAIZ, "documentos")
CAMINHO_BASELINE = os.path.join(RAIZ, "integridade", "baseline.json")


def sha256_arquivo(caminho, bloco=65536):
    """Calcula o SHA-256 de um arquivo lendo em blocos (suporta arquivos grandes)."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for pedaco in iter(lambda: f.read(bloco), b""):
            h.update(pedaco)
    return h.hexdigest()


def coletar_hashes(diretorio):
    """Retorna {caminho_relativo: hash_sha256} para todos os arquivos do diretório."""
    hashes = {}
    for raiz_dir, _, arquivos in os.walk(diretorio):
        for nome in arquivos:
            caminho = os.path.join(raiz_dir, nome)
            rel = os.path.relpath(caminho, diretorio)
            hashes[rel] = sha256_arquivo(caminho)
    return hashes


class MonitorIntegridade:
    def __init__(self):
        self.blockchain = Blockchain()

    # ------------------------------------------------------------------ #
    def inicializar(self):
        """Gera o baseline com os hashes de referência dos documentos."""
        os.makedirs(DIR_DOCUMENTOS, exist_ok=True)
        os.makedirs(os.path.dirname(CAMINHO_BASELINE), exist_ok=True)
        hashes = coletar_hashes(DIR_DOCUMENTOS)
        baseline = {
            "gerado_em": datetime.now(timezone.utc).isoformat(),
            "algoritmo": "sha256",
            "arquivos": hashes,
        }
        with open(CAMINHO_BASELINE, "w", encoding="utf-8") as f:
            json.dump(baseline, f, indent=2, ensure_ascii=False)
        self.blockchain.adicionar_evento(
            f"Baseline de integridade gerado para {len(hashes)} arquivo(s) em documentos/"
        )
        return hashes

    # ------------------------------------------------------------------ #
    def _carregar_baseline(self):
        if not os.path.exists(CAMINHO_BASELINE):
            raise FileNotFoundError(
                "Baseline não encontrado. Execute a inicialização primeiro "
                "(monitor.py init)."
            )
        with open(CAMINHO_BASELINE, "r", encoding="utf-8") as f:
            return json.load(f)["arquivos"]

    def verificar(self):
        """
        Compara o estado atual dos documentos com o baseline.
        Retorna lista de inconsistências; cada uma vira um bloco na blockchain.
        """
        referencia = self._carregar_baseline()
        atual = coletar_hashes(DIR_DOCUMENTOS)

        inconsistencias = []

        # Alterações e exclusões (varre o baseline).
        for arquivo, hash_ref in referencia.items():
            if arquivo not in atual:
                inconsistencias.append({"tipo": "EXCLUSAO", "arquivo": arquivo})
            elif atual[arquivo] != hash_ref:
                inconsistencias.append({
                    "tipo": "ALTERACAO",
                    "arquivo": arquivo,
                    "hash_referencia": hash_ref,
                    "hash_atual": atual[arquivo],
                })

        # Inclusões (arquivos novos não presentes no baseline).
        for arquivo in atual:
            if arquivo not in referencia:
                inconsistencias.append({"tipo": "INCLUSAO", "arquivo": arquivo})

        # Registra cada inconsistência na blockchain e emite alerta.
        for inc in inconsistencias:
            self.blockchain.adicionar_evento(
                f"Integridade: {inc['tipo']} detectada no arquivo '{inc['arquivo']}'"
            )

        return inconsistencias


def _alerta(inconsistencias):
    if not inconsistencias:
        print("[OK] Nenhuma inconsistência detectada. Documentos íntegros.")
        return
    print("\n" + "!" * 60)
    print("  ALERTA DE INTEGRIDADE - DOCUMENTOS MODIFICADOS")
    print("!" * 60)
    for inc in inconsistencias:
        print(f"  [{inc['tipo']:<9}] {inc['arquivo']}")
        if inc["tipo"] == "ALTERACAO":
            print(f"      ref:   {inc['hash_referencia'][:32]}...")
            print(f"      atual: {inc['hash_atual'][:32]}...")
    print("!" * 60)
    print(f"  Total: {len(inconsistencias)} inconsistência(s) registrada(s) na blockchain.\n")


def main():
    monitor = MonitorIntegridade()
    comando = sys.argv[1] if len(sys.argv) > 1 else "ajuda"

    if comando == "init":
        hashes = monitor.inicializar()
        print(f"[OK] Baseline gerado com {len(hashes)} arquivo(s):")
        for arq, h in hashes.items():
            print(f"  {h[:16]}...  {arq}")

    elif comando == "verificar":
        inconsistencias = monitor.verificar()
        _alerta(inconsistencias)
        if inconsistencias:
            sys.exit(1)

    else:
        print("Uso: python3 monitor.py [init|verificar]")


if __name__ == "__main__":
    main()
