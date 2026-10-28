"""
Exercício 10 (Desafio) — Antes e depois: prove o ataque, aplique a defesa, prove a defesa
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Este script executa a demonstração completa do Exercício 10 utilizando o exploit.py
contra a API vulnerável (app_vulneravel.py) e em seguida contra a versão mitigada (app_seguro.py).
"""

import subprocess
import sys

def main():
    print("=================================================================")
    print("Exercício 10 (Desafio) — Demonstração Prática de Ataque e Defesa")
    print("=================================================================\n")
    
    # Executa o exploit.py no modo comparativo completo
    from exploit import testar_aplicacao
    from app_vulneravel import app as app_vuln
    from app_seguro import app as app_sec

    print("=== [ETAPA 1] Executando exploits CONTRA app_vulneravel.py ===")
    testar_aplicacao(app_vuln.test_client(), "app_vulneravel")

    print("\n" + "=" * 65 + "\n")

    print("=== [ETAPA 2] Executando os MESMOS exploits CONTRA app_seguro.py ===")
    testar_aplicacao(app_sec.test_client(), "app_seguro")

if __name__ == "__main__":
    main()
