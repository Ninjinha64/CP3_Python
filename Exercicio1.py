"""
Exercício 1 — Assistente de decisão de armazenamento (Aulas 1 e 8)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados
"""

perfis = {
    "credenciais_do_SOC": {
        "schema_fixo": True,
        "precisa_acid": True,
        "escala_horizontal": False,
        "tolera_atraso_de_consistencia": False,
        "dado_sensivel": True
    },
    "telemetria_de_sensores": {
        "schema_fixo": False,
        "precisa_acid": False,
        "escala_horizontal": True,
        "tolera_atraso_de_consistencia": True,
        "dado_sensivel": False
    },
    "trilha_de_auditoria": {
        "schema_fixo": False,
        "precisa_acid": False,
        "escala_horizontal": True,
        "tolera_atraso_de_consistencia": False,
        "dado_sensivel": True
    },
    "carrinho_de_licencas": {
        "schema_fixo": True,
        "precisa_acid": True,
        "escala_horizontal": False,
        "tolera_atraso_de_consistencia": False,
        "dado_sensivel": True
    },
    "cache_de_sessoes": {
        "schema_fixo": True,
        "precisa_acid": False,
        "escala_horizontal": True,
        "tolera_atraso_de_consistencia": True,
        "dado_sensivel": False
    }
}

def recomendar(perfil: dict, nome: str = None) -> dict:
    """
    Recebe o perfil de um conjunto de dados e devolve uma recomendação fundamentada:
    qual banco usar (MySQL ou MongoDB), qual lado do Teorema CAP priorizar (CP ou AP),
    uma justificativa nomeando o erro inaceitável no cenário e o risco OWASP correspondente.
    """
    # 1. Decisão arquitetural de banco:
    # Se requer ACID estrito, schema rígido e não prioriza escala horizontal elástica -> Modelo Relacional (MySQL)
    # Se precisa de ingestão dinâmica, schema flexível ou escala horizontal distribuída -> Documentos NoSQL (MongoDB)
    usa_relacional = perfil.get("schema_fixo", False) and perfil.get("precisa_acid", False) and not perfil.get("escala_horizontal", False)
    banco = "MySQL" if usa_relacional else "MongoDB"

    # 2. Decisão no Teorema CAP:
    # Se não tolera consistência eventual (atrasos de sincronização invalidam os dados) -> CP (Consistência + Tolerância a Partições)
    # Se alta disponibilidade contínua é prioritária e tolera sincronização assíncrona -> AP (Disponibilidade + Tolerância a Partições)
    cap = "AP" if perfil.get("tolera_atraso_de_consistencia", False) else "CP"

    # 3. Base de conhecimento contextual para justificativa nomeando o erro inaceitável e risco OWASP (2025)
    cenarios = {
        "credenciais_do_SOC": {
            "justificativa": "autenticar errado é pior que ficar fora do ar",
            "risco_owasp": "A07"  # Identification and Authentication Failures
        },
        "telemetria_de_sensores": {
            "justificativa": "perder 1s de log < parar de aceitar log",
            "risco_owasp": "A09"  # Security Logging and Monitoring Failures
        },
        "trilha_de_auditoria": {
            "justificativa": "auditoria divergente não vale como prova",
            "risco_owasp": "A08"  # Software and Data Integrity Failures
        },
        "carrinho_de_licencas": {
            "justificativa": "venda duplicada ou concessão sem pagamento causa prejuízo financeiro e desvio de controle",
            "risco_owasp": "A04"  # Insecure Design
        },
        "cache_de_sessoes": {
            "justificativa": "sessão temporariamente dessincronizada é preferível à indisponibilidade de login sob alta concorrência",
            "risco_owasp": "A07"  # Identification and Authentication Failures
        }
    }

    # Identifica o perfil pelo nome fornecido ou pela chave se embutida
    chave_encontrada = nome or perfil.get("nome")

    if chave_encontrada and chave_encontrada in cenarios:
        detalhes = cenarios[chave_encontrada]
    else:
        # Fallback analítico para perfis dinâmicos
        if not perfil.get("tolera_atraso_de_consistencia", False):
            if perfil.get("precisa_acid", False):
                justificativa = "inconsistência em transações financeiras/críticas gera estado inválido e perdas irreparáveis"
                risco = "A04"
            else:
                justificativa = "divergência em registros probatórios ou auditoria invalida a custódia das evidências"
                risco = "A08"
        else:
            if not perfil.get("dado_sensivel", False):
                justificativa = "bloqueios por sincronismo síncrono causariam negação de serviço indesejada na ingestão de telemetria"
                risco = "A09"
            else:
                justificativa = "sessão expirada ou atraso de sincronia é tolerável em favor da disponibilidade contínua"
                risco = "A07"
        detalhes = {"justificativa": justificativa, "risco_owasp": risco}

    return {
        "banco": banco,
        "cap": cap,
        "justificativa": detalhes["justificativa"],
        "risco_owasp": detalhes["risco_owasp"]
    }

if __name__ == "__main__":
    print("=== Recomendações de Armazenamento e CAP ===")
    for nome, perfil in perfis.items():
        res = recomendar(perfil, nome=nome)
        print(f'{nome:<24} -> {res["banco"]} | {res["cap"]} | "{res["justificativa"]}" | {res["risco_owasp"]}')
