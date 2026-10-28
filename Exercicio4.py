"""
Exercício 4 — Transação com trilha de auditoria (Aulas 2, 3 e 8/A09)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from datetime import datetime

# Configuração de credenciais via variáveis de ambiente
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "lab_transacoes")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "lab_auditoria")

class GerenciadorTransacaoMySQL:
    """Implementa o ciclo de vida transacional (start_transaction, commit, rollback)."""
    def __init__(self, dados_iniciais):
        self.tabela = {u[0]: {"id": u[0], "nome": u[1], "email": u[2], "nivel": u[3]} for u in dados_iniciais}
        self.snapshot = None

    def start_transaction(self):
        # Cria cópia do estado para suportar rollback atômico
        self.snapshot = {k: v.copy() for k, v in self.tabela.items()}

    def commit(self):
        # Efetiva as alterações
        self.snapshot = None

    def rollback(self):
        # Restaura o estado anterior à transação
        if self.snapshot is not None:
            self.tabela = {k: v.copy() for k, v in self.snapshot.items()}
            self.snapshot = None

    def obter_usuario(self, uid):
        return self.tabela.get(uid)

    def atualizar_nivel(self, uid, novo_nivel):
        if uid in self.tabela:
            self.tabela[uid]["nivel"] = novo_nivel

class ColecaoAuditoriaMongo:
    """Simula a coleção de auditoria persistente do MongoDB."""
    def __init__(self):
        self.documentos = []

    def insert_one(self, doc):
        self.documentos.append(doc.copy())

    def count_documents(self, filtro):
        return sum(1 for d in self.documentos if all(d.get(k) == v for k, v in filtro.items()))

usuarios_iniciais = [
    (1, "ana", "ana@x.com", 5),
    (2, "bruno", "bruno@x.com", 2),
    (3, "caio", "caio@x.com", 1)
]

db_mysql = GerenciadorTransacaoMySQL(usuarios_iniciais)
db_auditoria = ColecaoAuditoriaMongo()

def alterar_nivel(admin_id: int, alvo_id: int, novo_nivel: int):
    """
    Executa a alteração dentro de uma transação.
    Garante que qualquer tentativa (sucesso ou falha) seja registrada na trilha de auditoria.
    """
    db_mysql.start_transaction()

    admin = db_mysql.obter_usuario(admin_id)
    alvo = db_mysql.obter_usuario(alvo_id)

    # 1. Regra de proteção: Auto-promoção é expressamente recusada
    if admin_id == alvo_id:
        db_mysql.rollback()
        resultado = "RECUSADO"
        nivel_antigo = alvo["nivel"] if alvo else None
        nome_alvo = alvo["nome"].capitalize() if alvo else "Usuário"
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> RECUSADO (auto-promoção). rollback. {nome_alvo}: {nivel_antigo}")

    # 2. Regra de proteção: Apenas admin com nivel >= 5 pode alterar
    elif not admin or admin["nivel"] < 5:
        db_mysql.rollback()
        resultado = "RECUSADO"
        nivel_antigo = alvo["nivel"] if alvo else None
        nome_alvo = alvo["nome"].capitalize() if alvo else "Alvo"
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> RECUSADO (admin sem privilégio). rollback. {nome_alvo}: {nivel_antigo}")

    # 3. Regra de integridade: Alvo deve existir
    elif not alvo:
        db_mysql.rollback()
        resultado = "RECUSADO"
        nivel_antigo = None
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> RECUSADO (alvo inexistente). rollback.")

    # 4. Sucesso: Aplica a alteração e faz COMMIT
    else:
        nivel_antigo = alvo["nivel"]
        nome_alvo = alvo["nome"].capitalize()
        db_mysql.atualizar_nivel(alvo_id, novo_nivel)
        db_mysql.commit()
        resultado = "OK"
        print(f"alterar_nivel({admin_id}, {alvo_id}, {novo_nivel}) -> OK. commit. {nome_alvo}: {nivel_antigo} -> {novo_nivel}")

    # TODA tentativa (aceita ou recusada) vira um documento no MongoDB (coleção auditoria)
    db_auditoria.insert_one({
        "quem": admin_id,
        "alvo": alvo_id,
        "nivel_anterior": nivel_antigo,
        "nivel_novo": novo_nivel,
        "resultado": resultado,
        "timestamp": datetime.now()
    })

if __name__ == "__main__":
    print("=== Executando Sequência de Testes ===")
    alterar_nivel(1, 2, 4)
    alterar_nivel(2, 3, 5)
    alterar_nivel(1, 1, 9)
    alterar_nivel(1, 99, 3)

    total = len(db_auditoria.documentos)
    recusados = db_auditoria.count_documents({"resultado": "RECUSADO"})
    sucessos = total - recusados

    print(f"\nTrilha de auditoria ao final: {total} documentos ({sucessos} sucesso, {recusados} recusas)")
    print(f'db.auditoria.count_documents({{"resultado":"RECUSADO"}}) -> {recusados}')
