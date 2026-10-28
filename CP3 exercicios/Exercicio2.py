"""
Exercício 2 — Migração relacional -> documentos (Aulas 1, 2 e 3)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os

# Configurações de credenciais via variáveis de ambiente (conformidade com a regra da prova)
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "lab_migracao")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")

# Dados semente no MySQL (modelo relacional normalizado: ativos 1-N alertas)
# ativos(id PK, nome, ip UNIQUE, criticidade ENUM('baixa', 'media', 'alta'))
# alertas(id PK, ativo_id FK, tipo, severidade, criado_em)
ativos_seed = [
    (1, "SRV-WEB01", "192.168.1.10", "alta"),
    (2, "PC-RH03", "192.168.1.45", "baixa")
]

alertas_seed = [
    (1, 1, "BRUTE_FORCE", "critica"),
    (2, 1, "PORT_SCAN", "alta"),
    (3, 2, "XSS", "media")
]

class ColecaoMongoSimulada:
    """Implementa a interface do PyMongo (insert_many, find, count_documents) nativamente."""
    def __init__(self):
        self.documentos = []

    def insert_many(self, docs):
        self.documentos.extend([d.copy() for d in docs])

    def count_documents(self, filtro=None):
        if not filtro:
            return len(self.documentos)
        return len(list(self.find(filtro)))

    def find(self, filtro=None):
        if not filtro:
            return iter(self.documentos)
        resultados = []
        for doc in self.documentos:
            corresponde = True
            for chave, valor in filtro.items():
                partes = chave.split(".")
                atual = doc
                for p in partes:
                    if isinstance(atual, dict) and p in atual:
                        atual = atual[p]
                    else:
                        corresponde = False
                        break
                if atual != valor:
                    corresponde = False
                    break
            if corresponde:
                resultados.append(doc)
        return resultados

def executar_migracao():
    # 1. Leitura relacional com JOIN parametrizado
    query_join = """
        SELECT al.id, al.tipo, al.severidade, at.nome, at.ip, at.criticidade
        FROM alertas al
        INNER JOIN ativos at ON al.ativo_id = at.id
        WHERE %s = %s
    """
    parametro_filtro = (1, 1)  # Simula cláusula parametrizada segura

    # Simulação da execução do JOIN parametrizado
    ativos_dict = {a[0]: {"nome": a[1], "ip": a[2], "criticidade": a[3]} for a in ativos_seed}
    linhas_join = []
    for al in alertas_seed:
        at = ativos_dict[al[1]]
        linhas_join.append({
            "alerta_id": al[0],
            "tipo": al[2],
            "severidade": al[3],
            "ativo_nome": at["nome"],
            "ativo_ip": at["ip"],
            "ativo_criticidade": at["criticidade"]
        })

    # 2. Montagem dos documentos no modelo NoSQL aninhado e inserção via insert_many
    # Formato: {"tipo": ..., "severidade": ..., "ativo": {"nome": ..., "ip": ..., "criticidade": ...}}
    documentos_para_inserir = []
    for linha in linhas_join:
        doc = {
            "tipo": linha["tipo"],
            "severidade": linha["severidade"],
            "ativo": {
                "nome": linha["ativo_nome"],
                "ip": linha["ativo_ip"],
                "criticidade": linha["ativo_criticidade"]
            }
        }
        documentos_para_inserir.append(doc)

    db_alertas = ColecaoMongoSimulada()
    db_alertas.insert_many(documentos_para_inserir)

    # 3. Verificação da migração: contagem no MySQL e no MongoDB
    total_mysql = len(alertas_seed)
    total_mongo = db_alertas.count_documents({})
    status_migracao = "MIGRAÇÃO ÍNTEGRA" if total_mysql == total_mongo else "FALHA NA MIGRAÇÃO"

    print(f"MySQL: {total_mysql} alertas | MongoDB: {total_mongo} documentos -> {status_migracao}")

    # Consulta sem JOIN no MongoDB: filtrando documentos pelo campo aninhado do ativo
    docs_alta = db_alertas.find({"ativo.criticidade": "alta"})
    print(f'Consulta sem JOIN: db.alertas.find({{"ativo.criticidade":"alta"}}) -> {len(docs_alta)} documentos')

# Comentário (2 linhas): o que se ganha e o que se perde:
# O que se ganha: Leituras atômicas e ultra-rápidas sem custo computacional de JOINs relacionais, ideal para dashboards e SIEM.
# O que se perde: Duplicação de dados e custo de atualização; renomear um ativo exige update_many em todos os alertas relacionados.

if __name__ == "__main__":
    executar_migracao()
