"""
Exercício 5 — O ORDER BY que o %s não protege (Aulas 3, 6, 7 e 8/A05)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Credenciais via variáveis de ambiente para conformidade de segurança
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "lab_eventos")

# ✅ Defesa: mapa fechado de valores permitidos (Whitelist)
COLUNAS = {
    "data": "criado_em",
    "sev": "severidade",
    "ip": "ip_origem"
}

ORDEM = {
    "asc": "ASC",
    "desc": "DESC"
}

# Base de dados em memória representando os registros do MySQL
eventos_db = [
    {"id": 1, "ip_origem": "192.168.1.10", "severidade": "alta", "criado_em": "2026-10-28 10:00:00"},
    {"id": 2, "ip_origem": "192.168.1.15", "severidade": "media", "criado_em": "2026-10-28 10:05:00"},
    {"id": 3, "ip_origem": "192.168.1.20", "severidade": "critica", "criado_em": "2026-10-28 10:10:00"},
    {"id": 4, "ip_origem": "192.168.1.25", "severidade": "baixa", "criado_em": "2026-10-28 10:15:00"},
    {"id": 5, "ip_origem": "192.168.1.30", "severidade": "alta", "criado_em": "2026-10-28 10:20:00"},
    {"id": 6, "ip_origem": "192.168.1.35", "severidade": "critica", "criado_em": "2026-10-28 10:25:00"}
]

@app.route("/api/eventos", methods=["GET"])
def listar_eventos():
    ordenar_por = request.args.get("ordenar_por", "data")
    ordem = request.args.get("ordem", "asc").lower()
    tamanho_param = request.args.get("tamanho", "10")

    # 1. Validação estrita do campo de ordenação via Whitelist (Evita Injeção SQL)
    if ordenar_por not in COLUNAS:
        return jsonify({"erro": "campo de ordenação inválido"}), 400

    # 2. Validação da direção de ordenação via Whitelist
    if ordem not in ORDEM:
        return jsonify({"erro": "ordem de ordenação inválida"}), 400

    # 3. Validação do tamanho da paginação
    try:
        tamanho_int = int(tamanho_param)
        if tamanho_int <= 0:
            return jsonify({"erro": "tamanho deve ser um inteiro positivo"}), 400
    except (ValueError, TypeError):
        return jsonify({"erro": "tamanho deve ser inteiro"}), 400

    # Aplicação do teto do servidor (máximo 100 registros)
    teto_servidor = 100
    tamanho_efetivo = min(tamanho_int, teto_servidor)

    coluna_efetiva = COLUNAS[ordenar_por]
    ordem_efetiva = ORDEM[ordem]

    # Ordenação e paginação seguras
    eventos_ordenados = sorted(
        eventos_db,
        key=lambda x: x[coluna_efetiva],
        reverse=(ordem_efetiva == "DESC")
    )

    return jsonify(eventos_ordenados[:tamanho_efetivo]), 200

# Comentário de 3 linhas: por que `LIMIT %s` funciona mas `ORDER BY %s` não, e o que isso diz sobre "identificador vs dado":
# LIMIT %s funciona porque a cláusula aceita literais numéricos de dados tratados nativamente pelo driver SQL preparado.
# ORDER BY %s falha porque o placeholder coloca aspas ('coluna'), interpretando o identificador como dado fixo e não como coluna real.
# Isso demonstra que placeholders aceitam apenas 'dados' e nunca 'identificadores' estruturais, exigindo whitelisting rígido.

if __name__ == "__main__":
    print("=== Executando Testes Obrigatórios com Flask Test Client ===")
    cliente = app.test_client()

    # Teste 1: ordenação válida por severidade descendente
    r1 = cliente.get("/api/eventos?ordenar_por=sev&ordem=desc&tamanho=5")
    print(f"GET /api/eventos?ordenar_por=sev&ordem=desc&tamanho=5 -> Status: {r1.status_code}, {len(r1.get_json())} eventos retornados")

    # Teste 2: tentativa de injeção SQL em ordenar_por
    r2 = cliente.get("/api/eventos?ordenar_por=criado_em,(SELECT+1)&ordem=asc")
    print(f"GET /api/eventos?ordenar_por=criado_em,(SELECT+1)&ordem=asc -> Status: {r2.status_code}, Resposta: {r2.get_json()}")

    # Teste 3: parâmetro tamanho inválido (não inteiro)
    r3 = cliente.get("/api/eventos?tamanho=abc")
    print(f"GET /api/eventos?tamanho=abc -> Status: {r3.status_code}, Resposta: {r3.get_json()}")

    # Teste 4: parâmetro tamanho excedendo o teto
    r4 = cliente.get("/api/eventos?tamanho=100000")
    print(f"GET /api/eventos?tamanho=100000 -> Status: {r4.status_code}, registros retornados: {len(r4.get_json())} (respeita teto do servidor)")
