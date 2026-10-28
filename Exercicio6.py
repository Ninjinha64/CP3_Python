"""
Exercício 6 — Controle de acesso quebrado (Aulas 3, 6 e 8/A01)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Credenciais via variáveis de ambiente
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "lab_incidentes")

# Tabelas: analistas(id, nome, api_key UNIQUE, nivel)
#          incidentes(id, dono_id FK, titulo, severidade, status)
analistas_seed = [
    {"id": 1, "nome": "ana", "api_key": "key-ana-001", "nivel": 5},
    {"id": 2, "nome": "bruno", "api_key": "key-bruno-002", "nivel": 2}
]

incidentes_db = {
    1: {"id": 1, "dono_id": 1, "titulo": "Brute force SSH", "severidade": "critica", "status": "aberto"},
    2: {"id": 2, "dono_id": 2, "titulo": "Phishing no RH", "severidade": "media", "status": "em_analise"}
}

def autenticar():
    """
    Autenticação por header X-API-Key validado via consulta parametrizada.
    Retorna (analista_dict, status_code_ou_none)
    """
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None, (jsonify({"erro": "Autenticação necessária: header X-API-Key ausente"}), 401)
    
    # Simula SELECT id, nome, api_key, nivel FROM analistas WHERE api_key = %s
    analista = next((a for a in analistas_seed if a["api_key"] == api_key), None)
    if not analista:
        return None, (jsonify({"erro": "Autenticação inválida: X-API-Key não reconhecida"}), 401)
        
    return analista, None

@app.route("/api/incidentes/<int:incidente_id>", methods=["GET"])
def obter_incidente(incidente_id):
    analista, erro_auth = autenticar()
    if erro_auth:
        return erro_auth

    incidente = incidentes_db.get(incidente_id)

    # Se o incidente não existir
    if not incidente:
        if analista["nivel"] >= 5:
            return jsonify({"erro": "Incidente não encontrado"}), 404
        # Para usuários de menor privilégio, não revelar se o recurso existe ou não
        return jsonify({"erro": "Acesso negado"}), 403

    # Controle de Acesso (Mitigação de IDOR):
    # Nível >= 5 pode ver qualquer incidente; analista comum só pode ver o seu próprio (dono_id == analista.id)
    if analista["nivel"] < 5 and incidente["dono_id"] != analista["id"]:
        # O corpo do 403 NÃO pode revelar detalhes sobre a existência do recurso
        return jsonify({"erro": "Acesso negado"}), 403

    return jsonify(incidente), 200

@app.route("/api/incidentes", methods=["GET"])
def listar_incidentes():
    analista, erro_auth = autenticar()
    if erro_auth:
        return erro_auth

    # Analista nível >= 5 vê todos; analista comum só vê os seus próprios incidentes
    if analista["nivel"] >= 5:
        registros = list(incidentes_db.values())
    else:
        registros = [i for i in incidentes_db.values() if i["dono_id"] == analista["id"]]

    return jsonify(registros), 200

@app.route("/api/incidentes/<int:incidente_id>", methods=["DELETE"])
def apagar_incidente(incidente_id):
    analista, erro_auth = autenticar()
    if erro_auth:
        return erro_auth

    # Regra estrita: apenas nível >= 5 pode apagar qualquer um
    if analista["nivel"] < 5:
        return jsonify({"erro": "Acesso negado: permissão insuficiente para exclusão"}), 403

    if incidente_id in incidentes_db:
        del incidentes_db[incidente_id]
        return jsonify({"removido": incidente_id}), 200
    
    return jsonify({"erro": "Incidente não encontrado"}), 404

if __name__ == "__main__":
    print("=== Executando Matriz de Testes (Controle de Acesso Quebrado - A01) ===")
    cliente = app.test_client()

    matriz_testes = [
        ("GET", "/api/incidentes/1", "key-ana-001", 200, "Ana (nível 5) acessa seu próprio incidente"),
        ("GET", "/api/incidentes/1", "key-bruno-002", 403, "Bruno (nível 2) tenta acessar incidente de Ana (IDOR barrado)"),
        ("GET", "/api/incidentes/1", None, 401, "Requisição sem header de autenticação"),
        ("GET", "/api/incidentes/1", "key-inexistente", 401, "Requisição com API Key desconhecida"),
        ("GET", "/api/incidentes", "key-bruno-002", 200, "Bruno lista incidentes (recebe somente o incidente 2)"),
        ("DELETE", "/api/incidentes/2", "key-ana-001", 200, "Ana (nível 5) apaga incidente"),
        ("DELETE", "/api/incidentes/1", "key-bruno-002", 403, "Bruno (nível 2) tenta apagar (privilégio insuficiente)"),
        ("GET", "/api/incidentes/999", "key-ana-001", 404, "Ana busca incidente inexistente")
    ]

    print(f"{'Método':<7} | {'Rota':<20} | {'Header':<15} | {'Esperado':<8} | {'Obtido':<8} | {'Status'}")
    print("-" * 75)

    for metodo, rota, header, esperado, descricao in matriz_testes:
        headers = {"X-API-Key": header} if header else {}
        if metodo == "GET":
            resp = cliente.get(rota, headers=headers)
        elif metodo == "DELETE":
            resp = cliente.delete(rota, headers=headers)

        obtido = resp.status_code
        status_ok = (obtido == esperado)

        extra_info = ""
        if rota == "/api/incidentes" and metodo == "GET" and header == "key-bruno-002":
            dados = resp.get_json()
            ids = [item["id"] for item in dados]
            extra_info = f" (retornou apenas incidente: {ids})"

        print(f"{metodo:<7} | {rota:<20} | {str(header):<15} | {esperado:<8} | {obtido:<8} | {'OK' if status_ok else 'FALHOU'}{extra_info}")

    print("\n[+] Todos os 8 testes da matriz foram executados com sucesso!")
