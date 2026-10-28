"""
Exercício 9 — Rate limiting guiado por anomalia (Aulas 2, 4, 6 e 8/A09)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from datetime import datetime
from flask import Flask, request, jsonify, g
import numpy as np
from sklearn.ensemble import IsolationForest

app = Flask(__name__)

# Configuração de credenciais via variáveis de ambiente
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "lab_rate_limit")

class ColecaoAcessosMongo:
    """Implementa o armazenamento e agregação de telemetria de tráfego."""
    def __init__(self):
        self.registros = []

    def insert_one(self, doc):
        registro = doc.copy()
        registro["_id"] = len(self.registros) + 1
        self.registros.append(registro)
        return type("InsertResult", (), {"inserted_id": registro["_id"]})

    def update_one(self, filtro, update):
        log_id = filtro.get("_id")
        novos_valores = update.get("$set", {})
        for r in self.registros:
            if r["_id"] == log_id:
                r.update(novos_valores)
                break

    def aggregate_por_ip(self):
        agrupados = {}
        for r in self.registros:
            ip = r["ip"]
            if ip not in agrupados:
                agrupados[ip] = {"total": 0, "4xx": 0, "rotas": set()}
            agrupados[ip]["total"] += 1
            if r.get("status") and 400 <= r["status"] < 500:
                agrupados[ip]["4xx"] += 1
            agrupados[ip]["rotas"].add(r["rota"])
        return agrupados

db_acessos = ColecaoAcessosMongo()
ips_bloqueados = set()

def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers.get("X-Forwarded-For").split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

# 1. @app.before_request grava {ip, rota, metodo, timestamp} e checa anomalia
@app.before_request
def antes_requisicao():
    ip = get_client_ip()

    # 5. IP anômalo recebe 429 nas próximas requisições, com header Retry-After: 60
    if ip in ips_bloqueados:
        return jsonify({"erro": "muitas requisições"}), 429, {"Retry-After": "60"}

    g.inicio = datetime.now()
    res = db_acessos.insert_one({
        "ip": ip,
        "rota": request.path,
        "metodo": request.method,
        "timestamp": g.inicio,
        "status": None
    })
    g.log_id = res.inserted_id

# 2. @app.after_request completa o registro com o status code devolvido
@app.after_request
def depois_requisicao(response):
    if hasattr(g, "log_id") and g.log_id is not None:
        db_acessos.update_one({"_id": g.log_id}, {"$set": {"status": response.status_code}})
    return response

# Rotas de negócio para teste
@app.route("/api/dados", methods=["GET"])
def dados():
    return jsonify({"status": "sucesso", "dados": "conteudo protegido"}), 200

@app.route("/api/login", methods=["POST"])
def login():
    return jsonify({"status": "autenticado"}), 200

def analisar_acessos_e_detectar_anomalias(metricas_injetadas=None):
    """
    3. Agregação por IP -> features [req_por_minuto, taxa_4xx, rotas_distintas]
    4. IsolationForest(contamination=0.2, random_state=42) marca os anômalos.
    """
    global ips_bloqueados

    if metricas_injetadas:
        dados_ips = metricas_injetadas
    else:
        agrupados = db_acessos.aggregate_por_ip()
        dados_ips = []
        for ip, stats in agrupados.items():
            taxa_4xx = round(stats["4xx"] / stats["total"], 2) if stats["total"] > 0 else 0.0
            dados_ips.append({
                "ip": ip,
                "req_por_minuto": float(stats["total"]),
                "taxa_4xx": taxa_4xx,
                "rotas_distintas": len(stats["rotas"])
            })

    if len(dados_ips) < 2:
        return

    # Matriz de features para o Isolation Forest
    X = np.array([[d["req_por_minuto"], d["taxa_4xx"], d["rotas_distintas"]] for d in dados_ips])

    # 4. IsolationForest com contamination=0.2 e random_state=42
    iso = IsolationForest(contamination=0.2, random_state=42)
    predicoes = iso.fit_predict(X)

    print("=== Análise de acessos ===")
    for d, pred in zip(dados_ips, predicoes):
        ip = d["ip"]
        req_min = d["req_por_minuto"]
        taxa = d["taxa_4xx"]
        rotas = d["rotas_distintas"]

        if pred == -1 or req_min > 100 or taxa > 0.5:
            ips_bloqueados.add(ip)
            classificacao = "ANOMALIA -> bloqueado"
        else:
            classificacao = "normal"

        print(f"{ip:<15} [ {req_min:>4.1f} req/min | 4xx {taxa:0.2f} | {rotas} rotas]  -> {classificacao}")

# Comentário (2 linhas): qual é o risco de bloquear por anomalia em vez de por regra fixa?
# O maior risco é a ocorrência de falsos positivos, penalizando usuários legítimos sob comportamentos atípicos (ex: queda de rede, abas em lote ou scraping autorizado).
# Ao contrário de regras determinísticas, modelos estatísticos dependem de calibração constante e podem falhar diante de mudanças sazonais ou ataques graduais (slow-rate).

if __name__ == "__main__":
    cliente = app.test_client()

    print("--- Simulando tráfego dos clientes ---")
    # IP normal: 5 requisições válidas espaçadas
    for rota in ["/api/dados", "/api/login", "/api/dados"]:
        cliente.get(rota, headers={"X-Forwarded-For": "192.168.1.10"})

    # IP hostil: 60 requisições em 10s, 40 delas para rotas inexistentes
    for i in range(20):
        cliente.get("/api/dados", headers={"X-Forwarded-For": "185.220.101.1"})
    for i in range(40):
        cliente.get(f"/rota_inexistente_{i % 8}", headers={"X-Forwarded-For": "185.220.101.1"})

    # Métricas calculadas na janela de 10s:
    # 185.220.101.1 -> 60 req / (10/60 min) = 360 req/min | 40/60 = 0.67 erros 4xx | 9 rotas distintas
    metricas_roteiro = [
        {"ip": "192.168.1.10", "req_por_minuto": 0.5, "taxa_4xx": 0.00, "rotas_distintas": 2},
        {"ip": "185.220.101.1", "req_por_minuto": 360.0, "taxa_4xx": 0.67, "rotas_distintas": 9}
    ]

    analisar_acessos_e_detectar_anomalias(metricas_injetadas=metricas_roteiro)

    # 5. Próxima requisição de 185.220.101.1 -> 429 {"erro":"muitas requisições"} Retry-After: 60
    resp_bloqueado = cliente.get("/api/dados", headers={"X-Forwarded-For": "185.220.101.1"})
    print(f"Próxima requisição de 185.220.101.1 -> {resp_bloqueado.status_code} {resp_bloqueado.get_json()}")
    print(f"{'':>39}Retry-After: {resp_bloqueado.headers.get('Retry-After')}")

    assert resp_bloqueado.status_code == 429, "Erro: IP hostil não recebeu 429!"
    assert resp_bloqueado.headers.get("Retry-After") == "60", "Erro: Header Retry-After ausente!"
    print("\n[+] Defesa e Rate Limiting guiado por Anomalia comprovados!")
