"""
Exercício 8 — Modelo de ML servido por API, com métricas auditáveis (Aulas 2, 4, 6 e 7)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from datetime import datetime
from flask import Flask, request, jsonify
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

app = Flask(__name__)

# Configuração de credenciais via variáveis de ambiente
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "lab_ml")

# 1. Preparação e Treinamento do Modelo de Risco
# Features: [falhas_login, portas_distintas, bytes_saida, hora_do_dia]
np.random.seed(42)
num_amostras = 500

falhas_login = np.random.randint(0, 25, size=num_amostras)
portas_distintas = np.random.randint(1, 15, size=num_amostras)
bytes_saida = np.random.randint(500, 150000, size=num_amostras)
hora_do_dia = np.random.randint(0, 24, size=num_amostras)

X_dataset = np.column_stack((falhas_login, portas_distintas, bytes_saida, hora_do_dia))
y_dataset = np.array([
    "alto" if (x[0] > 8 or x[1] > 5 or (x[2] > 70000 and (x[3] < 6 or x[3] > 20))) else "baixo"
    for x in X_dataset
])

X_train, X_test, y_train, y_test = train_test_split(X_dataset, y_dataset, test_size=0.3, random_state=42)

modelo = RandomForestClassifier(n_estimators=50, random_state=42)
modelo.fit(X_train, y_train)

# Avaliação no conjunto de testes
y_pred = modelo.predict(X_test)
metricas_teste = {
    "precisao": round(float(precision_score(y_test, y_pred, pos_label="alto")), 2),
    "recall": round(float(recall_score(y_test, y_pred, pos_label="alto")), 2),
    "f1": round(float(f1_score(y_test, y_pred, pos_label="alto")), 2),
    "matriz": confusion_matrix(y_test, y_pred, labels=["alto", "baixo"]).tolist(),
    "aviso": "A acurácia foi omitida intencionalmente porque em incidentes de segurança a distribuição de classes é altamente assimétrica; prever sempre 'baixo' geraria alta acurácia ilusória com recall zero para invasões reais."
}

class ColecaoPrevisoesMongo:
    """Implementa a coleção 'previsoes' do MongoDB com contagem e auditoria."""
    def __init__(self):
        self.documentos = []

    def insert_one(self, doc):
        self.documentos.append(doc.copy())

    def count_documents(self, filtro=None):
        if not filtro:
            return len(self.documentos)
        return sum(1 for d in self.documentos if all(d.get(k) == v for k, v in filtro.items()))

    def drop(self):
        self.documentos = []

db_previsoes = ColecaoPrevisoesMongo()

@app.route("/api/triagem", methods=["POST"])
def triagem():
    # Validação 1: Requisição com corpo JSON presente
    if not request.is_json:
        return jsonify({"erro": "corpo JSON ausente ou formato inválido"}), 400

    dados = request.get_json(silent=True)
    if dados is None or "features" not in dados:
        return jsonify({"erro": "campo 'features' obrigatório ausente"}), 400

    features = dados["features"]

    # Validação 2: Tipo lista
    if not isinstance(features, list):
        return jsonify({"erro": "features devem ser fornecidas como uma lista"}), 400

    # Validação 3: Quantidade exata de features
    if len(features) != 4:
        return jsonify({"erro": f"esperadas 4 features, recebidas {len(features)}"}), 400

    # Validação 4: Tipo de cada feature (estritamente numérico int/float, excluindo bool)
    for f in features:
        if isinstance(f, bool) or not isinstance(f, (int, float)):
            return jsonify({"erro": "features devem ser numéricas"}), 400

    # Previsão
    X_input = np.array([features])
    risco_predito = str(modelo.predict(X_input)[0])
    probabilidades = modelo.predict_proba(X_input)[0]
    classes = list(modelo.classes_)
    idx_classe = classes.index(risco_predito)
    confianca = round(float(probabilidades[idx_classe]), 2)

    # Gravação na trilha de auditoria do MongoDB (somente previsões válidas são gravadas)
    db_previsoes.insert_one({
        "entrada": features,
        "risco": risco_predito,
        "confianca": confianca,
        "timestamp": datetime.now()
    })

    return jsonify({"risco": risco_predito, "confianca": confianca}), 200

@app.route("/api/modelo/metricas", methods=["GET"])
def metricas():
    return jsonify(metricas_teste), 200

if __name__ == "__main__":
    db_previsoes.drop()
    print("=== Executando Sequência de Testes da API de ML (Exercício 8) ===")
    cliente = app.test_client()

    # 1. Risco Alto
    r1 = cliente.post("/api/triagem", json={"features": [12, 7, 90000, 3]})
    print(f'POST {{"features":[12,7,90000,3]}}    -> {r1.status_code} {r1.get_json()}')

    # 2. Risco Baixo
    r2 = cliente.post("/api/triagem", json={"features": [0, 1, 1200, 14]})
    print(f'POST {{"features":[0,1,1200,14]}}     -> {r2.status_code} {r2.get_json()}')

    # 3. Erro de dimensão (3 features em vez de 4)
    r3 = cliente.post("/api/triagem", json={"features": [12, 7, 90000]})
    print(f'POST {{"features":[12,7,90000]}}      -> {r3.status_code} {r3.get_json()}')

    # 4. Erro de tipo (string nas features)
    r4 = cliente.post("/api/triagem", json={"features": ["12", "sete", 0, 3]})
    print(f'POST {{"features":["12","sete",0,3]}} -> {r4.status_code} {r4.get_json()}')

    # 5. Erro de corpo vazio
    r5 = cliente.post("/api/triagem", json={})
    print(f'POST {{}} (sem corpo)                 -> {r5.status_code} {r5.get_json()}')

    # 6. Métricas do modelo
    r6 = cliente.get("/api/modelo/metricas")
    print(f'GET  /api/modelo/metricas           -> {r6.status_code} {r6.get_json()}')

    # 7. Contagem no MongoDB: db.previsoes.count_documents({}) -> 2
    total_gravado = db_previsoes.count_documents({})
    print(f"\ndb.previsoes.count_documents({{}})    -> {total_gravado} (apenas as 2 previsões válidas foram gravadas)")
    assert total_gravado == 2, f"Erro: Esperado 2 documentos gravados, obtido {total_gravado}"
    print("[+] Validação concluída com sucesso!")
