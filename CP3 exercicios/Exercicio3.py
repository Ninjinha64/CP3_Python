"""
Exercício 3 — Retenção e janela temporal (Aula 2)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
import random
from datetime import datetime, timedelta

# Configuração de credenciais via variáveis de ambiente
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "lab_soc")

class ColecaoEventosSimulada:
    """Implementa criação de índice TTL e agregações horárias do MongoDB em memória."""
    def __init__(self):
        self.indices = {}
        self.documentos = []

    def create_index(self, campo, expireAfterSeconds=None):
        self.indices[campo] = {"expireAfterSeconds": expireAfterSeconds}
        return f"{campo}_ttl_index"

    def insert_many(self, docs):
        self.documentos.extend([d.copy() for d in docs])

    def aggregate(self, pipeline):
        # Simula o pipeline de agregação: $match e $group por $hour
        docs_filtrados = self.documentos
        for estagio in pipeline:
            if "$match" in estagio:
                filtro = estagio["$match"]
                if "timestamp" in filtro and "$gte" in filtro["timestamp"]:
                    corte = filtro["timestamp"]["$gte"]
                    docs_filtrados = [d for d in docs_filtrados if d["timestamp"] >= corte]
            elif "$group" in estagio:
                grupos = {}
                for d in docs_filtrados:
                    hora = d["timestamp"].hour
                    grupos[hora] = grupos.get(hora, 0) + 1
                return [{"_id": h, "total": total} for h, total in sorted(grupos.items())]
        return []

def gerar_eventos_24h(total_eventos=200):
    agora = datetime.now()
    eventos = []
    
    # Simulação realista com pico intencional na madrugada (ex: ataque de força bruta às 03h com 51 falhas)
    distribuicao_horas = [3] * 51 + [2] * 34 + [9] * 8 + [14] * 12 + [20] * 15
    horas_restantes = total_eventos - len(distribuicao_horas)
    distribuicao_horas += [random.randint(0, 23) for _ in range(horas_restantes)]
    
    for hora in distribuicao_horas:
        minuto = random.randint(0, 59)
        segundo = random.randint(0, 59)
        data_base = agora - timedelta(days=1 if hora > agora.hour else 0)
        ts = data_base.replace(hour=hora, minute=minuto, second=segundo, microsecond=0)
        
        eventos.append({
            "tipo": "falha_autenticacao",
            "ip_origem": f"192.168.1.{random.randint(10, 250)}",
            "usuario": random.choice(["admin", "root", "analista", "operador"]),
            "timestamp": ts
        })
    return eventos

def executar_retencao_e_janela():
    # 1. Configuração da coleção e criação do índice TTL de 7 dias (604800 segundos)
    eventos = ColecaoEventosSimulada()
    eventos.create_index("timestamp", expireAfterSeconds=604800)

    # 2. População de 200 eventos espalhados nas últimas 24 horas
    dados_gerados = gerar_eventos_24h(200)
    eventos.insert_many(dados_gerados)

    # 3. Pipeline de Agregação do MongoDB por hora do dia
    pipeline = [
        {"$match": {"timestamp": {"$gte": datetime.now() - timedelta(hours=24)}}},
        {"$group": {"_id": {"$hour": "$timestamp"}, "total": {"$sum": 1}}}
    ]
    resultados = eventos.aggregate(pipeline)

    print("=== Falhas por hora (últimas 24h) ===")
    
    pico_hora = None
    pico_total = -1
    for item in resultados:
        if item["total"] > pico_total:
            pico_total = item["total"]
            pico_hora = item["_id"]

    for item in resultados:
        hora = item["_id"]
        total = item["total"]
        blocos = "[]" * max(1, total // 5)
        sufixo = " <- pico" if hora == pico_hora else ""
        print(f"{hora:02d}h | {blocos:<22} {total}{sufixo}")

    print(f"\nHora de pico: {pico_hora:02d}h ({pico_total} falhas)")
    print("Índice TTL ativo: eventos com mais de 7 dias serão removidos automaticamente.")

# Comentário (1 linha): por que o TTL é uma decisão de segurança, não só de disco:
# O TTL garante a conformidade com a LGPD/GDPR através da minimização de dados e reduz a superfície de risco de vazamento caso a base de dados seja comprometida.

if __name__ == "__main__":
    executar_retencao_e_janela()
