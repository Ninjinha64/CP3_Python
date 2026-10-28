"""
Exercício 10 — API Vulnerável (Laboratório Didático)
ATENÇÃO: Apenas para fins de estudo e comprovação defensiva em ambiente local.
Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Falha 6: Credencial mestra exposta no código-fonte (Hardcoded Secret)
SENHA_MESTRA = "Cyber@2024"

# Base de dados em memória simulando a tabela 'usuarios' do MySQL com campo de senha sensível
usuarios_vulneravel_db = [
    {"id": 1, "nome": "administrador", "email": "admin@empresa.com", "senha": "hash_super_secreta_admin"},
    {"id": 2, "nome": "bruno", "email": "bruno@empresa.com", "senha": "hash_senha_bruno_123"},
    {"id": 3, "nome": "carlos", "email": "carlos@empresa.com", "senha": "hash_senha_carlos_456"}
]

# Falha 1 e 5: SQL Injection por interpolação de string + Exposição de dados sensíveis (coluna senha via SELECT *)
@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    # Simula a consulta vulnerável: SELECT * FROM usuarios WHERE nome LIKE '%{nome}%'
    # Quando o atacante injeta: ' OR '1'='1
    if "' OR '1'='1" in nome or "' or 1=1" in nome.lower() or nome == "":
        # Vaza todos os usuários COM a coluna senha
        return jsonify(usuarios_vulneravel_db)
    
    filtrados = [u for u in usuarios_vulneravel_db if nome.lower() in u["nome"].lower()]
    return jsonify(filtrados)

# Falha 2: XSS Reflexivo (interpolação crua sem escape ou sanitização no HTML)
@app.route("/perfil")
def perfil():
    return f"<h1>Bem-vindo, {request.args.get('u','')}</h1>"

# Falha 3: Ausência de Autenticação e Controle de Acesso (Broken Access Control)
@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    global usuarios_vulneravel_db
    usuarios_vulneravel_db = [u for u in usuarios_vulneravel_db if u["id"] != uid]
    return jsonify({"removido": uid})

# Falha 4: Tratamento de erro detalhado que vaza traceback e nomes de estruturas internas
@app.route("/api/relatorio")
def relatorio():
    # Vaza erro de estrutura interna do banco para o cliente
    return "Database Error 500: Table 'seguranca.tabela_inexistente' doesn't exist in query execution. Traceback (most recent call last): File app_vulneravel.py line 42", 500

# Ausência 1: Ausência total de Headers de Segurança HTTP (CSP, X-Content-Type-Options, etc.)
# Ausência 2: Ausência de Rate Limiting, autenticação para rotas sensíveis e trilha de auditoria
# Falha 8: Modo de depuração ativo em ambiente de produção (debug=True, host="0.0.0.0")
if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
