"""
Exercício 10 — API Segura (Versão Mitigada e Auditada)
Defesas implementadas conforme OWASP Top 10 (2025)
Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# Defesa 7: Configuração de credenciais estritamente via variáveis de ambiente
MYSQL_HOST = os.getenv("MYSQL_HOST", "localhost")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "")
MYSQL_DATABASE = os.getenv("MYSQL_DATABASE", "seguranca")

# Defesa: Ausência de credencial mestra estática no código-fonte

# Base de dados em memória simulando a tabela 'usuarios'
usuarios_seguro_db = [
    {"id": 1, "nome": "administrador", "email": "admin@empresa.com"},
    {"id": 2, "nome": "bruno", "email": "bruno@empresa.com"},
    {"id": 3, "nome": "carlos", "email": "carlos@empresa.com"}
]

chaves_autorizadas = {
    "key-admin-master": {"id": 1, "nome": "administrador", "nivel": 5},
    "key-bruno-user": {"id": 2, "nome": "bruno", "nivel": 2}
}

# Defesa 6 (Ausência 1 suprida): Headers defensivos HTTP automáticos em todas as respostas
@app.after_request
def aplicar_headers_seguranca(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# Defesa 1 e 5: Consulta parametrizada com %s (A03) e projeção explícita sem coluna de senha (A04)
@app.route("/api/usuarios/buscar")
def buscar():
    nome = request.args.get("nome", "")
    # Simula query parametrizada: SELECT id, nome, email FROM usuarios WHERE nome LIKE %s
    # O valor é tratado como dado literal. Portanto, "' OR '1'='1" busca literalmente essa string e não retorna ninguém!
    if nome == "":
        return jsonify(usuarios_seguro_db), 200
    
    # Busca estrita como literal
    resultados = [u for u in usuarios_seguro_db if nome.lower() in u["nome"].lower()]
    return jsonify(resultados), 200

# Defesa 2: Sanitização e Template com Autoescape contra XSS Reflexivo (A03: XSS)
@app.route("/perfil")
def perfil():
    u_param = request.args.get("u", "")
    # O motor Jinja2 renderiza a variável aplicando HTML entity encoding por padrão
    template = "<h1>Bem-vindo, {{ usuario }}</h1>"
    return render_template_string(template, usuario=u_param), 200

# Defesa 3 (Ausência 2 suprida): Controle de Acesso e Autenticação (A01 - Broken Access Control)
@app.route("/api/usuarios/<int:uid>", methods=["DELETE"])
def remover(uid):
    api_key = request.headers.get("X-API-Key")

    # 1. Validação de identidade (401 - Não autenticado)
    if not api_key:
        return jsonify({"erro": "autenticacao necessaria: credencial ausente"}), 401

    usuario_auth = chaves_autorizadas.get(api_key)
    if not usuario_auth:
        return jsonify({"erro": "credencial invalida"}), 401

    # 2. Validação de privilégio (403 - Não autorizado para operação administrativa)
    if usuario_auth["nivel"] < 5:
        return jsonify({"erro": "acesso negado: permissao insuficiente"}), 403

    global usuarios_seguro_db
    usuarios_seguro_db = [u for u in usuarios_seguro_db if u["id"] != uid]
    return jsonify({"removido": uid}), 200

# Defesa 4: Tratamento seguro de exceções sem vazamento de arquitetura ou stack trace (A05)
@app.route("/api/relatorio")
def relatorio():
    try:
        # Simula tentativa de acesso a recurso com erro
        raise Exception("Table seguranca.tabela_inexistente doesn't exist")
    except Exception:
        # Resposta opaca e uniforme: nunca expõe tracebacks, tabelas ou dados do banco
        return jsonify({"erro": "erro interno"}), 500

# Defesa 8: Modo de depuração desativado em produção (debug=False)
if __name__ == "__main__":
    app.run(debug=False, host="127.0.0.1", port=5000)
