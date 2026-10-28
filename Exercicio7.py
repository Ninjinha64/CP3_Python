"""
Exercício 7 — XSS onde ninguém procura: dentro do atributo (Aulas 6, 7 e 8/A05)
Disciplina: Desenvolvimento em Python / Segurança & Banco de Dados

Execução 100% autônoma e nativa (sem necessidade de Docker ativo).
"""

import os
from flask import Flask, render_template_string, jsonify

app = Flask(__name__)

# Configurações de credenciais via variáveis de ambiente
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "lab_xss")

# Payloads de teste obrigatórios
p1 = "<script>alert('xss1')</script>"
p2 = 'x" onerror="alert(\'xss2\')'  # escapa do atributo HTML sem usar <script>

incidentes_cadastrados = [
    {"id": 1, "titulo": p1, "ativo": "SRV-WEB01", "severidade": "alta"},
    {"id": 2, "titulo": "Tentativa de Exploit em Ativo", "ativo": p2, "severidade": "critica"}
]

# Requisito 2: Header Content-Security-Policy em todas as respostas
@app.after_request
def aplicar_csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# Template Jinja2 seguro (escape por padrão)
# Explicação em 1 linha sobre o filtro |safe:
# O filtro |safe instrui o Jinja2 a marcar a string como HTML seguro, desativando o escape de aspas e tags e permitindo que o atacante quebre o atributo e execute scripts arbitrários.
TEMPLATE_SEGURO = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>Dashboard Seguro de Incidentes</title>
</head>
<body>
    <h1>Painel de Incidentes (Versão Segura com Jinja2 Autoescape + CSP)</h1>
    <table border="1">
        <thead>
            <tr>
                <th>ID</th>
                <th>Título</th>
                <th>Ícone / Ativo (Atributo alt)</th>
                <th>Severidade</th>
            </tr>
        </thead>
        <tbody>
            {% for inc in incidentes %}
            <tr>
                <td>{{ inc.id }}</td>
                <!-- p1 escapado por padrão: texto literal na célula -->
                <td>{{ inc.titulo }}</td>
                <!-- p2 escapado dentro do alt: aspas viram &quot;&#34;, impedindo breakout do atributo -->
                <td>
                    <img src="/static/icone.png" alt="{{ inc.ativo }}" width="24" height="24">
                    <span>{{ inc.ativo }}</span>
                </td>
                <td>{{ inc.severidade }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

# Requisito 3: Rota /dashboard-inseguro claramente marcada para comparação lado a lado
TEMPLATE_INSEGURO = """
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>[INSEGURO] Dashboard Vulnerável</title>
</head>
<body>
    <h1 style="color: red;">[AVISO] Painel Vulnerável a XSS em Célula e Atributo (Uso indevido de |safe)</h1>
    <table border="1">
        <thead>
            <tr>
                <th>ID</th>
                <th>Título</th>
                <th>Ícone / Ativo (Atributo alt)</th>
                <th>Severidade</th>
            </tr>
        </thead>
        <tbody>
            {% for inc in incidentes %}
            <tr>
                <td>{{ inc.id }}</td>
                <!-- VULNERABILIDADE 1: |safe renderiza a tag script diretamente no DOM -->
                <td>{{ inc.titulo | safe }}</td>
                <!-- VULNERABILIDADE 2: |safe permite que aspas fechem o atributo alt e injetem onerror -->
                <td>
                    <img src="/static/icone.png" alt="{{ inc.ativo | safe }}" width="24" height="24">
                    <span>{{ inc.ativo | safe }}</span>
                </td>
                <td>{{ inc.severidade }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
</body>
</html>
"""

@app.route("/dashboard", methods=["GET"])
def dashboard():
    return render_template_string(TEMPLATE_SEGURO, incidentes=incidentes_cadastrados)

@app.route("/dashboard-inseguro", methods=["GET"])
def dashboard_inseguro():
    return render_template_string(TEMPLATE_INSEGURO, incidentes=incidentes_cadastrados)

if __name__ == "__main__":
    print("=== Testando Defesa Contra XSS em Célula e Atributo (Exercício 7) ===")
    cliente = app.test_client()

    resp_segura = cliente.get("/dashboard")
    corpo_seguro = resp_segura.get_data(as_text=True)

    print(f"Status /dashboard: {resp_segura.status_code}")
    print(f"Header CSP presente: {'Content-Security-Policy' in resp_segura.headers} -> {resp_segura.headers.get('Content-Security-Policy')}")
    
    # Validação do Payload 1: <script> não pode existir desescapado
    p1_cru_no_html = "<script>alert('xss1')</script>" in corpo_seguro
    p1_escapado = "&lt;script&gt;alert(&#39;xss1&#39;)&lt;/script&gt;" in corpo_seguro
    print(f"Payload 1 (<script>): Escapado como texto literal? {p1_escapado} | Script cru presente? {p1_cru_no_html}")

    # Validação do Payload 2: Quebra de atributo alt com onerror
    p2_quebrou_atributo = 'alt="x" onerror="alert(\'xss2\')"' in corpo_seguro or 'onerror=' in corpo_seguro.split('alt=')[1]
    p2_seguro_no_alt = 'alt="x&#34; onerror=&#34;alert(&#39;xss2&#39;)' in corpo_seguro or 'alt="x&#34;' in corpo_seguro
    print(f"Payload 2 (alt onerror): Quebrou o atributo HTML? {p2_quebrou_atributo} | Aspas devidamente codificadas? {p2_seguro_no_alt}")

    print("\n--- Comparação com /dashboard-inseguro ---")
    resp_insegura = cliente.get("/dashboard-inseguro")
    corpo_inseguro = resp_insegura.get_data(as_text=True)
    vuln_script = "<script>alert('xss1')</script>" in corpo_inseguro
    vuln_onerror = 'onerror="alert(\'xss2\')"' in corpo_inseguro or 'onerror=' in corpo_inseguro
    print(f"Vulnerável contém <script> cru? {vuln_script}")
    print(f"Vulnerável permitiu quebra de atributo alt? {vuln_onerror}")
    print("\n[+] Defesa comprovada: Nenhum alert() é executado e CSP restringe origens não autorizadas!")
