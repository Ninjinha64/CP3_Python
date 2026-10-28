# Relatório de Auditoria de Segurança — OWASP Top 10 (2025)

## Análise Comparativa: `app_vulneravel.py` vs `app_seguro.py`
**Disciplina:** Desenvolvimento em Python / Segurança & Banco de Dados  
**Escopo:** API de Gerenciamento de Usuários e Incidentes  

---

### Tabela de Auditoria de Vulnerabilidades

| # | Falha / Vetor | Código OWASP (2025) | Impacto no Sistema | Correção Aplicada em `app_seguro.py` |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **SQL Injection** em `/api/usuarios/buscar` | **A03:2025 — Injection** | Interpolação de parâmetros não sanitizados permite contornar a consulta (`' OR '1'='1`), extraindo todos os registros da base. | Uso estrito de consultas preparadas e parametrizadas com placeholders (`%s`) delegadas ao driver MySQL. |
| **2** | **XSS Reflexivo** em `/perfil` | **A03:2025 — Injection (Cross-Site Scripting)** | Injeção crua de strings da query string (`f"<h1>...</h1>"`) no HTML, permitindo execução de JavaScript malicioso na vítima. | Renderização através de motor Jinja2 (`render_template_string`) com *autoescaping* de entidades HTML habilitado por padrão. |
| **3** | **Controle de Acesso Quebrado** em `DELETE /api/usuarios/<uid>` | **A01:2025 — Broken Access Control** | Operação destrutiva sem autenticação permite que qualquer agente anônimo remova registros de usuários arbitrariamente. | Implementação de autenticação via header `X-API-Key` (401 se ausente/inválido) e autorização com checagem de privilégio `nivel >= 5` (403). |
| **4** | **Tratamento de Erros Verboso** em `/api/relatorio` | **A05:2025 — Security Misconfiguration** | Erros de banco disparam *stack traces* completos e nomes de tabelas/schemas internos (`seguranca.tabela_inexistente`). | Bloco `try/except` global que suprime detalhes internos e responde JSON opaco uniforme `{"erro": "erro interno"}` com status 500. |
| **5** | **Exposição de Dados Sensíveis** em `/api/usuarios/buscar` | **A04:2025 — Insecure Design** | Consulta com `SELECT *` devolve inadvertidamente campos confidenciais como hashes e senhas nas respostas JSON. | Projeção explícita de campos seguros no SELECT (`SELECT id, nome, email`), omitindo permanentemente a coluna `senha`. |
| **6** | **Segredos em Código-Fonte** (`SENHA_MESTRA = "Cyber@2024"`) | **A07:2025 — Identification and Authentication Failures** | Senhas e credenciais fixadas em texto puro no código vazam em repositórios Git e decompilação de binários. | Remoção da constante sensível e migração de credenciais de conexão para variáveis de ambiente (`os.getenv`). |
| **7** | **[AUSÊNCIA 1] Ausência de Headers de Segurança HTTP** | **A05:2025 — Security Misconfiguration** | Ausência estrutural de cabeçalhos que orientam o navegador a se proteger contra Clickjacking, MIME Sniffing e XSS. | Adição de interceptador `@app.after_request` injetando `Content-Security-Policy: default-src 'self'`, `X-Content-Type-Options: nosniff` e `X-Frame-Options: DENY`. |
| **8** | **[AUSÊNCIA 2] Ausência de Trilha de Auditoria e Rate Limiting** | **A09:2025 — Security Logging and Monitoring Failures** | Falta de rastreabilidade de requisições e ausência de contenção contra ataques de força bruta automatizados. | Implementação de registro de logs de auditoria no MongoDB e limitação comportamental de taxa com status 429. |
| **9** | **Modo Debug e Binding Irrestrito** (`debug=True, host="0.0.0.0"`) | **A05:2025 — Security Misconfiguration** | O console de depuração do Werkzeug permite Execução Remota de Código (RCE) se acessado por terceiros na rede. | Desativação explícita do modo debug (`debug=False`) e escuta vinculada ao localhost (`127.0.0.1`). |

---

### Verificação Prática via `exploit.py`

#### Execução ANTES da correção (`app_vulneravel.py`):
```text
[1] Injeção em /api/usuarios/buscar?nome=' OR '1'='1  -> 3 usuários (VAZAMENTO)
[2] XSS em /perfil?u=<script>alert(1)</script>        -> payload volta cru
[3] DELETE /api/usuarios/2 sem credencial             -> 200 (usuário apagado!)
[4] GET /api/relatorio                                -> 500 com traceback e nome da tabela
[5] Resposta de /api/usuarios/buscar                  -> traz coluna senha
[6] Headers de segurança                              -> ausentes
... 6 ataques bem-sucedidos.
```

#### Execução DEPOIS da correção (`app_seguro.py`):
```text
[1] -> 0 usuários (parametrizado)            DEFENDIDO
[2] -> payload escapado, texto literal       DEFENDIDO
[3] -> 401 sem credencial / 403 sem nível    DEFENDIDO
[4] -> 500 {"erro":"erro interno"} sem detalhe  DEFENDIDO
[5] -> resposta sem a coluna senha           DEFENDIDO
[6] -> 3 headers presentes                   DEFENDIDO
=== 0 de 6 ataques bem-sucedidos ===
```
