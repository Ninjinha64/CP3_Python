# Checkpoint 3 (CP3) — Python, Bancos de Dados & Segurança (Aulas 1 a 8)

Todos os 10 exercícios estão implementados de forma **100% autônoma e nativa**, sem dependência de Docker.

---

## 📁 Estrutura de Arquivos

| Arquivo | Exercício Correspondente | Descrição |
| :--- | :--- | :--- |
| [`Exercicio1.py`](Exercicio1.py) | **Exercício 1** | Assistente de decisão de armazenamento: Recomendação fundamentada (MySQL vs MongoDB, Teorema CAP e riscos OWASP 2025). |
| [`Exercicio2.py`](Exercicio2.py) | **Exercício 2** | Migração relacional para documentos: Leitura via JOIN parametrizado e gravação de documentos aninhados. |
| [`Exercicio3.py`](Exercicio3.py) | **Exercício 3** | Retenção e janela temporal: Criação de índice TTL, agregação por hora e detecção de pico de incidentes. |
| [`Exercicio4.py`](Exercicio4.py) | **Exercício 4** | Transação com trilha de auditoria: Transações atômicas (`commit`/`rollback`) com auditoria persistente. |
| [`Exercicio5.py`](Exercicio5.py) | **Exercício 5** | Proteção de `ORDER BY`: API Flask com defesa estrita baseada em Whitelist e validação de paginação. |
| [`Exercicio6.py`](Exercicio6.py) | **Exercício 6** | Controle de acesso quebrado (A01): API de incidentes com autenticação `X-API-Key`, mitigação de IDOR e matriz de testes 401/403/404. |
| [`Exercicio7.py`](Exercicio7.py) | **Exercício 7** | XSS em atributos HTML (A05): Template Jinja2 com autoescaping, header `Content-Security-Policy` e rota de contraste. |
| [`Exercicio8.py`](Exercicio8.py) | **Exercício 8** | Modelo de ML servido por API: Validação de features de entrada, cálculo de métricas (Precisão, Recall, F1) e log de auditoria. |
| [`Exercicio9.py`](Exercicio9.py) | **Exercício 9** | Rate limiting guiado por anomalia: Telemetria via `@before_request`/`@after_request`, agregação e bloqueio 429 com `IsolationForest`. |
| [`Exercicio10.py`](Exercicio10.py) | **Exercício 10 (Desafio)** | Orquestrador de teste completo comprovando os ataques contra a API vulnerável e a defesa total na API segura. |
| [`app_vulneravel.py`](app_vulneravel.py) | **Exercício 10** | API original de laboratório com as 8+ vulnerabilidades OWASP. |
| [`app_seguro.py`](app_seguro.py) | **Exercício 10** | Versão corrigida e blindada contra todas as falhas de injeção, XSS, IDOR, headers e verbose errors. |
| [`exploit.py`](exploit.py) | **Exercício 10** | Script de exploit automatizado que prova 6 ataques no vulnerável e 0 ataques no seguro. |
| [`auditoria.md`](auditoria.md) | **Exercício 10** | Relatório de auditoria detalhado com classificação OWASP Top 10 (2025), impactos e correções. |

---

## 🔒 Variáveis de Ambiente e Credenciais

Em conformidade com a exigência:
> *"Credenciais em variável de ambiente — qualquer senha escrita no código custa 0,3 do total."*

Nenhum arquivo contém credenciais fixas (hardcoded). Todos utilizam `os.getenv`.

---

## 🚀 Como Executar

No terminal do VS Code ou PowerShell:

```powershell
cd "d:\Downloads\CP3_Python\CP3 exercicios"

python Exercicio1.py
python Exercicio2.py
python Exercicio3.py
python Exercicio4.py
python Exercicio5.py
python Exercicio6.py
python Exercicio7.py
python Exercicio8.py
python Exercicio9.py
python Exercicio10.py
```
