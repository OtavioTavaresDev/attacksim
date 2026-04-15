from fastapi import APIRouter, Depends
from typing import List, Dict, Any

from app.core.orchestrator import AttackOrchestrator

router = APIRouter()

@router.get("/modules")
def list_attack_modules():
    """Lista todos os módulos de ataque disponíveis."""
    orchestrator = AttackOrchestrator()
    modules = [
        {
            "name": m.name,
            "description": m.description,
            "severity": m.severity
        }
        for m in orchestrator.modules
    ]
    return {"modules": modules}

@router.post("/test")
def test_single_attack(target_url: str, module_name: str):
    """Testa um módulo de ataque específico contra um alvo."""
    orchestrator = AttackOrchestrator()
    
    for module in orchestrator.modules:
        if module.name.lower() == module_name.lower():
            result = module.run(target_url)
            return {
                "module": module.name,
                "target": target_url,
                "result": result
            }
    
    return {"error": f"Module '{module_name}' not found"}

@router.get("/test-sqli")
def test_sqli_endpoint(id: str = "1"):
    """Endpoint INTENCIONALMENTE VULNERÁVEL para testar o scanner."""
    import sqlite3
    
    # Criar banco em memória
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'Admin', 'secret123')")
    cursor.execute("INSERT INTO users VALUES (2, 'User', 'pass456')")
    conn.commit()
    
    # VULNERÁVEL: concatenação direta do input do usuário!
    query = f"SELECT name, password FROM users WHERE id = {id}"
    
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return {
            "query": query,
            "results": [{"name": r[0], "password": r[1]} for r in results]
        }
    except Exception as e:
        conn.close()
        return {
            "error": str(e),
            "query": query,
            "vulnerable": True,
            "message": "SQL Injection detected! The input broke the query."
        }

# ========== ENDPOINTS VULNERÁVEIS PARA TESTE ==========

@router.get("/test-sqli")
def test_sqli_endpoint(id: str = "1"):
    """Endpoint VULNERÁVEL a SQL Injection para teste do scanner."""
    import sqlite3
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INTEGER, name TEXT, password TEXT)")
    cursor.execute("INSERT INTO users VALUES (1, 'Admin', 'secret123')")
    cursor.execute("INSERT INTO users VALUES (2, 'User', 'pass456')")
    
    # VULNERÁVEL: concatenação direta
    query = f"SELECT name, password FROM users WHERE id = {id}"
    try:
        cursor.execute(query)
        results = cursor.fetchall()
        return {"query": query, "results": results}
    except Exception as e:
        return {"error": str(e), "query": query, "vulnerable": True}


@router.get("/test-xss")
def test_xss_endpoint(name: str = "Guest"):
    """Endpoint VULNERÁVEL a XSS para teste do scanner."""
    # VULNERÁVEL: reflete input sem sanitização
    html = f"""
    <html>
    <body>
        <h1>Welcome, {name}!</h1>
        <p>Your name was reflected from the URL parameter.</p>
    </body>
    </html>
    """
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html)


@router.get("/test-traversal")
def test_traversal_endpoint(file: str = "test.txt"):
    """Endpoint VULNERÁVEL a Directory Traversal para teste."""
    import os
    
    # VULNERÁVEL: não valida o caminho do arquivo
    base_path = "/tmp/"
    
    try:
        full_path = os.path.join(base_path, file)
        with open(full_path, 'r') as f:
            content = f.read()
        return {"file": file, "content": content}
    except FileNotFoundError:
        return {"error": f"File not found: {file}"}
    except Exception as e:
        return {"error": str(e)}


@router.get("/test-all")
def test_all_endpoint(param: str = "1"):
    """Endpoint com MÚLTIPLAS vulnerabilidades para teste completo."""
    import sqlite3
    
    # SQL Injection
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE test (id INTEGER, value TEXT)")
    cursor.execute("INSERT INTO test VALUES (1, 'test')")
    
    try:
        query = f"SELECT value FROM test WHERE id = {param}"
        cursor.execute(query)
        result = cursor.fetchone()
        sqli_result = result[0] if result else None
    except:
        sqli_result = "SQL Error - VULNERABLE!"
    
    # XSS (reflected)
    xss_reflected = param
    
    return {
        "sql_injection_test": {"query": f"SELECT value FROM test WHERE id = {param}", "result": sqli_result},
        "xss_test": f"Your input: {xss_reflected}",
        "traversal_test": f"File param: {param}",
        "message": "This endpoint is intentionally vulnerable for testing!"
    }

# ========== ENDPOINTS PARA TESTAR NOVOS MÓDULOS ==========

@router.post("/test-bruteforce")
async def test_bruteforce_endpoint(username: str = "admin", password: str = "admin"):
    """Endpoint que simula um login vulnerável a força bruta."""
    weak_passwords = ["admin", "password", "123456", "root", "user"]
    
    if username == "admin" and password in weak_passwords:
        return {
            "vulnerable": True,
            "message": f"Login successful with weak password: {password}",
            "session": "mock-session-token"
        }
    elif username == "admin" and password == "strongpass123":
        return {"message": "Login successful with strong password"}
    else:
        return {"message": "Invalid credentials"}


@router.get("/test-command")
def test_command_endpoint(cmd: str = "ls"):
    """Endpoint VULNERÁVEL a injeção de comandos."""
    import subprocess
    
    # VULNERÁVEL: executa comando diretamente
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        return {
            "command": cmd,
            "output": result.stdout,
            "error": result.stderr,
            "vulnerable": True
        }
    except Exception as e:
        return {"error": str(e), "vulnerable": True}


@router.get("/test-redirect")
def test_redirect_endpoint(redirect: str = "/"):
    """Endpoint VULNERÁVEL a open redirect."""
    from fastapi.responses import RedirectResponse
    
    # VULNERÁVEL: não valida a URL de destino
    if redirect.startswith("http"):
        return RedirectResponse(url=redirect, status_code=302)
    else:
        return RedirectResponse(url=f"/{redirect}", status_code=302)


@router.get("/test-headers")
def test_headers_endpoint():
    """Endpoint que retorna headers de segurança (ou falta deles)."""
    from fastapi.responses import JSONResponse
    
    content = {"message": "Security headers test endpoint"}
    response = JSONResponse(content=content)
    
    # Propositalmente NÃO configurar vários headers de segurança
    # Apenas um exemplo
    response.headers["X-Content-Type-Options"] = "nosniff"
    
    return response
