from fastapi import FastAPI, HTTPException
from db import buscar_por_cwe  # Tu función de conexión a MongoDB
from services import wpquery  # Tu lógica para consultar la API

app = FastAPI()

@app.get("/")
def root():
    return {"mensaje": "API de antipatrones funcionando ✅"}

# --- Buscar en base de datos por CWE ---
@app.get("/cwe/{cwe_id}")
def buscar_por_cwe_endpoint(cwe_id: str):

    resultado = buscar_por_cwe(f"CWE-{cwe_id}")
    if resultado:
        resultado["_id"] = str(resultado["_id"])
        return resultado
    
    raise HTTPException(status_code=404, detail="No se encontró ningún antipatrón para ese CWE")

# --- CORE ---
@app.get("/core/{wp_version}")
def buscar_core(wp_version: str):
    
    agrupadas, sin_mapeo = wpquery.buscar_vulnerabilidades(core_version=wp_version, version_objetivo=wp_version)
    resultados = []

    for cwe_id, cve_list in agrupadas.items():
        antipatron = buscar_por_cwe(f"CWE-{cwe_id}")
        if antipatron:
            antipatron["_id"] = str(antipatron["_id"])
        resultados.append({
            "cwe_id": f"CWE-{cwe_id}",
            "antipatron": antipatron,
            "vulnerabilidades": [cve for cve, _ in cve_list]
        })

    return {
        "core_version": wp_version,
        "resultados": resultados,
        "sin_antipatron": sin_mapeo
    }

# --- PLUGINS ---
@app.get("/plugins/{plugin_slug}")
@app.get("/plugins/{plugin_slug}/{plugin_version}")
def buscar_plugin(plugin_slug: str, plugin_version: str = None):
    agrupadas, sin_mapeo = wpquery.buscar_vulnerabilidades(plugin_slug=plugin_slug, version_objetivo=plugin_version)
    resultados = []

    for cwe_id, cve_list in agrupadas.items():
        antipatron = buscar_por_cwe(f"CWE-{cwe_id}")
        if antipatron:
            antipatron["_id"] = str(antipatron["_id"])
        resultados.append({
            "cwe_id": f"CWE-{cwe_id}",
            "antipatron": antipatron,
            "vulnerabilidades": [cve for cve, _ in cve_list]
        })

    return {
        "plugin": plugin_slug,
        "version": plugin_version or "todas",
        "resultados": resultados,
        "sin_antipatron": sin_mapeo
    }

# --- THEMES ---
@app.get("/themes/{theme_slug}")
@app.get("/themes/{theme_slug}/{theme_version}")
def buscar_theme(theme_slug: str, theme_version: str = None):
    agrupadas, sin_mapeo = wpquery.buscar_vulnerabilidades(theme_slug=theme_slug, version_objetivo=theme_version)
    resultados = []

    for cwe_id, cve_list in agrupadas.items():
        antipatron = buscar_por_cwe(f"CWE-{cwe_id}")
        if antipatron:
            antipatron["_id"] = str(antipatron["_id"])
        resultados.append({
            "cwe_id": f"CWE-{cwe_id}",
            "antipatron": antipatron,
            "vulnerabilidades": [cve for cve, _ in cve_list]
        })

    return {
        "theme": theme_slug,
        "version": theme_version or "todas",
        "resultados": resultados,
        "sin_antipatron": sin_mapeo
    }
