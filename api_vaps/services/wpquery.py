import requests
from packaging import version

def buscar_vulnerabilidades_plugin(plugin_slug, version):
    url = f"https://www.wpvulnerability.net/plugin/{plugin_slug}"
    respuesta = requests.get(url)
    
    if respuesta.status_code != 200:
        print("No se pudo acceder a la API.")
        return
    
    data = respuesta.json()
    
    vulnerabilidades = data.get("data", {}).get("vulnerability", [])

    for v in vulnerabilidades:
        min_version = v.get("operator", {}).get("min_version")
        min_operator = v.get("operator", {}).get("min_operator")
        max_version = v.get("operator", {}).get("max_version")
        max_operator = v.get("operator", {}).get("max_operator")
        if version_en_rango(version, min_version, min_operator, max_version, max_operator):
                mostrar_vulnerabilidad(v)



def version_en_rango(version_objetivo, min_version, min_op, max_version, max_op):
    # Convertimos la versión que estamos evaluando
    vo = version.parse(version_objetivo)

    # --- Comparación con la versión mínima ---
    if min_version:
        # Convertimos la versión mínima a objeto versión
        vmin = version.parse(min_version)
        # Si se espera que sea mayor que la mínima, pero no lo es → no está en rango
        if min_op == "gt" and not (vo > vmin):
            return False
        # Si se espera que sea mayor o igual, pero no lo es → no está en rango
        if min_op == "ge" and not (vo >= vmin):
            return False

    # --- Comparación con la versión máxima ---
    if max_version:
        # Convertimos la versión máxima a objeto versión
        vmax = version.parse(max_version)
        # Si se espera que sea menor que la máxima, pero no lo es → no está en rango
        if max_op == "lt" and not (vo < vmax):
            return False
        # Si se espera que sea menor o igual, pero no lo es → no está en rango
        if max_op == "le" and not (vo <= vmax):
            return False

    # Si pasa todas las validaciones anteriores → sí está en el rango afectado
    return True


def mostrar_vulnerabilidad(v):
    
    
    fuentes = v.get("source", [])
    if fuentes:
        cve = fuentes[0].get("id")
        if cve and cve.startswith("CVE-"):
            print("🛑 Vulnerabilidad:")
            print(f"  CVE: {cve}")
    
    impact = v.get("impact")
    if isinstance(impact, dict):
        cwes = impact.get("cwe", [])
        if isinstance(cwes, list) and cwes:
            cwe = cwes[0].get("cwe")
            if cwe:
                print(f"  CWE: {cwe}")

buscar_vulnerabilidades_plugin("elementor", "3.0.0")