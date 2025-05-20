import requests
from packaging import version


# Se usa =None en la definición de una función para hacer que ese parámetro sea opcional. 
def buscar_vulnerabilidades(plugin_slug=None, theme_slug=None, core_version=None, version_objetivo=None):
    # --- Determinar el tipo de recurso ---
    if plugin_slug:
        url = f"https://www.wpvulnerability.net/plugin/{plugin_slug}"
    elif theme_slug:
        url = f"https://www.wpvulnerability.net/theme/{theme_slug}"
    elif core_version:
        url = f"https://www.wpvulnerability.net/core/{core_version}"
    else:
        raise ValueError("Debes proporcionar plugin_slug, theme_slug o core_version.")
    
    respuesta = requests.get(url)

    if respuesta.status_code != 200:
        print("No se pudo acceder a la API.")
        return

    data = respuesta.json()
    vulnerabilidades = data.get("data", {}).get("vulnerability", [])

    agrupadas_por_cwe = {}  # clave: cwe principal, valor: lista de tuplas (cve, cwe original)
    cwes_no_mapeados = []  # Lista de tuplas (cve, cwe sin mapear)

# 1. De todas las vulnerabilidades se extrae el CWE y el CVE

    for v in vulnerabilidades:
        min_version = v.get("operator", {}).get("min_version")
        min_operator = v.get("operator", {}).get("min_operator")
        max_version = v.get("operator", {}).get("max_version")
        max_operator = v.get("operator", {}).get("max_operator")

            # --- Lógica según tipo de búsqueda ---
        if version_objetivo:  # Se está buscando por versión de plugin o tema
            if not version_en_rango(version_objetivo, min_version, min_operator, max_version, max_operator):
                continue
        elif core_version:  # Se está buscando por versión del core
            if not version_en_rango(core_version, min_version, min_operator, max_version, max_operator):
                continue


        fuentes = v.get("source", [])
        cves = [s["id"] for s in fuentes if s.get("id", "").startswith("CVE-")]
        impact = v.get("impact")

        # Si impact es un diccionario, seguimos normalmente
        cwes = extraer_cwes(impact)

# 2. Se busca si el cwe tiene un antipatrón o es hijo de un cwe con antipatrón

        for cwe_info in cwes:
            cwe_code = cwe_info.get("cwe")
            if not cwe_code:
                continue

            # Intenta mapear el CWE a uno de los principales definidos en tu diccionario. Si no lo encuentra (ni como principal ni como hijo), lo saltea.
            cwe_principal = mapear_cwe_a_principal(cwe_code)
            if not cwe_principal:
                for cve in cves:
                    cwes_no_mapeados.append((cve, cwe_code))
                continue

            # Si el CWE principal no está en el diccionario, lo inicializamos
            if cwe_principal not in agrupadas_por_cwe:
                agrupadas_por_cwe[cwe_principal] = []

            # Para cada CVE asociado a esa vulnerabilidad, lo agrega a la lista del CWE principal, junto con su CWE real (por si era un hijo).
            for cve in cves:
                agrupadas_por_cwe[cwe_principal].append((cve, cwe_code))

    return agrupadas_por_cwe, cwes_no_mapeados
   
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

def extraer_cwes(impact):
    if isinstance(impact, dict):
        return impact.get("cwe", [])
    elif isinstance(impact, list):
        cwes = []
        for item in impact:
            if isinstance(item, dict) and "cwe" in item:
                cwes.extend(item["cwe"])
        return cwes
    return []

def mapear_cwe_a_principal(cwe):
    """Dado un CWE, devuelve el CWE principal si corresponde."""
    cwe_numero = cwe.replace("CWE-", "")

    if cwe_numero in cwe_parents:
        return cwe_numero

    for padre, hijos in cwe_parents.items():
        if cwe_numero in hijos:
            return padre

    return None  # No encontrado

# --- Mapeo de CWE principales e hijos ---
cwe_parents = {
    "79": ["80", "81", "83", "84", "85", "86", "87"],
    "284": ["269", "282", "285", "286", "287", "346", "749", "923", "1191", "1220", "1224", "1231", "1233", "1252", "1257", "1259", "1260", "1262", "1263", "1267", "1268", "1270", "1274", "1276", "1280", "1283", "1290", "1292", "1294", "1296", "1304", "1311", "1312", "1313", "1315", "1316", "1317", "1320", "1323", "1334"],
    "285": ["288", "639", "862", "863"],
    "352": [],
    "918": [],
    "22": ["23", "36"],
    "98": [],
    "89": ["564"],
    "94": ["95", "96", "1336"],
    "1236": [],
    "200": ["201", "203", "209", "213", "215", "359", "497", "538", "1258", "1273", "1295", "1431"],
    "639": ["566"],
    "269": ["250", "266", "267", "268", "270", "271", "274", "648"],
    "362": ["364", "366", "367", "368", "421", "689", "1223", "1298"],
    "434": [],
    "502": []
}

# slug = internal name used by WordPress to do plugin updates and to determine which plugins are currently active

buscar_vulnerabilidades(plugin_slug="woocommerce")