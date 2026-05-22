"""
Detector de Phishing (Educativo)
=================================

Analiza URLs y correos electrónicos para detectar indicios típicos de
phishing y asigna una puntuación de riesgo.

Este script es DIDÁCTICO: ningún detector basado en reglas es infalible.
Los atacantes reales evolucionan. Úsalo para aprender qué señales mirar,
no como única defensa.

Uso:
    python detector_phishing.py
"""

import re
import sys
from pathlib import Path
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Listas y patrones de referencia
# ---------------------------------------------------------------------------

# TLDs que aparecen con frecuencia en campañas de phishing (gratuitos
# o muy baratos). No significa que sean malos por definición.
TLDS_SOSPECHOSOS = {
    "tk", "ml", "ga", "cf", "gq",   # Freenom (históricamente abusados)
    "xyz", "top", "club", "click", "country", "stream", "gdn",
    "work", "support", "rest", "fit", "loan", "men", "review",
}

# Servicios de acortado de URLs: ocultan el destino real.
ACORTADORES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorturl.at", "rebrand.ly", "cutt.ly",
    "tiny.cc", "lnkd.in",
}

# Marcas frecuentemente suplantadas. Si aparecen en el dominio
# (no como dominio principal) suele ser un intento de engaño.
MARCAS_SUPLANTADAS = {
    "paypal", "google", "microsoft", "apple", "amazon", "netflix",
    "facebook", "instagram", "whatsapp", "bbva", "santander",
    "caixabank", "correos", "dhl", "fedex", "ups", "outlook",
    "office365", "icloud", "binance", "coinbase", "bizum",
    "hacienda", "agenciatributaria", "seg-social",
}

# Palabras con tono de urgencia / amenaza típicas en correos de phishing.
PALABRAS_URGENCIA = {
    "urgente", "inmediato", "inmediata", "verifica", "verificar",
    "verifique", "suspendid", "bloqueado", "bloquead", "expira",
    "expirar", "última oportunidad", "actúa ahora", "acción requerida",
    "confirme", "confirmar", "haga clic", "haz clic", "click aquí",
    "click here", "verify", "suspended", "expire", "act now",
    "limited time", "winner", "ganador", "premio", "lotería",
    "herencia", "transferencia", "reembolso", "refund",
}

SALUDOS_GENERICOS = {
    "estimado cliente", "estimado usuario", "querido cliente",
    "dear customer", "dear user", "dear client", "hola usuario",
    "estimado/a", "estimad@",
}

# Regex de IP literal (en lugar de dominio) en una URL.
RE_IP = re.compile(
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)

# Caracteres "lookalike" usados en ataques homográficos
# (no exhaustivo, sólo educativo).
HOMOGRAFOS = {
    "а": "a (cirílico)", "е": "e (cirílico)", "о": "o (cirílico)",
    "р": "p (cirílico)", "с": "c (cirílico)", "ѕ": "s (cirílico)",
    "і": "i (cirílico)", "ӏ": "l (cirílico)",
}

RE_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
RE_URL = re.compile(r"https?://[^\s<>\"')]+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Análisis de URLs
# ---------------------------------------------------------------------------

def analizar_url(url: str) -> dict:
    """
    Devuelve un diccionario con la URL, una lista de motivos detectados
    y una puntuación de riesgo (0 = limpio, >5 = sospechoso).
    """
    motivos = []
    puntos = 0

    # Normalizamos: si no trae esquema, le añadimos http:// para urlparse.
    url_normalizada = url if "://" in url else "http://" + url
    parsed = urlparse(url_normalizada)
    host = (parsed.hostname or "").lower()
    ruta = parsed.path or ""

    if not host:
        return {"url": url, "motivos": ["URL no parseable"], "puntos": 1}

    # 1) HTTP sin cifrar
    if parsed.scheme.lower() == "http":
        motivos.append("Usa HTTP sin cifrar (sin candado)")
        puntos += 1

    # 2) IP en lugar de dominio
    if RE_IP.match(host):
        motivos.append(f"La URL apunta a una IP literal ({host})")
        puntos += 3

    # 3) TLD sospechoso
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in TLDS_SOSPECHOSOS:
        motivos.append(f"TLD frecuentemente abusado: .{tld}")
        puntos += 2

    # 4) Acortador de URLs
    if host in ACORTADORES:
        motivos.append(f"Servicio acortador ({host}) — destino oculto")
        puntos += 2

    # 5) Subdominios muy largos / excesivos
    partes = host.split(".")
    if len(partes) >= 5:
        motivos.append(f"Demasiados subdominios ({len(partes)} niveles)")
        puntos += 1

    # 6) Marca suplantada en subdominio o path
    for marca in MARCAS_SUPLANTADAS:
        if marca in host and not host.endswith(f"{marca}.com") \
                and not host.endswith(f"{marca}.es"):
            motivos.append(f"Marca '{marca}' usada fuera de su dominio oficial")
            puntos += 3
            break
        if marca in ruta.lower():
            motivos.append(f"Marca '{marca}' aparece en la ruta de la URL")
            puntos += 1
            break

    # 7) Carácter '@' en la URL (engaño clásico: la parte antes de @ es ignorada)
    if "@" in url_normalizada.split("://", 1)[-1]:
        motivos.append("Contiene '@' en la URL (puede ocultar el destino real)")
        puntos += 3

    # 8) Muchos guiones en el dominio
    if host.count("-") >= 3:
        motivos.append(f"Dominio con muchos guiones ({host.count('-')})")
        puntos += 1

    # 9) URL anormalmente larga
    if len(url) > 100:
        motivos.append(f"URL muy larga ({len(url)} caracteres)")
        puntos += 1

    # 10) Caracteres homográficos
    encontrados = [c for c in host if c in HOMOGRAFOS]
    if encontrados:
        ejemplos = ", ".join(f"'{c}' = {HOMOGRAFOS[c]}" for c in set(encontrados))
        motivos.append(f"Caracteres homográficos detectados: {ejemplos}")
        puntos += 4

    # 11) Doble extensión sospechosa en la ruta
    if re.search(r"\.(zip|exe|scr|js|html)\.[a-z]{2,4}($|\?)", ruta.lower()):
        motivos.append("Posible doble extensión en la ruta")
        puntos += 2

    return {"url": url, "motivos": motivos, "puntos": puntos}


# ---------------------------------------------------------------------------
# Análisis de correos
# ---------------------------------------------------------------------------

def analizar_email(texto: str) -> dict:
    """
    Analiza el cuerpo (y opcionalmente cabeceras) de un correo en texto plano.
    """
    motivos = []
    puntos = 0
    texto_min = texto.lower()

    # 1) Saludo genérico
    for saludo in SALUDOS_GENERICOS:
        if saludo in texto_min:
            motivos.append(f"Saludo genérico detectado: '{saludo}'")
            puntos += 1
            break

    # 2) Palabras de urgencia / amenaza
    encontradas = [p for p in PALABRAS_URGENCIA if p in texto_min]
    if encontradas:
        muestra = ", ".join(sorted(set(encontradas))[:5])
        motivos.append(f"Lenguaje de urgencia/amenaza: {muestra}")
        puntos += min(3, len(encontradas))

    # 3) Discrepancia entre remitente y dominio enlazado
    remitente = None
    m_from = re.search(r"^from:\s*(.+)$", texto, re.IGNORECASE | re.MULTILINE)
    if m_from:
        emails_from = RE_EMAIL.findall(m_from.group(1))
        if emails_from:
            remitente = emails_from[0]
            dominio_from = remitente.split("@", 1)[1].lower()
            urls = RE_URL.findall(texto)
            for u in urls:
                host = (urlparse(u).hostname or "").lower()
                base_host = ".".join(host.split(".")[-2:])
                base_from = ".".join(dominio_from.split(".")[-2:])
                if base_host and base_host != base_from:
                    motivos.append(
                        f"Enlace a '{host}' no coincide con remitente "
                        f"({dominio_from})"
                    )
                    puntos += 2
                    break

    # 4) Texto del enlace distinto del destino (formato Markdown / HTML simple)
    for m in re.finditer(r"\[([^\]]+)\]\((https?://[^\)]+)\)", texto):
        etiqueta, destino = m.group(1), m.group(2)
        if re.match(r"^https?://", etiqueta) and etiqueta != destino:
            motivos.append("Texto de enlace muestra una URL distinta al destino")
            puntos += 3
            break
    for m in re.finditer(
        r'<a\s+href=["\'](https?://[^"\']+)["\'][^>]*>([^<]+)</a>',
        texto, re.IGNORECASE,
    ):
        destino, etiqueta = m.group(1), m.group(2)
        if re.match(r"^https?://", etiqueta) and etiqueta != destino:
            motivos.append("Enlace HTML con texto visible distinto al destino")
            puntos += 3
            break

    # 5) Adjunto con extensión peligrosa
    if re.search(
        r"\b\S+\.(exe|scr|js|vbs|bat|cmd|jar|ps1|hta|msi|zip|rar|7z|iso)\b",
        texto_min,
    ):
        motivos.append("Mención a adjuntos con extensión potencialmente peligrosa")
        puntos += 2

    # 6) Solicitud de datos sensibles
    if re.search(
        r"\b(contraseña|password|tarjeta|número de tarjeta|cvv|dni|nif|"
        r"bizum|iban|pin)\b",
        texto_min,
    ):
        motivos.append("Pide datos sensibles (contraseña, tarjeta, DNI…)")
        puntos += 3

    # 7) Análisis de cada URL incrustada
    urls = RE_URL.findall(texto)
    if urls:
        motivos.append(f"URLs detectadas en el correo: {len(urls)}")
        for u in urls:
            resultado = analizar_url(u)
            if resultado["puntos"] >= 3:
                motivos.append(
                    f"  · URL sospechosa ({resultado['puntos']} pts): {u}"
                )
                puntos += resultado["puntos"] // 2

    # 8) Faltas de ortografía / mezcla de idiomas (heurística muy simple)
    if re.search(r"[A-Za-z]+\s+[áéíóú]+\s+[A-Za-z]+", texto):
        # heurística débil; sólo aviso suave
        pass

    if remitente:
        motivos.insert(0, f"Remitente: {remitente}")

    return {"motivos": motivos, "puntos": puntos}


# ---------------------------------------------------------------------------
# Presentación
# ---------------------------------------------------------------------------

def nivel_riesgo(puntos: int) -> str:
    if puntos == 0:
        return "🟢 LIMPIO — sin indicios obvios"
    if puntos <= 2:
        return "🟡 BAJO — revisa con calma"
    if puntos <= 5:
        return "🟠 MEDIO — sospechoso, NO hagas clic"
    return "🔴 ALTO — muy probablemente phishing"


def mostrar_resultado(titulo: str, resultado: dict):
    print("\n" + "─" * 60)
    print(f"  {titulo}")
    print("─" * 60)
    print(f"  Puntuación: {resultado['puntos']}  →  {nivel_riesgo(resultado['puntos'])}")
    if resultado["motivos"]:
        print("  Indicios detectados:")
        for m in resultado["motivos"]:
            print(f"    • {m}")
    else:
        print("  (sin indicios)")
    print("─" * 60)


# ---------------------------------------------------------------------------
# Menú principal
# ---------------------------------------------------------------------------

def menu():
    print("""
╔══════════════════════════════════════════╗
║   DETECTOR DE PHISHING (EDUCATIVO)       ║
╚══════════════════════════════════════════╝
  1. Analizar una URL
  2. Analizar un correo (texto pegado)
  3. Analizar un correo desde archivo .txt/.eml
  4. Ver ejemplos de prueba
  0. Salir
""")
    return input("Opción: ").strip()


def ejemplo_demo():
    """Muestra un par de ejemplos didácticos."""
    print("\n--- EJEMPLO 1: URL sospechosa ---")
    mostrar_resultado(
        "http://paypa1-secure-login.tk/verify?user=tu",
        analizar_url("http://paypa1-secure-login.tk/verify?user=tu"),
    )

    print("\n--- EJEMPLO 2: URL legítima ---")
    mostrar_resultado(
        "https://www.paypal.com/signin",
        analizar_url("https://www.paypal.com/signin"),
    )

    print("\n--- EJEMPLO 3: Correo de phishing ---")
    correo = """From: soporte@paypaI-seguridad.tk
Asunto: ¡URGENTE! Su cuenta será suspendida

Estimado cliente,

Hemos detectado actividad sospechosa. Su cuenta será BLOQUEADA en 24h.
Verifique su contraseña inmediatamente haciendo clic aquí:

http://paypa1-secure-login.tk/verify?user=tu

Si no lo hace, perderá el acceso. Necesitamos su número de tarjeta y CVV
para confirmar su identidad.

Atentamente,
Equipo de Seguridad"""
    mostrar_resultado("Correo de prueba", analizar_email(correo))


def main():
    print("=" * 60)
    print("   DETECTOR DE PHISHING — uso educativo")
    print("=" * 60)
    print("   Heurística basada en reglas. No reemplaza a un antivirus.")

    while True:
        opcion = menu()

        if opcion == "0":
            print("¡Hasta luego!")
            break

        elif opcion == "1":
            url = input("URL a analizar: ").strip()
            if url:
                mostrar_resultado(url, analizar_url(url))

        elif opcion == "2":
            print("Pega el correo. Termina con una línea vacía + ENTER:")
            lineas = []
            while True:
                try:
                    l = input()
                except EOFError:
                    break
                if l == "":
                    break
                lineas.append(l)
            if lineas:
                mostrar_resultado("Correo pegado", analizar_email("\n".join(lineas)))

        elif opcion == "3":
            ruta = input("Ruta del archivo: ").strip().strip('"')
            p = Path(ruta)
            if not p.exists():
                print(f"[!] No se encontró el archivo: {ruta}")
                continue
            texto = p.read_text(encoding="utf-8", errors="replace")
            mostrar_resultado(p.name, analizar_email(texto))

        elif opcion == "4":
            ejemplo_demo()

        else:
            print("[!] Opción no válida.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrumpido por el usuario.")
        sys.exit(0)
