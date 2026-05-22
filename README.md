# 📧 Detector de Phishing con Python

Una herramienta **CLI educativa** escrita en Python que analiza **URLs**
y **correos electrónicos** en busca de indicios típicos de *phishing*,
asignándoles una puntuación de riesgo y explicando qué se ha detectado
y por qué.

> ⚠️ **Aviso**: este detector es **didáctico** y se basa en heurísticas
> (reglas). No reemplaza a un antivirus, a un filtro antispam profesional
> ni al sentido común. Úsalo para aprender qué señales mirar.

---

## 📋 Tabla de contenidos

- [Características](#-características)
- [¿Qué busca?](#-qué-busca)
- [Requisitos](#-requisitos)
- [Instalación](#-instalación)
- [Uso](#-uso)
- [Ejemplo de ejecución](#-ejemplo-de-ejecución)
- [Niveles de riesgo](#-niveles-de-riesgo)
- [Limitaciones](#-limitaciones)
- [Próximas mejoras](#-próximas-mejoras)
- [Licencia](#-licencia)

---

## ✨ Características

- 🔗 Análisis de **URLs**: esquema, dominio, TLD, subdominios, IP literal,
  acortadores, marcas suplantadas, caracteres homográficos, etc.
- ✉️ Análisis de **correos**: tono de urgencia, saludo genérico,
  discrepancia entre remitente y enlaces, texto de enlace distinto al
  destino, adjuntos peligrosos, solicitud de datos sensibles.
- 📊 **Puntuación de riesgo** y nivel (🟢 / 🟡 / 🟠 / 🔴).
- 📝 Lista detallada de **indicios** detectados con explicación.
- 🐍 Sin dependencias externas (sólo biblioteca estándar de Python).
- 📂 Soporta pegar el correo o leerlo desde un archivo `.txt` / `.eml`.

---

## 🔍 ¿Qué busca?

### En una URL

| Indicio | ¿Por qué importa? |
|---|---|
| HTTP sin cifrar | Una web seria que pide credenciales usa HTTPS. |
| IP literal (1.2.3.4) | Servicios legítimos casi siempre tienen dominio. |
| TLDs `.tk .ml .xyz .top …` | Históricamente abusados por su bajo coste. |
| Acortadores (`bit.ly`, `t.co`…) | Ocultan el destino real del enlace. |
| Marca suplantada en subdominio | `paypal.seguro-cuenta.tk` no es PayPal. |
| Carácter `@` en la URL | El navegador ignora lo anterior al `@`. |
| Caracteres homográficos | `раypal.com` (con "р" cirílica) ≠ `paypal.com`. |
| Doble extensión (`.pdf.exe`) | Engaño clásico de adjuntos. |
| URL anormalmente larga | Suele esconder *payloads* o parámetros raros. |

### En un correo

| Indicio | ¿Por qué importa? |
|---|---|
| Saludo genérico ("Estimado cliente") | Tu banco te conoce por tu nombre. |
| Urgencia / amenazas | "Su cuenta será bloqueada en 24h" es presión. |
| Remitente vs enlaces | Si el remitente es `@banco.com` pero el enlace va a `banco-seguro.tk`, mala señal. |
| Texto del enlace ≠ destino | Pone "paypal.com" pero el href va a otro sitio. |
| Adjuntos `.exe .scr .js .vbs .iso` | Extensiones típicas de malware. |
| Pide contraseña / tarjeta / CVV | Ninguna entidad seria lo pide por correo. |

---

## 📦 Requisitos

- Python **3.8** o superior.
- No requiere dependencias externas (sólo `re`, `urllib`, `pathlib`).

---

## 🚀 Instalación

```bash
git clone https://github.com/<tu-usuario>/detector-phishing.git
cd detector-phishing
python detector_phishing.py
```

---

## ▶️ Uso

```bash
python detector_phishing.py
```

Verás un menú con estas opciones:

```
1. Analizar una URL
2. Analizar un correo (texto pegado)
3. Analizar un correo desde archivo .txt/.eml
4. Ver ejemplos de prueba
0. Salir
```

---

## 🖥️ Ejemplo de ejecución

```
Opción: 1
URL a analizar: http://paypa1-secure-login.tk/verify?user=tu

────────────────────────────────────────────────────────────
  http://paypa1-secure-login.tk/verify?user=tu
────────────────────────────────────────────────────────────
  Puntuación: 8  →  🔴 ALTO — muy probablemente phishing
  Indicios detectados:
    • Usa HTTP sin cifrar (sin candado)
    • TLD frecuentemente abusado: .tk
    • Marca 'paypal' usada fuera de su dominio oficial
    • Dominio con muchos guiones (2)
────────────────────────────────────────────────────────────
```

```
Opción: 4   (ver ejemplos de prueba)

--- EJEMPLO 2: URL legítima ---
  https://www.paypal.com/signin
  Puntuación: 0  →  🟢 LIMPIO — sin indicios obvios
```

---

## 🚦 Niveles de riesgo

| Puntos | Nivel | Recomendación |
|:--:|---|---|
| 0      | 🟢 LIMPIO | Sin indicios evidentes. Sigue con cuidado normal. |
| 1–2    | 🟡 BAJO  | Algo llama la atención. Revisa con calma. |
| 3–5    | 🟠 MEDIO | Sospechoso. **No hagas clic** sin verificar. |
| 6+     | 🔴 ALTO  | Muy probablemente phishing. **Bórralo.** |

> La puntuación es orientativa — un correo con 2 puntos puede seguir
> siendo malicioso, y uno con 6 puede ser un boletín mal redactado.

---

## ⚠️ Limitaciones

- **Basado en reglas** → un atacante que conozca las reglas puede
  esquivarlas. Los detectores reales combinan reglas + *machine learning*
  + *threat intelligence* en tiempo real.
- **No descarga páginas** ni sigue redirecciones; sólo analiza la URL tal
  cual se introduce.
- **No revisa cabeceras SPF/DKIM/DMARC** del correo (sería el siguiente
  paso natural en un análisis real).
- Las listas de TLDs / acortadores / marcas son **estáticas** y limitadas.
- No detecta phishing dirigido (*spear phishing*) muy bien escrito.

---

## 🛠️ Próximas mejoras

- [ ] Verificación de **SPF / DKIM / DMARC** desde cabeceras `.eml`.
- [ ] Resolver redirecciones de acortadores antes de analizar.
- [ ] Consultar **VirusTotal** o **PhishTank** vía API (opcional).
- [ ] Detección de **typosquatting** (distancia de Levenshtein con marcas).
- [ ] Modo *batch* para analizar archivos de logs / listas de URLs.
- [ ] Exportar informes en JSON / CSV.
- [ ] Interfaz web ligera con Flask.

---

## 📚 Recursos para profundizar

- [APWG — Anti-Phishing Working Group](https://apwg.org/)
- [PhishTank](https://phishtank.org/)
- [OWASP Phishing Cheat Sheet](https://cheatsheetseries.owasp.org/)
- [URLhaus (abuse.ch)](https://urlhaus.abuse.ch/)
- [INCIBE — Avisos de seguridad](https://www.incibe.es/)

---

## 📄 Licencia

Distribuido bajo licencia **MIT**. Consulta el archivo `LICENSE` para más
información.

---

## 🙋 Autor

Hecho con ❤️ con fines educativos.
**La mejor defensa contra el phishing sigue siendo un usuario formado.**
