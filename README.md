# email-osint (educativo)

Herramienta de línea de comandos para reconocimiento OSINT de correos electrónicos
usando **solo fuentes públicas/legítimas**. Pensada para aprender, defender y para
engagements de pentesting **autorizados**.

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

Investigar un correo (validez, dominio/MX, desechable, Gravatar):

```bash
python email_osint.py check alguien@ejemplo.com
```

Varios correos + salida JSON:

```bash
python email_osint.py check a@x.com b@y.com --json
```

Incluir exposición en brechas (necesitas tu propia API key de HIBP):

```bash
python email_osint.py check alguien@ejemplo.com --hibp-key TU_API_KEY
```

Generar permutaciones de correo corporativo a partir de nombre + dominio:

```bash
python email_osint.py perm Saul Cortijo empresa.com
```

## Qué hace cada módulo

| Función            | Fuente                        | Nota                                    |
|--------------------|-------------------------------|-----------------------------------------|
| Validación sintaxis| local (regex)                 | No garantiza que exista la cuenta       |
| MX / recibe correo | DNS público                   | Requiere `dnspython`                    |
| Desechable         | lista local                   | Amplíala con una lista real             |
| Gravatar           | gravatar.com (público)        | Revela avatar público si existe         |
| Brechas            | Have I Been Pwned API v3       | Requiere API key de pago propia         |
| Permutaciones      | local                         | Patrones de correo corporativo típicos  |

## Ética y legalidad

Usa esto únicamente sobre:
- Tus propias cuentas y dominios.
- Un laboratorio controlado.
- Un engagement con **autorización por escrito**.

Hacer reconocimiento contra personas o empresas sin permiso puede constituir
delito (p. ej. arts. 197/264 del Código Penal español). La responsabilidad del
uso es tuya.
