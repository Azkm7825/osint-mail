#!/usr/bin/env python3
"""
email-osint — Herramienta educativa de OSINT sobre correos electronicos.

Consulta UNICAMENTE fuentes publicas / legitimas:
  - Validacion sintactica del correo
  - Verificacion del dominio (registros MX / A) para ver si puede recibir correo
  - Deteccion de dominios desechables (lista local)
  - Generacion de permutaciones de correo a partir de nombre + dominio
  - Gravatar (avatar publico asociado al correo)
  - Have I Been Pwned (exposicion en brechas publicas; requiere API key propia)

USO ETICO: usa esto solo sobre tus propias cuentas/dominios, en un laboratorio,
o dentro de un engagement de pentesting con autorizacion por escrito. Hacer
reconocimiento contra personas o empresas sin permiso puede ser ilegal.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Falta la dependencia 'requests'. Instala con: pip install requests dnspython")

try:
    import dns.resolver  # dnspython
    _HAS_DNS = True
except ImportError:
    _HAS_DNS = False


EMAIL_RE = re.compile(r"^(?P<local>[^@\s]+)@(?P<domain>[^@\s]+\.[^@\s]+)$")

# Pequeña muestra; amplia con una lista real como disposable-email-domains.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "yopmail.com", "trashmail.com", "getnada.com", "throwawaymail.com",
    "temp-mail.org", "sharklasers.com", "maildrop.cc", "fakeinbox.com",
}

USER_AGENT = "email-osint-edu/1.0 (+educational OSINT tool)"


@dataclass
class EmailReport:
    email: str
    valid_syntax: bool = False
    local: Optional[str] = None
    domain: Optional[str] = None
    disposable: bool = False
    domain_receives_mail: Optional[bool] = None
    mx_records: list[str] = field(default_factory=list)
    gravatar_url: Optional[str] = None
    breaches: Optional[list[str]] = None          # None = no consultado
    notes: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Comprobaciones
# ---------------------------------------------------------------------------
def validate_syntax(email: str, report: EmailReport) -> None:
    m = EMAIL_RE.match(email.strip())
    if not m:
        report.valid_syntax = False
        report.notes.append("Sintaxis de correo invalida.")
        return
    report.valid_syntax = True
    report.local = m.group("local")
    report.domain = m.group("domain").lower()
    report.disposable = report.domain in DISPOSABLE_DOMAINS
    if report.disposable:
        report.notes.append("El dominio es un servicio de correo desechable conocido.")


def check_domain_mx(report: EmailReport) -> None:
    """Un dominio con MX (o A como fallback) puede recibir correo."""
    if not report.domain:
        return
    if not _HAS_DNS:
        report.notes.append("dnspython no instalado: se omite la verificacion MX. (pip install dnspython)")
        return
    try:
        answers = dns.resolver.resolve(report.domain, "MX")
        report.mx_records = sorted(
            str(r.exchange).rstrip(".") for r in answers
        )
        report.domain_receives_mail = bool(report.mx_records)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # Sin MX; probar registro A (algunos aceptan correo igualmente)
        try:
            dns.resolver.resolve(report.domain, "A")
            report.domain_receives_mail = True
            report.notes.append("Sin MX, pero el dominio resuelve (registro A).")
        except Exception:
            report.domain_receives_mail = False
            report.notes.append("El dominio no parece poder recibir correo.")
    except Exception as e:  # noqa: BLE001
        report.notes.append(f"No se pudo consultar MX: {e}")


def check_gravatar(report: EmailReport, timeout: float = 8.0) -> None:
    """Gravatar expone un avatar publico si el correo tiene uno asociado."""
    if not report.valid_syntax:
        return
    h = hashlib.md5(report.email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{h}?d=404"
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        if r.status_code == 200:
            report.gravatar_url = f"https://www.gravatar.com/avatar/{h}"
            report.notes.append("Gravatar publico encontrado para este correo.")
    except requests.RequestException as e:
        report.notes.append(f"Gravatar no comprobado: {e}")


def check_hibp(report: EmailReport, api_key: str, timeout: float = 15.0) -> None:
    """
    Consulta Have I Been Pwned (breaches). Requiere API key de pago propia.
    Doc: https://haveibeenpwned.com/API/v3
    """
    if not report.valid_syntax:
        return
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{report.email}"
    headers = {"hibp-api-key": api_key, "User-Agent": USER_AGENT}
    try:
        r = requests.get(url, headers=headers, params={"truncateResponse": "true"}, timeout=timeout)
        if r.status_code == 200:
            report.breaches = [b["Name"] for b in r.json()]
            report.notes.append(f"Expuesto en {len(report.breaches)} brecha(s) publica(s).")
        elif r.status_code == 404:
            report.breaches = []
            report.notes.append("Sin brechas publicas registradas en HIBP.")
        elif r.status_code == 401:
            report.notes.append("HIBP: API key invalida o ausente.")
        elif r.status_code == 429:
            report.notes.append("HIBP: limite de peticiones (rate limit). Reintenta mas tarde.")
        else:
            report.notes.append(f"HIBP respondio {r.status_code}.")
    except requests.RequestException as e:
        report.notes.append(f"HIBP no comprobado: {e}")


# ---------------------------------------------------------------------------
# Generador de permutaciones
# ---------------------------------------------------------------------------
def permutations(first: str, last: str, domain: str) -> list[str]:
    """Patrones habituales de correo corporativo a partir de nombre y apellido."""
    f, l = first.lower().strip(), last.lower().strip()
    fi, li = f[:1], l[:1]
    patterns = {
        f, l, f + l, f + "." + l, fi + l, f + li, fi + "." + l,
        f + "_" + l, l + f, l + "." + f, li + f, f + "-" + l,
    }
    return sorted(f"{p}@{domain}" for p in patterns if p)


# ---------------------------------------------------------------------------
# Orquestacion
# ---------------------------------------------------------------------------
def investigate(email: str, hibp_key: Optional[str] = None) -> EmailReport:
    report = EmailReport(email=email)
    validate_syntax(email, report)
    if report.valid_syntax:
        check_domain_mx(report)
        check_gravatar(report)
        if hibp_key:
            check_hibp(report, hibp_key)
    return report


def print_report(report: EmailReport, as_json: bool) -> None:
    if as_json:
        print(json.dumps(asdict(report), indent=2, ensure_ascii=False))
        return
    tick = lambda b: "si" if b else "no"  # noqa: E731
    print(f"\n=== Informe OSINT: {report.email} ===")
    print(f"  Sintaxis valida : {tick(report.valid_syntax)}")
    if report.valid_syntax:
        print(f"  Dominio         : {report.domain}")
        print(f"  Desechable      : {tick(report.disposable)}")
        rec = report.domain_receives_mail
        print(f"  Recibe correo   : {'desconocido' if rec is None else tick(rec)}")
        if report.mx_records:
            print(f"  MX              : {', '.join(report.mx_records)}")
        print(f"  Gravatar        : {report.gravatar_url or 'no'}")
        if report.breaches is not None:
            print(f"  Brechas (HIBP)  : {len(report.breaches)}"
                  + (f" -> {', '.join(report.breaches)}" if report.breaches else ""))
    if report.notes:
        print("  Notas:")
        for n in report.notes:
            print(f"    - {n}")


def main() -> None:
    # Sin argumentos -> lanza el menu interactivo "hacker".
    if len(sys.argv) == 1:
        try:
            import osint_tui
            osint_tui.main()
        except ImportError:
            print("No se encontro osint_tui.py (el menu interactivo) junto a este fichero.")
            print("Ejecuta con argumentos, p. ej.:  python email_osint.py check correo@dominio.com")
        return

    p = argparse.ArgumentParser(
        description="Herramienta educativa de OSINT sobre correos (solo fuentes publicas).",
        epilog="Uso etico: solo cuentas propias, laboratorio o engagement autorizado.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    pc = sub.add_parser("check", help="Investigar uno o varios correos.")
    pc.add_argument("emails", nargs="+", help="Correos a analizar.")
    pc.add_argument("--hibp-key", help="API key de Have I Been Pwned (opcional).")
    pc.add_argument("--json", action="store_true", help="Salida en JSON.")

    pp = sub.add_parser("perm", help="Generar permutaciones de correo.")
    pp.add_argument("first", help="Nombre.")
    pp.add_argument("last", help="Apellido.")
    pp.add_argument("domain", help="Dominio (ej. empresa.com).")

    args = p.parse_args()

    if args.cmd == "check":
        for email in args.emails:
            report = investigate(email, hibp_key=args.hibp_key)
            print_report(report, as_json=args.json)
    elif args.cmd == "perm":
        for addr in permutations(args.first, args.last, args.domain):
            print(addr)


if __name__ == "__main__":
    main()
