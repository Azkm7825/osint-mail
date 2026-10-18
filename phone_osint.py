#!/usr/bin/env python3
"""
phone_osint — OSINT pasivo sobre numeros de telefono (solo datos publicos).

Usa la libreria 'phonenumbers' (port de libphonenumber de Google) para deducir,
a partir del propio numero y rangos publicos de numeracion:
  - Si el numero es valido / posible
  - Formato internacional, nacional y E.164
  - Pais y region aproximada
  - Operadora (cuando el rango lo permite)
  - Tipo de linea (movil, fijo, VoIP, gratuito...)
  - Zona(s) horaria(s)

NO hace: geolocalizar en tiempo real, sacar la IP, ni identificar al titular.
Eso no es posible desde datos publicos y seria vigilancia ilegal.

Uso etico: numeros propios, laboratorio o engagement autorizado por escrito.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, timezone
    from phonenumbers.phonenumberutil import number_type, PhoneNumberType
except ImportError:  # pragma: no cover
    phonenumbers = None


# Mapa legible de tipos de linea
_TYPE_NAMES = {
    0: "Fijo",
    1: "Movil",
    2: "Fijo o movil",
    3: "Gratuito (toll-free)",
    4: "Tarificacion especial (premium)",
    5: "Coste compartido",
    6: "VoIP",
    7: "Numero personal",
    8: "Buscapersonas (pager)",
    9: "UAN",
    10: "Desconocido",
    27: "Buzon de voz",
}


@dataclass
class PhoneReport:
    raw: str
    default_region: Optional[str] = None
    valid: Optional[bool] = None
    possible: Optional[bool] = None
    e164: Optional[str] = None
    international: Optional[str] = None
    national: Optional[str] = None
    country_code: Optional[int] = None
    region: Optional[str] = None
    carrier: Optional[str] = None
    line_type: Optional[str] = None
    timezones: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def investigate_phone(raw: str, default_region: Optional[str] = "ES") -> PhoneReport:
    """
    Analiza un numero. 'default_region' se usa si el numero no trae prefijo
    internacional (ej. 'ES' para Espana). Si el numero empieza por '+', el
    prefijo manda y default_region se ignora.
    """
    report = PhoneReport(raw=raw, default_region=default_region)

    if phonenumbers is None:
        report.notes.append("Falta la libreria 'phonenumbers'. Instala: pip install phonenumbers")
        return report

    try:
        num = phonenumbers.parse(raw, default_region)
    except phonenumbers.NumberParseException as e:
        report.notes.append(f"No se pudo interpretar el numero: {e}")
        return report

    report.possible = phonenumbers.is_possible_number(num)
    report.valid = phonenumbers.is_valid_number(num)
    report.country_code = num.country_code

    report.e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
    report.international = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
    report.national = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)

    # Region / pais (en espanol cuando hay datos)
    report.region = geocoder.description_for_number(num, "es") or None
    # Operadora (no siempre disponible; depende del rango y portabilidad)
    report.carrier = carrier.name_for_number(num, "es") or None
    # Zonas horarias
    tzs = timezone.time_zones_for_number(num)
    report.timezones = list(tzs) if tzs else []

    # Tipo de linea
    report.line_type = _TYPE_NAMES.get(number_type(num), "Desconocido")

    if not report.valid:
        report.notes.append("El numero NO es valido para esa region/formato.")
    if report.carrier is None:
        report.notes.append("Operadora no disponible (rango sin datos o numero portado).")

    return report


# --- Modo linea de comandos independiente -------------------------------
def _main() -> None:
    import argparse
    import json

    p = argparse.ArgumentParser(description="OSINT pasivo sobre numeros de telefono.")
    p.add_argument("numbers", nargs="+", help="Numeros a analizar (mejor en formato +34...).")
    p.add_argument("--region", default="ES", help="Region por defecto si no hay prefijo (def: ES).")
    p.add_argument("--json", action="store_true", help="Salida JSON.")
    args = p.parse_args()

    for raw in args.numbers:
        r = investigate_phone(raw, default_region=args.region)
        if args.json:
            print(json.dumps(asdict(r), indent=2, ensure_ascii=False))
        else:
            print(f"\n=== {r.raw} ===")
            print(f"  Valido      : {r.valid}")
            print(f"  E.164       : {r.e164}")
            print(f"  Internacional: {r.international}")
            print(f"  Pais/region : {r.region}")
            print(f"  Operadora   : {r.carrier}")
            print(f"  Tipo linea  : {r.line_type}")
            print(f"  Zona horaria: {', '.join(r.timezones) if r.timezones else '-'}")
            for n in r.notes:
                print(f"    - {n}")


if __name__ == "__main__":
    _main()
