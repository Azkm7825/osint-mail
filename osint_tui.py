#!/usr/bin/env python3
"""
osint_tui — Interfaz interactiva estilo terminal "hacker" para email-osint.

Ejecuta:  python osint_tui.py

Reutiliza la logica de email_osint.py. Solo consulta fuentes publicas.
Uso etico: cuentas propias, laboratorio o engagement autorizado por escrito.
"""

from __future__ import annotations

import os
import sys
import time
import random

# --- Core OSINT (de tu modulo) -------------------------------------------
from email_osint import (
    investigate,
    permutations,
    validate_syntax,
    check_domain_mx,
    check_gravatar,
    check_hibp,
    EmailReport,
)


# ---------------------------------------------------------------------------
# Colores ANSI (se activan tambien en Windows 10/11)
# ---------------------------------------------------------------------------
def _enable_ansi() -> None:
    if os.name == "nt":
        os.system("")  # activa el procesamiento de secuencias VT en cmd/PowerShell


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    GREEN = "\033[92m"
    DGREEN = "\033[32m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    GREY = "\033[90m"
    WHITE = "\033[97m"


BANNER = r"""
   ___  ____  ___ _   _ _____   __  __    _    ___ _
  / _ \/ ___||_ _| \ | |_   _| |  \/  |  / \  |_ _| |
 | | | \___ \ | ||  \| | | |   | |\/| | / _ \  | || |
 | |_| |___) || || |\  | | |   | |  | |/ ___ \ | || |___
  \___/|____/|___|_| \_| |_|   |_|  |_/_/   \_\___|_____|
"""

TAGLINE = "  [ e-mail reconnaissance toolkit // educational ]"


# ---------------------------------------------------------------------------
# Utilidades de UI
# ---------------------------------------------------------------------------
def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def cprint(text: str, color: str = C.GREEN, bold: bool = False) -> None:
    b = C.BOLD if bold else ""
    print(f"{b}{color}{text}{C.RESET}")


def typeln(text: str, color: str = C.GREEN, delay: float = 0.004) -> None:
    """Imprime con efecto de 'tecleo' linea a linea."""
    for ch in text:
        sys.stdout.write(f"{color}{ch}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")


def matrix_rain(lines: int = 6, width: int = 54) -> None:
    chars = "01</>{}[]#$@%&*ABCDEF0123456789abcdef"
    for _ in range(lines):
        row = "".join(random.choice(chars) for _ in range(width))
        cprint("  " + row, C.DGREEN)
        time.sleep(0.03)


def banner() -> None:
    clear()
    cprint(BANNER, C.GREEN, bold=True)
    cprint(TAGLINE, C.CYAN)
    cprint("  " + "=" * 54, C.DGREEN)
    matrix_rain(3)
    cprint("  " + "=" * 54, C.DGREEN)
    cprint("  [!] Solo fuentes publicas. Uso etico y autorizado.", C.YELLOW)
    print()


def pause() -> None:
    cprint("\n  [ pulsa ENTER para volver al menu ]", C.GREY)
    input()


def prompt(label: str, color: str = C.CYAN) -> str:
    return input(f"{color}  {label} {C.GREEN}> {C.RESET}").strip()


def spinner(msg: str, seconds: float = 0.8) -> None:
    frames = "|/-\\"
    end = time.time() + seconds
    i = 0
    while time.time() < end:
        sys.stdout.write(f"\r{C.DGREEN}  [{frames[i % len(frames)]}] {msg}...{C.RESET}")
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write(f"\r{C.GREEN}  [+] {msg}... OK{C.RESET}\n")


# ---------------------------------------------------------------------------
# Render de informe
# ---------------------------------------------------------------------------
def _flag(value) -> str:
    if value is True:
        return f"{C.GREEN}SI{C.RESET}"
    if value is False:
        return f"{C.RED}NO{C.RESET}"
    return f"{C.GREY}?{C.RESET}"


def render_report(r: EmailReport) -> None:
    cprint("\n  +" + "-" * 52 + "+", C.DGREEN)
    cprint(f"  |  OBJETIVO: {r.email:<40}|", C.GREEN, bold=True)
    cprint("  +" + "-" * 52 + "+", C.DGREEN)

    rows = [
        ("Sintaxis valida", _flag(r.valid_syntax)),
    ]
    if r.valid_syntax:
        rows += [
            ("Dominio", f"{C.WHITE}{r.domain}{C.RESET}"),
            ("Desechable", _flag(r.disposable)),
            ("Recibe correo", _flag(r.domain_receives_mail)),
            ("Registros MX", f"{C.WHITE}{', '.join(r.mx_records) if r.mx_records else '-'}{C.RESET}"),
            ("Gravatar", f"{C.CYAN}{r.gravatar_url}{C.RESET}" if r.gravatar_url else f"{C.GREY}no{C.RESET}"),
        ]
        if r.breaches is not None:
            n = len(r.breaches)
            col = C.RED if n else C.GREEN
            detail = f" -> {', '.join(r.breaches)}" if r.breaches else ""
            rows.append(("Brechas (HIBP)", f"{col}{n}{C.RESET}{C.GREY}{detail}{C.RESET}"))

    for label, value in rows:
        cprint(f"  {C.DGREEN}[>]{C.RESET} {label:<16}: ", C.GREEN) if False else \
            print(f"  {C.DGREEN}[>]{C.RESET} {C.GREEN}{label:<16}{C.RESET}: {value}")

    if r.notes:
        cprint("\n  [log]", C.YELLOW)
        for note in r.notes:
            cprint(f"    - {note}", C.GREY)


# ---------------------------------------------------------------------------
# Acciones del menu
# ---------------------------------------------------------------------------
_hibp_key: str | None = None  # se guarda en memoria durante la sesion


def action_check() -> None:
    banner()
    cprint("  >> ESCANEO COMPLETO DE CORREO", C.GREEN, bold=True)
    email = prompt("Introduce el correo objetivo:")
    if not email:
        return
    print()
    spinner("Validando sintaxis", 0.4)
    spinner("Resolviendo DNS / MX", 0.9)
    spinner("Consultando Gravatar", 0.7)
    if _hibp_key:
        spinner("Consultando Have I Been Pwned", 0.9)
    report = investigate(email, hibp_key=_hibp_key)
    render_report(report)
    pause()


def action_batch() -> None:
    banner()
    cprint("  >> ESCANEO EN LOTE", C.GREEN, bold=True)
    cprint("  Introduce correos separados por espacio o coma.", C.GREY)
    raw = prompt("Correos:")
    emails = [e for e in raw.replace(",", " ").split() if e]
    if not emails:
        return
    for email in emails:
        spinner(f"Escaneando {email}", 0.6)
        render_report(investigate(email, hibp_key=_hibp_key))
    pause()


def action_perm() -> None:
    banner()
    cprint("  >> GENERADOR DE PERMUTACIONES", C.GREEN, bold=True)
    first = prompt("Nombre:")
    last = prompt("Apellido:")
    domain = prompt("Dominio (ej. empresa.com):")
    if not (first and last and domain):
        return
    print()
    spinner("Generando patrones", 0.5)
    for addr in permutations(first, last, domain):
        typeln(f"    {addr}", C.GREEN, delay=0.002)
    pause()


def action_setkey() -> None:
    banner()
    global _hibp_key
    cprint("  >> CONFIGURAR API KEY DE HIBP", C.GREEN, bold=True)
    cprint("  La necesitas para consultar brechas publicas.", C.GREY)
    cprint("  Consiguela en: https://haveibeenpwned.com/API/Key", C.GREY)
    key = prompt("API key (vacio para borrar):")
    _hibp_key = key or None
    estado = "configurada" if _hibp_key else "sin configurar"
    spinner("Guardando en memoria de sesion", 0.4)
    cprint(f"  [+] API key {estado}.", C.GREEN)
    pause()


def action_about() -> None:
    banner()
    cprint("  >> ACERCA DE / USO ETICO", C.GREEN, bold=True)
    texto = [
        "",
        "  email-osint es una herramienta EDUCATIVA de reconocimiento",
        "  sobre correos usando unicamente fuentes publicas:",
        "    - validacion de sintaxis y dominio (DNS/MX)",
        "    - deteccion de correos desechables",
        "    - avatar publico (Gravatar)",
        "    - exposicion en brechas publicas (Have I Been Pwned)",
        "    - permutaciones de correo corporativo",
        "",
        "  Usala SOLO sobre:",
        "    [*] tus propias cuentas y dominios",
        "    [*] un laboratorio controlado",
        "    [*] un engagement con autorizacion por escrito",
        "",
        "  El reconocimiento no autorizado puede ser delito",
        "  (arts. 197/264 del Codigo Penal espanol).",
    ]
    for line in texto:
        cprint(line, C.GREY if line.strip().startswith("[") or line.startswith("    ") else C.GREEN)
    pause()


MENU = [
    ("1", "Escanear un correo (completo)", action_check),
    ("2", "Escanear varios correos (lote)", action_batch),
    ("3", "Generar permutaciones de correo", action_perm),
    ("4", "Configurar API key de HIBP", action_setkey),
    ("5", "Acerca de / uso etico", action_about),
    ("0", "Salir", None),
]


def draw_menu() -> None:
    banner()
    key_state = f"{C.GREEN}activa{C.RESET}" if _hibp_key else f"{C.GREY}no configurada{C.RESET}"
    cprint(f"  HIBP: {key_state}", C.DGREEN)
    cprint("  +" + "-" * 40 + "+", C.DGREEN)
    for num, label, _ in MENU:
        color = C.RED if num == "0" else C.GREEN
        print(f"  {C.DGREEN}|{C.RESET}  {color}[{num}]{C.RESET} {C.WHITE}{label:<32}{C.RESET}{C.DGREEN}|{C.RESET}")
    cprint("  +" + "-" * 40 + "+", C.DGREEN)


def main() -> None:
    _enable_ansi()
    actions = {num: fn for num, _, fn in MENU}
    while True:
        draw_menu()
        choice = prompt("Selecciona una opcion")
        if choice == "0":
            clear()
            typeln("  [*] Cerrando sesion... hasta la proxima, operador.", C.GREEN)
            break
        fn = actions.get(choice)
        if fn:
            try:
                fn()
            except KeyboardInterrupt:
                continue
        else:
            cprint("  [!] Opcion invalida.", C.RED)
            time.sleep(0.6)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear()
        print("\nInterrumpido.")
