#!/usr/bin/env python3
import sys, os, re, shutil, subprocess, argparse
from datetime import datetime

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    print("falta colorama, instala: pip install colorama")
    sys.exit(2)

try:
    import pyfiglet
except ImportError:
    print("falta pyfiglet, instala: pip install pyfiglet")
    sys.exit(2)

PATCHED = {(8,5):(8,5,12), (8,4):(8,4,27), (8,3):(8,3,36), (8,2):(8,2,35)}
MIN_AF = (5,4,0)
EOL = [(5,4),(5,5),(5,6),(6,0),(7,0),(7,1),(7,2),(7,3),(7,4),(8,0),(8,1)]
PATCH_RELEASE = datetime(2026,10,21,14,0,0)


def banner():
    print(Fore.RED + pyfiglet.figlet_format("PHP2Shell", font="slant") + Style.RESET_ALL)
    print(Fore.YELLOW + "="*66)
    print(Fore.RED + Style.BRIGHT + "  Detector de vulnerabilidad PHP2Shell")
    print(Fore.YELLOW + "  CVE-2026-109618 / CVE-2026-109619   |   CVSS v4.0: 9.2 (Critical)")
    print(Fore.YELLOW + "="*66)
    print(Fore.MAGENTA + Style.BRIGHT + "  made by Pr@fEsOr X" + Style.RESET_ALL)
    print()


def get_php_info(binpath):
    p = shutil.which(binpath) or (binpath if os.path.exists(binpath) and os.access(binpath, os.X_OK) else None)
    if p is None:
        return None, None
    try:
        r = subprocess.run([p, "-v"], capture_output=True, text=True, timeout=10)
    except Exception:
        return None, None
    if r.returncode != 0 or not r.stdout:
        return None, None
    first = r.stdout.splitlines()[0].strip()
    m = re.match(r"^PHP\s+(\d+)\.(\d+)\.(\d+)", first)
    if not m:
        return None, None
    v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    b = re.search(r"\(built:\s+([A-Za-z]+\s+\d+\s+\d+\s+\d+:\d+:\d+)\)", first)
    bd = None
    if b:
        try: bd = datetime.strptime(b.group(1), "%b %d %Y %H:%M:%S")
        except ValueError: pass
    return v, bd


def classify(v, bd, mode):
    branch = (v[0], v[1])
    if v < MIN_AF:
        return "unaffected"
    if branch in PATCHED:
        if v >= PATCHED[branch]:
            return "safe"
        base = "vulnerable"
    elif branch in EOL:
        base = "eol_vulnerable"
    else:
        return "unknown"
    if mode != "full" or bd is None:
        return base
    return "backport" if bd >= PATCH_RELEASE else base


def rep_safe(v, bd):
    p = PATCHED[(v[0], v[1])]
    print(Back.GREEN + Fore.WHITE + Style.BRIGHT + "  [OK]   No vulnerable, rama parchada." + Style.RESET_ALL)
    print(Fore.GREEN + f"         Minimo parchado para {v[0]}.{v[1]}: {p[0]}.{p[1]}.{p[2]}")
    print(Fore.GREEN + "         Reinicia php-fpm / Apache para cargar el binario nuevo." + Style.RESET_ALL)
    return 0

def rep_vuln(v, bd):
    p = PATCHED[(v[0], v[1])]
    print(Back.RED + Fore.WHITE + Style.BRIGHT + "  [VULNERABLE]  Actualiza YA, existe parche oficial." + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + f"         Sube a {p[0]}.{p[1]}.{p[2]} o superior.")
    if bd is None:
        print(Fore.YELLOW + "         Sin fecha de build, no puedo confirmar backport." + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "         Reinicia php-fpm / Apache / FrankenPHP / LiteSpeed despues." + Style.RESET_ALL)
    return 1

def rep_eol(v, bd):
    print(Back.RED + Fore.WHITE + Style.BRIGHT + "  [VULNERABLE-EOL]  Sin parche oficial para tu rama." + Style.RESET_ALL)
    print(Fore.RED + Style.BRIGHT + f"         {v[0]}.{v[1]} es EOL, php.net ya no la toca.")
    if bd is None:
        print(Fore.YELLOW + "         Sin fecha de build para confirmar backport." + Style.RESET_ALL)
    print(Fore.YELLOW + "         Migrar a 8.5.12+ / 8.4.27+ / 8.3.36+ / 8.2.35+ o ELS o aislar host." + Style.RESET_ALL)
    return 1

def rep_backport(v, bd):
    p = PATCHED.get((v[0], v[1]))
    sug = f"{p[0]}.{p[1]}.{p[2]}" if p else "(EOL: migrar o ELS)"
    print(Back.YELLOW + Fore.BLACK + Style.BRIGHT + "  [BACKPORT?]  Version dice vulnerable, build posterior al parche." + Style.RESET_ALL)
    print(Fore.YELLOW + f"         Tu distro probablemente backporteo sin subir version.")
    print(Fore.YELLOW + f"         php.net sugiere: {sug}")
    print(Fore.YELLOW + f"         Build: {bd.strftime('%Y-%m-%d %H:%M UTC')}  >=  parche: {PATCH_RELEASE.strftime('%Y-%m-%d %H:%M UTC')}")
    print(Fore.CYAN + "         Confirma con tu distro o phpinfo()." + Style.RESET_ALL)
    return 4

def rep_low(v, bd):
    print(Back.YELLOW + Fore.BLACK + Style.BRIGHT + "  [LOW]  PHP < 5.4.0, fuera del PoC filtrado." + Style.RESET_ALL)
    print(Fore.YELLOW + "        Igual actualiza, eso no deberia correr." + Style.RESET_ALL)
    return 0

def rep_unknown(v, bd):
    print(Back.YELLOW + Fore.BLACK + Style.BRIGHT + "  [?]  Rama PHP rara, no se." + Style.RESET_ALL)
    print(Fore.YELLOW + "       Mira en php.net." + Style.RESET_ALL)
    return 3


REPORTERS = {
    "safe": rep_safe,
    "vulnerable": rep_vuln,
    "eol_vulnerable": rep_eol,
    "backport": rep_backport,
    "unaffected": rep_low,
    "unknown": rep_unknown,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--php", default="php")
    ap.add_argument("--mode", choices=["version", "full"], default="version")
    args = ap.parse_args()

    banner()
    print(Fore.CYAN + f"[*] Modo: {args.mode}" + Style.RESET_ALL)
    print(Fore.CYAN + "[*] Detectando interprete PHP local...\n" + Style.RESET_ALL)

    v, bd = get_php_info(args.php)
    if v is None:
        print(Fore.RED + Style.BRIGHT + f"[!] No hay PHP en '{args.php}'." + Style.RESET_ALL)
        print(Fore.YELLOW + "    usa --php /ruta/al/binario" + Style.RESET_ALL)
        return 2

    ver = f"{v[0]}.{v[1]}.{v[2]}"
    print(Fore.CYAN + f"[*] Binario: {args.php}")
    print(Fore.CYAN + f"[*] Version: {ver}")
    if args.mode == "full":
        bstr = bd.strftime("%Y-%m-%d %H:%M:%S UTC") if bd else "(sin fecha)"
        print(Fore.CYAN + f"[*] Build:   {bstr}")
    print()

    s = classify(v, bd, args.mode)
    return REPORTERS[s](v, bd)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Cancelado." + Style.RESET_ALL)
        sys.exit(130)
