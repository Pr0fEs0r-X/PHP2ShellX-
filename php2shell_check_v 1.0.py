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
PATCH_REL = datetime(2026,10,21,14,0,0)

R, G, Y, C, M = Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.CYAN, Fore.MAGENTA
BG_R, BG_G, BG_Y = Back.RED, Back.GREEN, Back.YELLOW
B = Style.BRIGHT
RS = Style.RESET_ALL


def banner():
    print(R + pyfiglet.figlet_format("PHP2Shell", font="slant") + RS)
    print(Y + "="*66)
    print(R + B + "  Detector de vulnerabilidad PHP2Shell")
    print(Y + "  CVE-2026-109618 / CVE-2026-109619   |   CVSS v4.0: 9.2 (Critical)")
    print(Y + "="*66)
    print(M + B + "  made by Pr@fEsOr X" + RS)
    print()


def get_php(bin_):
    p = shutil.which(bin_) or (bin_ if os.path.exists(bin_) and os.access(bin_, os.X_OK) else None)
    if not p: return None, None
    try:
        r = subprocess.run([p, "-v"], capture_output=True, text=True, timeout=10)
    except: return None, None
    if r.returncode or not r.stdout: return None, None
    first = r.stdout.splitlines()[0].strip()
    m = re.match(r"^PHP\s+(\d+)\.(\d+)\.(\d+)", first)
    if not m: return None, None
    v = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    bd = None
    b = re.search(r"\(built:\s+([A-Za-z]+\s+\d+\s+\d+\s+\d+:\d+:\d+)\)", first)
    if b:
        try: bd = datetime.strptime(b.group(1), "%b %d %Y %H:%M:%S")
        except: pass
    return v, bd


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--php", default="php")
    ap.add_argument("--mode", choices=["version","full"], default="version")
    a = ap.parse_args()

    banner()
    print(C + f"[*] Modo: {a.mode}")
    print(C + "[*] Detectando interprete PHP local...\n" + RS)

    v, bd = get_php(a.php)
    if v is None:
        print(R + B + f"[!] No hay PHP en '{a.php}'." + RS)
        print(Y + "    usa --php /ruta/al/binario" + RS)
        return 2

    ver = f"{v[0]}.{v[1]}.{v[2]}"
    print(C + f"[*] Binario: {a.php}")
    print(C + f"[*] Version: {ver}")
    if a.mode == "full":
        bstr = bd.strftime("%Y-%m-%d %H:%M:%S UTC") if bd else "(sin fecha)"
        print(C + f"[*] Build:   {bstr}")
    print()

    branch = (v[0], v[1])

    if v < MIN_AF:
        print(BG_Y + "  [LOW]  PHP < 5.4.0, fuera del PoC filtrado." + RS)
        print(Y + "        Igual actualiza, eso no deberia correr." + RS)
        return 0

    if branch in PATCHED:
        p = PATCHED[branch]
        if v >= p:
            print(BG_G + "  [OK]   No vulnerable, rama parchada." + RS)
            print(G + f"         Minimo parchado para {v[0]}.{v[1]}: {p[0]}.{p[1]}.{p[2]}")
            print(G + "         Reinicia php-fpm / Apache para cargar el binario nuevo." + RS)
            return 0
        if a.mode == "full" and bd and bd >= PATCH_REL:
            print(BG_Y + "  [BACKPORT?]  Version dice vulnerable, build posterior al parche." + RS)
            print(Y + "         Tu distro probablemente backporteo sin subir version.")
            print(Y + f"         php.net sugiere: {p[0]}.{p[1]}.{p[2]}")
            print(Y + f"         Build: {bd.strftime('%Y-%m-%d %H:%M UTC')}  >=  parche: {PATCH_REL.strftime('%Y-%m-%d %H:%M UTC')}")
            print(C + "         Confirma con tu distro o phpinfo()." + RS)
            return 4
        print(BG_R + "  [VULNERABLE]  Actualiza YA, existe parche oficial." + RS)
        print(R + B + f"         Sube a {p[0]}.{p[1]}.{p[2]} o superior.")
        if bd is None:
            print(Y + "         Sin fecha de build, no puedo confirmar backport." + RS)
        else:
            print(Y + "         Reinicia php-fpm / Apache / FrankenPHP / LiteSpeed despues." + RS)
        return 1

    if branch in EOL:
        if a.mode == "full" and bd and bd >= PATCH_REL:
            print(BG_Y + "  [BACKPORT?]  Version dice vulnerable, build posterior al parche." + RS)
            print(Y + "         Tu distro probablemente backporteo sin subir version.")
            print(Y + "         php.net sugiere: (EOL: migrar o ELS)")
            print(Y + f"         Build: {bd.strftime('%Y-%m-%d %H:%M UTC')}  >=  parche: {PATCH_REL.strftime('%Y-%m-%d %H:%M UTC')}")
            print(C + "         Confirma con tu distro o phpinfo()." + RS)
            return 4
        print(BG_R + "  [VULNERABLE-EOL]  Sin parche oficial para tu rama." + RS)
        print(R + B + f"         {v[0]}.{v[1]} es EOL, php.net ya no la toca.")
        if bd is None:
            print(Y + "         Sin fecha de build para confirmar backport." + RS)
        print(Y + "         Migrar a 8.5.12+ / 8.4.27+ / 8.3.36+ / 8.2.35+ o ELS o aislar host." + RS)
        return 1

    print(BG_Y + "  [?]  Rama PHP rara, no se." + RS)
    print(Y + "       Mira en php.net." + RS)
    return 3


if __name__ == "__main__":
    try: sys.exit(main())
    except KeyboardInterrupt:
        print(Y + "\n[!] Cancelado." + RS)
        sys.exit(130)
