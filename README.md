# PHP2ShellX Detector V 1.0 BETA

[![Made by Pr@fEsOr X](https://img.shields.io/badge/Made%20by-Pr%40fEsOr%20X-blueviolet?style=for-the-badge)](https://github.com/Pr0fEsOr-X)
[![PHP2Shell](https://img.shields.io/badge/PHP2Shell-Detector-red?style=for-the-badge)](https://en.wikipedia.org/wiki/PHP2Shell)
[![CVSS](https://img.shields.io/badge/CVSS%20v4.0-9.2%20Critical-red?style=for-the-badge)](https://www.first.org/cvss/)
[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)]()
[![Dependencies](https://img.shields.io/badge/Dependencies-colorama%20%26%20pyfiglet-yellow)](requirements.txt)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](../../pulls)


> Detector CLI para la vulnerabilidad **PHP2Shell** (`CVE-2026-109618` / `CVE-2026-109619`) en instalaciones locales de PHP.

PHP2Shell es el nombre que investigadores dieron a dos vulnerabilidades críticas de ejecución remota de código (RCE) **sin autenticación** en el intérprete PHP, divulgadas el **21 de octubre de 2026** con CVSS v4.0 **9.2 (Critical)**. Afecta a PHP desde la versión **5.4.0** en adelante y no tiene mitigación parcial: solo parche.

Este script verifica la versión de PHP instalada localmente y te dice:
- Si tu instalación es vulnerable
- Si existe parche oficial para tu rama
- Qué versión mínima necesitas aplicar
- Si tu distro probablemente backportó el parche (modo `full`)

---

## BASH

```bash
pip install -r requirements.txt
python3 php2shell_check.py                 # chequeo rápido
python3 php2shell_check.py --mode full     # chequeo + fecha de build
echo $?                                    # 0=safe, 1=vulnerable, 4=backport
```

---

## Tabla de contenidos

- [Características](#características)
- [Instalación](#instalación)
- [Uso](#uso)
- [Cómo detecta la vulnerabilidad](#cómo-detecta-la-vulnerabilidad)
- [Códigos de salida](#códigos-de-salida)
- [Versiones afectadas](#versiones-afectadas)
- [Integración con CI/CD](#integración-con-cicd)
- [Testing](#testing)
- [Aviso importante](#aviso-importante)
- [Fuentes](#fuentes)
- [Contribuir](#contribuir)
- [Licencia](#licencia)
- [Autor](#autor)

---

## Características

- Banner ASCII con `pyfiglet` + colores `colorama`
- Detección automática del binario `php` en el PATH (o ruta explícita con `--php`)
- Dos modos de verificación:
  - `version` (default) — compara contra la tabla de parches oficiales
  - `full` — además parsea la fecha de build y detecta backports de distro
- 6 estados de resultado: `OK` / `VULNERABLE` / `VULNERABLE-EOL` / `BACKPORT?` / `LOW` / `?`
- Códigos de salida listos para pipelines CI/CD


---

## Instalación

```bash
git clone https://github.com/Pr0fEsOr-X/php2shell-detector.git
cd php2shell-detector
pip install -r requirements.txt
```

---

## Uso

```bash
# Detección automática (usa 'php' del PATH)
python3 php2shell_check.py

# Ruta específica al binario PHP
python3 php2shell_check.py --php /usr/bin/php8.2

# Modo verificación completa (versión + fecha de build)
python3 php2shell_check.py --mode full

# Combinado: ruta específica + modo completo
python3 php2shell_check.py --php /usr/bin/php8.2 --mode full

# Ayuda
python3 php2shell_check.py --help
```

### Modos de verificación

| Modo | Qué hace | Cuándo usarlo |
|------|----------|---------------|
| `version` (default) | Compara el número de versión contra la tabla de parches oficiales | Chequeo rápido, CI/CD estándar |
| `full` | Además de la versión, parsea la fecha de build (`(built: ...)`) y la compara contra la fecha del advisory (21 oct 2026 14:00 UTC). Si la fecha es posterior al parche, marca como `BACKPORT?` | Entornos con distros que backportean (Debian/Ubuntu/RHEL) — detecta parches aplicados sin subir versión |

### Ejemplo de salida (modo `full` con backport)

```
    ____  __  ______ ___  _____ __         ____
   / __ \/ / / / __ \__ \/ ___// /_  ___  / / /
  / /_/ / /_/ / /_/ /_/ /\__ \/ __ \/ _ \/ / /
 / ____/ __  / ____/ __/___/ / / / /  __/ / /
/_/   /_/ /_/_/   /____/____/_/ /_/\___/_/_/

==================================================================
  Detector de vulnerabilidad PHP2Shell
  CVE-2026-109618 / CVE-2026-109619   |   CVSS v4.0: 9.2 (Critical)
==================================================================
  made by Pr@fEsOr X

[*] Modo: full
[*] Detectando interprete PHP local...

[*] Binario: php
[*] Version: 8.5.11
[*] Build:   2026-10-22 14:00:00 UTC

  [BACKPORT?]  Version dice vulnerable, build posterior al parche.
         Tu distro probablemente backporteo sin subir version.
         php.net sugiere: 8.5.12
         Build: 2026-10-22 14:00 UTC  >=  parche: 2026-10-21 14:00 UTC
         Confirma con tu distro o phpinfo().
```

### Ejemplo de salida (vulnerabilidad confirmada)

```
  [VULNERABLE]  Actualiza YA, existe parche oficial.
         Sube a 8.5.12 o superior.
         Reinicia php-fpm / Apache / FrankenPHP / LiteSpeed despues.
```

---

## Cómo detecta la vulnerabilidad

El script **no inspecciona el binario** ni lanza PoC. Lo que hace:

1. **Ejecuta `php -v`** y captura la salida.
2. **Extrae dos datos con regex**:
   - Versión: `PHP 8.5.11` → `(8, 5, 11)` tupla
   - Build date: `(built: Oct 22 2026 14:00:00)` → `datetime`
3. **Clasifica** según el modo:
   - **Modo `version`**: compara la tupla contra una tabla hardcoded de versiones parchadas (`PATCHED = {8.5: (8,5,12), 8.4: (8,4,27), 8.3: (8,3,36), 8.2: (8,2,35)}`).
   - **Modo `full`**: además compara la fecha de build contra `PATCH_RELEASE = 2026-10-21 14:00 UTC` (fecha del advisory oficial). Si la build es posterior al parche pero la versión sigue diciendo vulnerable → tu distro backporteó.

| Versión | Modo | Build date | Resultado |
|---------|------|------------|-----------|
| 8.5.12+ | cualquiera | cualquiera | `safe` |
| 8.5.11 | `version` | (ignorada) | `vulnerable` |
| 8.5.11 | `full` | antes del 21 oct 2026 | `vulnerable` |
| 8.5.11 | `full` | después del 21 oct 2026 | `backport` |
| 8.1.30 | `version` | (ignorada) | `eol_vulnerable` |
| 8.1.30 | `full` | después del 21 oct 2026 | `backport` |
| 5.3.29 | cualquiera | cualquiera | `unaffected` |

Es detección basada en **metadata del binario**, no en inspección de código. Funciona rápido, sin privilegios y sin riesgo, pero depende de que la versión y la fecha de build sean honestas.

---

## Códigos de salida

| Código | Significado | ¿Acción? |
|--------|-------------|----------|
| `0` | No vulnerable (rama parchada, pre-5.4.0, o unaffected) | Ninguna |
| `1` | **Vulnerable** — acción inmediata | Actualizar / migrar / aislar |
| `2` | PHP no detectado | Instalar PHP o usar `--php` |
| `3` | Rama PHP no reconocida | Verificar sitio oficial PHP |
| `4` | Backport probable (modo `full`): versión dice vulnerable pero la fecha de build es posterior al parche | Verificar con distro / `phpinfo()` |

---

## Versiones afectadas

| Rama PHP | Estado | Parche mínimo |
|----------|--------|---------------|
| 8.5.x | < 8.5.12 vulnerable | **8.5.12** |
| 8.4.x | < 8.4.27 vulnerable | **8.4.27** |
| 8.3.x | < 8.3.36 vulnerable | **8.3.36** |
| 8.2.x | < 8.2.35 vulnerable | **8.2.35** |
| 8.1.x | EOL, sin parche upstream | Migrar o ELS |
| 8.0.x | EOL, sin parche upstream | Migrar o ELS |
| 7.x | EOL, sin parche upstream | Migrar o ELS |
| 5.4 – 5.6 | EOL, sin parche upstream | Migrar o ELS |
| < 5.4.0 | No afectada por el PoC filtrado | Actualizar por buenas prácticas |

---

## Integración con CI/CD

### Bash (GitLab CI, GitHub Actions, Jenkins)

```bash
python3 php2shell_check.py
if [ $? -eq 1 ]; then
  echo "::error::PHP vulnerable a PHP2Shell — abortando deploy"
  exit 1
fi
```

### GitHub Actions workflow

```yaml
- name: Check PHP2Shell
  run: |
    pip install colorama pyfiglet
    python3 php2shell_check.py --php /usr/bin/php
```

### Bloquear solo si es crítico (modo full, ignorar backports)

```bash
result=$(python3 php2shell_check.py --mode full; echo $?)
case "$result" in
  0|4) echo "OK o backport probable, continuar" ;;
  1)   echo "::error::PHP vulnerable confirmado"; exit 1 ;;
  *)   echo "::warning::Resultado $result, revisar manualmente" ;;
esac
```

### Cron de monitoreo

```bash
0 6 * * * /usr/bin/python3 /opt/php2shell/php2shell_check.py >> /var/log/php2shell.log 2>&1
```

### Inventario de flota

```bash
for host in $(cat hosts.txt); do
  echo "=== $host ==="
  ssh $host python3 php2shell_check.py --mode full
done
```

---

## Testing

El repo incluye un script de pruebas que valida la lógica de clasificación con mocks:

```bash
python3 scripts/test_php2shell_cases.py
```

Casos cubiertos:

| Versión | Modo | Esperado |
|---------|------|----------|
| `8.5.12` + build nuevo | `version` | `safe` |
| `8.5.11` + build viejo | `version` | `vulnerable` |
| `8.5.11` + build nuevo | `full` | `backport` |
| `8.1.30` + build viejo | `version` | `eol_vulnerable` |
| `5.3.29` + cualquier build | `version` | `unaffected` |

Salida esperada:

```
[OK] 8.5.12   mode=version -> safe (esperado safe)
[OK] 8.5.11   mode=version -> vulnerable (esperado vulnerable)
[OK] 8.5.11   mode=full    -> backport (esperado backport)
[OK] 8.1.30   mode=version -> eol_vulnerable (esperado eol_vulnerable)
[OK] 5.3.29   mode=version -> unaffected (esperado unaffected)

fallas: 0
```

---

## Aviso importante

Este script verifica la **versión CLI** de PHP (`php -v`), que puede diferir de la versión que atiende peticiones en producción (mod_php, PHP-FPM, FrankenPHP, LiteSpeed). Para confirmar la versión real en producción:

```bash
echo '<?php phpinfo();' | sudo tee /var/www/html/info.php
# Visita https://tu-sitio/info.php y revisa "PHP Version"
sudo rm /var/www/html/info.php   # ¡Bórralo después!
```

Actualizar PHP no es suficiente: **debes reiniciar los workers** para que carguen el binario nuevo:

```bash
sudo systemctl restart apache2          # Apache + mod_php
sudo systemctl restart php8.5-fpm       # PHP-FPM
sudo systemctl restart frankenphp       # FrankenPHP
sudo systemctl restart lsws             # LiteSpeed
```

> **Uso defensivo únicamente.** Verifica la vulnerabilidad solo en sistemas propios o donde tengas autorización explícita.

---

## Fuentes

- [Wikipedia: PHP2Shell](https://en.wikipedia.org/wiki/PHP2Shell)
- [watchTowr FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq)
- [Google Cloud advisory](https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619)
- [PHP.net releases](https://www.php.net/releases/)
- [TuxCare ELS](https://tuxcare.com/blog/php2shell-cve)
- [TopSyde analysis](https://topsyde.com/blog/php2shell-critical-php-rce-cve-2026-109618)

---

## Contribuir

Las contribuciones son bienvenidas. Áreas donde se puede mejorar:

- Soporte para más SAPIs (CGI, LiteSpeed nativo, FrankenPHP via Caddy)
- Tabla de hashes SHA256 de binarios parchados
- Detección de PHP embebido en apps (composer.lock analysis)
- Tests para EOL con backport confirmado

1. Fork el repo
2. Crea tu rama (`git checkout -b feature/foo`)
3. Commit tus cambios (`git commit -m 'add foo'`)
4. Push a la rama (`git push origin feature/foo`)
5. Abre un Pull Request

---

## Licencia

Distribuido bajo licencia **MIT**. Ver [`LICENSE`](LICENSE) para más detalles.

---

## Autor

**Pr@fEsOr X**

[![GitHub](https://img.shields.io/badge/GitHub-Pr%40fEsOr%20X-181717?logo=github&logoColor=white)](https://github.com/Pr0fEsOr-X)

---

> Si este proyecto te sirvió, déjale una **estrell
