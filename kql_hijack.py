#!/usr/bin/env python3
"""
hijacklibs_to_kql.py
--------------------
Génère des requêtes KQL (Microsoft Defender XDR / Sentinel) de détection de
DLL hijacking à partir de la liste HijackLibs (https://hijacklibs.net).

Logique de détection (identique à l'approche HijackLibs) :
    une DLL référencée est chargée depuis un dossier qui ne fait PAS partie
    de ses "ExpectedLocations" -> suspect.
    Les DLL sans ExpectedLocations (souvent de type "Phantom") sont signalées
    quel que soit le dossier de chargement.

Fonctionnalités :
    - téléchargement du CSV officiel (ou lecture d'un fichier local)
    - regroupement des lignes par nom de DLL (1 ligne CSV = 1 couple DLL/exe)
    - expansion des variables HijackLibs (%SYSTEM32%, %PROGRAMFILES%, ...)
      en chemins concrets, %VERSION% et chemins utilisateur -> regex RE2
    - découpage en plusieurs requêtes de N DLL max (100 par défaut)
    - colonne IsKnownVulnExe : le process qui charge la DLL fait partie des
      exécutables vulnérables connus pour cette DLL (aide au tri)

Usage :
    python3 hijacklibs_to_kql.py                       # télécharge + génère
    python3 hijacklibs_to_kql.py -i hijacklibs.csv     # CSV local
    python3 hijacklibs_to_kql.py --chunk-size 50 --lookback 7d -o out/
    python3 hijacklibs_to_kql.py --types Sideloading "Search Order"
    python3 hijacklibs_to_kql.py --only-known-exe      # haute fidélité

Aucune dépendance externe (stdlib uniquement).
"""

from __future__ import annotations

import argparse
import csv
import io
import ntpath
import re
import sys
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_URL = "https://hijacklibs.net/api/hijacklibs.csv"
MULTI_SEP = ", "  # séparateur multi-valeurs utilisé dans le CSV HijackLibs

# Placeholders internes (en minuscules : les chemins sont passés en lower())
USER_TOKEN = "\x00user\x00"        # segment utilisateur (C:\Users\<user>)
VERSION_TOKEN = "\x00version\x00"  # %VERSION%


def build_env_map(system_drive: str, users_root: str) -> dict[str, list[str]]:
    """
    Variables documentées par HijackLibs (docs/SCHEMA.md) + celles
    effectivement présentes dans le repo. Une variable peut s'étendre en
    plusieurs chemins (ex. %PROGRAMFILES% -> x64 et x86).
    Tout est en minuscules : la comparaison KQL se fait sur tolower().
    """
    d = system_drive.lower().rstrip("\\")
    u = users_root.lower().rstrip("\\") + "\\" + USER_TOKEN
    return {
        "%SYSTEM32%": [rf"{d}\windows\system32"],
        "%SYSWOW64%": [rf"{d}\windows\syswow64"],
        "%WINDIR%": [rf"{d}\windows"],
        "%SYSTEMROOT%": [rf"{d}\windows"],
        "%PROGRAMFILES%": [rf"{d}\program files", rf"{d}\program files (x86)"],
        "%PROGRAMFILES(X86)%": [rf"{d}\program files (x86)"],
        "%PROGRAMDATA%": [rf"{d}\programdata"],
        "%USERPROFILE%": [u],
        "%APPDATA%": [rf"{u}\appdata\roaming"],
        "%LOCALAPPDATA%": [rf"{u}\appdata\local"],
    }


VAR_RE = re.compile(r"%[A-Za-z0-9_()]+%")


def expand_path(path: str, env: dict[str, list[str]]) -> tuple[list[str], set[str]]:
    """
    Étend toutes les variables d'un chemin. Retourne (chemins, variables inconnues).
    %VERSION% est remplacé par un placeholder converti plus tard en regex.
    """
    results = [path.strip().rstrip("\\")]
    unknown: set[str] = set()
    for var in VAR_RE.findall(path):
        key = var.upper()
        if key == "%VERSION%":
            results = [r.replace(var, VERSION_TOKEN) for r in results]
            continue
        if key not in env:
            unknown.add(key)
            continue
        new = []
        for r in results:
            for val in env[key]:
                new.append(r.replace(var, val))
        results = new
    return [r.lower() for r in results], unknown


RE2_SPECIAL = set(r"\.^$|?*+()[]{}")


def re2_escape(s: str) -> str:
    return "".join("\\" + c if c in RE2_SPECIAL else c for c in s)


def to_regex(p: str) -> str:
    """Chemin contenant des placeholders -> regex RE2 ancrée (sans groupe)."""
    out = re2_escape(p)
    out = out.replace(re2_escape(USER_TOKEN), r"[^\\]+")
    out = out.replace(re2_escape(VERSION_TOKEN), r"[^\\]*")
    return "^" + out + "$"


def kql_str(s: str) -> str:
    """Littéral KQL verbatim (@"..."), les guillemets sont doublés."""
    return '@"' + s.replace('"', '""') + '"'


# ---------------------------------------------------------------------------
# Lecture du CSV
# ---------------------------------------------------------------------------

def load_csv(path: str | None, url: str) -> list[dict]:
    if path:
        text = Path(path).read_text(encoding="utf-8-sig")
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "hijacklibs-to-kql"})
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode("utf-8-sig")
    return list(csv.DictReader(io.StringIO(text)))


def split_multi(value: str | None) -> list[str]:
    if not value:
        return []
    return [v.strip() for v in value.split(MULTI_SEP) if v.strip()]


def aggregate(rows: list[dict], types: list[str] | None) -> "OrderedDict[str, dict]":
    """Regroupe par nom de DLL (union des emplacements / exe sur toutes les entrées)."""
    wanted = {t.lower() for t in types} if types else None
    dlls: "OrderedDict[str, dict]" = OrderedDict()
    for row in rows:
        name = (row.get("Name") or "").strip().lower()
        if not name.endswith(".dll"):
            continue
        vtype = (row.get("VulnerableExecutableType") or "").strip()
        if wanted and vtype.lower() not in wanted:
            continue
        e = dlls.setdefault(name, {"locations": [], "exes": set(), "types": set(), "vendors": set()})
        for loc in split_multi(row.get("ExpectedLocations")):
            if loc not in e["locations"]:
                e["locations"].append(loc)
        for exe in split_multi(row.get("VulnerableExecutablePath")):
            e["exes"].add(ntpath.basename(exe).lower())
        if vtype:
            e["types"].add(vtype)
        if row.get("Vendor"):
            e["vendors"].add(row["Vendor"].strip())
    return OrderedDict(sorted(dlls.items()))


# ---------------------------------------------------------------------------
# Génération KQL
# ---------------------------------------------------------------------------

def expected_predicate(locations: list[str], env: dict, unknown_vars: set[str]) -> str:
    """Prédicat KQL vrai si Dir est un emplacement attendu pour la DLL."""
    exact: list[str] = []
    regexes: list[str] = []
    for loc in locations:
        expanded, unk = expand_path(loc, env)
        unknown_vars |= unk
        for p in expanded:
            if "%" in p:  # variable inconnue restée telle quelle -> ignorée
                continue
            if USER_TOKEN in p or VERSION_TOKEN in p:
                regexes.append(to_regex(p))
            elif p not in exact:
                exact.append(p)
    parts = []
    if exact:
        parts.append("Dir in (" + ", ".join(kql_str(p) for p in exact) + ")")
    if regexes:
        # alternance sans groupe capturant (limite RE2 côté Kusto : 16 groupes)
        parts.append("Dir matches regex " + kql_str("|".join(dict.fromkeys(regexes))))
    return " or ".join(parts) if parts else "false"


def build_query(chunk: list[tuple[str, dict]], idx: int, total: int, args, env, unknown_vars) -> str:
    names = [n for n, _ in chunk]
    t = args.time_column
    lines = [
        f"// HijackLibs DLL hijacking - partie {idx}/{total} ({len(chunk)} DLL)",
        f"// Source : {args.input or args.url}",
        f"// Généré le {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC par hijacklibs_to_kql.py",
        f"// DLL : {names[0]} -> {names[-1]}",
        f"{args.table}",
    ]
    if args.lookback:
        lines.append(f"| where {t} > ago({args.lookback})")
    lines += [
        "| where FileName in~ (" + ", ".join(kql_str(n) for n in names) + ")",
        "| extend Dll = tolower(FileName), ImgPath = tolower(FolderPath)",
        "// FolderPath peut contenir le nom du fichier : on ne garde que le dossier",
        '| extend Dir = iff(ImgPath endswith strcat(@"\\", Dll), substring(ImgPath, 0, strlen(ImgPath) - strlen(Dll) - 1), ImgPath)',
        "| extend IsExpected = case(",
    ]
    for name, e in chunk:
        pred = expected_predicate(e["locations"], env, unknown_vars)
        lines.append(f"    Dll == {kql_str(name)}, {pred},")
    lines += ["    false)", "| where not(IsExpected)"]

    lines.append("| extend IsKnownVulnExe = case(")
    for name, e in chunk:
        if e["exes"]:
            exes = ", ".join(kql_str(x) for x in sorted(e["exes"]))
            lines.append(f"    Dll == {kql_str(name)}, tolower(InitiatingProcessFileName) in ({exes}),")
    lines += ["    false)"]
    if args.only_known_exe:
        lines.append("| where IsKnownVulnExe")

    lines.append(
        f"| project {t}, DeviceId, DeviceName, ReportId, FileName, FolderPath, SHA256, "
        "IsKnownVulnExe, InitiatingProcessFileName, InitiatingProcessFolderPath, "
        "InitiatingProcessSHA1, InitiatingProcessCommandLine, InitiatingProcessAccountName"
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description="HijackLibs CSV -> requêtes KQL découpées")
    ap.add_argument("-i", "--input", help="CSV local (sinon téléchargement depuis --url)")
    ap.add_argument("--url", default=DEFAULT_URL)
    ap.add_argument("-o", "--out-dir", default="kql_hijacklibs")
    ap.add_argument("--chunk-size", type=int, default=100, help="DLL max par requête (défaut 100)")
    ap.add_argument("--table", default="DeviceImageLoadEvents")
    ap.add_argument("--time-column", default="Timestamp", help="Timestamp (Defender) ou TimeGenerated (Sentinel)")
    ap.add_argument("--lookback", default="1d", help="ex. 1h, 1d, 7d ; vide pour désactiver")
    ap.add_argument("--types", nargs="+", help='filtre : Sideloading Phantom "Search Order" "Environment Variable"')
    ap.add_argument("--only-known-exe", action="store_true",
                    help="ne garder que les chargements par un exe vulnérable connu")
    ap.add_argument("--system-drive", default="C:")
    ap.add_argument("--users-root", default=r"C:\Users")
    args = ap.parse_args()

    if args.chunk_size < 1:
        ap.error("--chunk-size doit être >= 1")

    rows = load_csv(args.input, args.url)
    dlls = aggregate(rows, args.types)
    if not dlls:
        print("Aucune DLL trouvée (CSV vide ou filtre --types trop restrictif).", file=sys.stderr)
        return 1

    env = build_env_map(args.system_drive, args.users_root)
    items = list(dlls.items())
    chunks = [items[i:i + args.chunk_size] for i in range(0, len(items), args.chunk_size)]
    out = Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)

    unknown_vars: set[str] = set()
    for i, chunk in enumerate(chunks, 1):
        q = build_query(chunk, i, len(chunks), args, env, unknown_vars)
        (out / f"hijacklibs_part{i:02d}.kql").write_text(q, encoding="utf-8")

    no_loc = sum(1 for e in dlls.values() if not e["locations"])
    print(f"{len(rows)} lignes CSV -> {len(dlls)} DLL uniques -> {len(chunks)} requête(s) dans {out}/")
    print(f"{no_loc} DLL sans ExpectedLocations (signalées quel que soit le dossier).")
    if unknown_vars:
        print("Variables non gérées (emplacements ignorés, à ajouter dans build_env_map) : "
              + ", ".join(sorted(unknown_vars)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
