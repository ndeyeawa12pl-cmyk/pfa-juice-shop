#!/usr/bin/env python3
"""
security_gate.py - Security Gate du pipeline DevSecOps
(Chapitre 3 section 3.5 : gestion des vulnerabilites et des seuils)

Principe (strategie du "cliquet" / ratcheting) :
  1. On lit les rapports JSON de Semgrep, Dependency-Check, Trivy et OWASP ZAP.
  2. On normalise chaque alerte : outil, regle, emplacement, severite, empreinte.
  3. On compare avec la BASELINE (l'etat de reference des failles deja connues).
  4. On BLOQUE seulement les NOUVELLES failles HIGH / CRITICAL.
     La dette historique est tolerée, mesurée et rendue visible.

Codes de sortie :
  0 = gate valide (ou baseline creee)
  1 = gate bloque (nouvelles failles graves)
  2 = erreur ou rapports manquants/illisibles (on ne deploie pas "a l'aveugle")

Sorties (dans le dossier des rapports) :
  findings.json : toutes les alertes normalisees (donnees d'entree du module IA)
  summary.json  : bilan chiffre du build (a envoyer vers ELK / Grafana)
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
BLOCKING = {"HIGH", "CRITICAL"}
REPORT_FILES = {
    "semgrep": "semgrep.json",
    "dependency-check": "dependency-check.json",
    "trivy": "trivy.json",
    "zap": "zap.json",
}


def norm_sev(value):
    v = str(value or "").strip().upper()
    if v == "MODERATE":
        v = "MEDIUM"
    return v if v in SEVERITIES else "LOW"


def make(tool, rule, where, severity, title="", fix=None):
    return {
        "tool": tool,
        "rule": str(rule),
        "location": str(where),
        "severity": severity,
        "title": (title or "")[:200],
        "fix_available": fix,
        # Empreinte stable : sans numero de ligne, pour qu'un simple
        # decalage de code ne transforme pas une vieille faille en "nouvelle".
        "fingerprint": f"{tool}|{rule}|{where}",
    }


def load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def parse_semgrep(path):
    out = []
    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    for r in load_json(path).get("results", []) or []:
        extra = r.get("extra", {}) or {}
        sev = sev_map.get(str(extra.get("severity", "")).upper(), "LOW")
        out.append(make("semgrep", r.get("check_id", "?"), r.get("path", "?"),
                        sev, extra.get("message", "")))
    return out


def parse_trivy(path):
    out = []
    for res in load_json(path).get("Results", []) or []:
        for v in res.get("Vulnerabilities") or []:
            out.append(make("trivy", v.get("VulnerabilityID", "?"),
                            v.get("PkgName", "?"), norm_sev(v.get("Severity")),
                            v.get("Title", ""), bool(v.get("FixedVersion"))))
    return out


def parse_depcheck(path):
    out = []
    for dep in load_json(path).get("dependencies", []) or []:
        for v in dep.get("vulnerabilities") or []:
            out.append(make("dependency-check", v.get("name", "?"),
                            dep.get("fileName", "?"), norm_sev(v.get("severity")),
                            v.get("description", "")))
    return out


def parse_zap(path):
    out = []
    sev_map = {"3": "HIGH", "2": "MEDIUM", "1": "LOW", "0": "INFO"}
    for site in load_json(path).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            sev = sev_map.get(str(a.get("riskcode", "0")), "INFO")
            out.append(make("zap", a.get("pluginid", "?"), a.get("name", "?"),
                            sev, a.get("desc", "")))
    return out


PARSERS = {
    "semgrep": parse_semgrep,
    "dependency-check": parse_depcheck,
    "trivy": parse_trivy,
    "zap": parse_zap,
}


def count_by_tool(findings):
    counts = {}
    for f in findings.values():
        counts.setdefault(f["tool"], {s: 0 for s in SEVERITIES})
        counts[f["tool"]][f["severity"]] += 1
    return counts


def write_json(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


def main():
    ap = argparse.ArgumentParser(description="Security Gate DevSecOps")
    ap.add_argument("--reports", required=True, help="dossier des rapports JSON")
    ap.add_argument("--baseline", required=True, help="fichier baseline.json")
    ap.add_argument("--require", default="semgrep,trivy,zap,dependency-check",
                    help="outils dont le rapport est obligatoire")
    ap.add_argument("--reset-baseline", action="store_true",
                    help="recreer la baseline a partir de ce build")
    ap.add_argument("--fail-on-critical", action="store_true",
                    help="bloquer aussi toute faille CRITICAL existante (jalon 1)")
    args = ap.parse_args()

    required = [t.strip() for t in args.require.split(",") if t.strip()]
    findings, missing, broken = {}, [], []

    for tool in required:
        if tool not in PARSERS:
            print(f"[GATE] outil inconnu : {tool}")
            return 2
        path = os.path.join(args.reports, REPORT_FILES[tool])
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            missing.append(tool)
            continue
        try:
            items = PARSERS[tool](path)
        except Exception as exc:  # rapport corrompu ou format inattendu
            broken.append(f"{tool} ({exc})")
            continue
        for f in items:
            old = findings.get(f["fingerprint"])
            if old is None or SEVERITIES.index(f["severity"]) > SEVERITIES.index(old["severity"]):
                findings[f["fingerprint"]] = f

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": count_by_tool(findings),
        "total_findings": len(findings),
        "missing_reports": missing,
        "broken_reports": broken,
    }
    write_json(os.path.join(args.reports, "findings.json"), list(findings.values()))

    print("=" * 60)
    print("SECURITY GATE")
    print("=" * 60)
    for tool, c in summary["counts"].items():
        line = ", ".join(f"{s}={c[s]}" for s in reversed(SEVERITIES) if c[s])
        print(f"  {tool:<18} {line or 'aucune alerte'}")

    if missing or broken:
        print(f"[GATE] rapports manquants : {missing} ; illisibles : {broken}")
        print("[GATE] decision impossible : on ne deploie pas a l'aveugle.")
        summary["decision"] = "INCOMPLETE"
        write_json(os.path.join(args.reports, "summary.json"), summary)
        return 2

    baseline_exists = os.path.isfile(args.baseline)
    if args.reset_baseline or not baseline_exists:
        write_json(args.baseline, {
            "created_at": summary["generated_at"],
            "findings": {fp: f["severity"] for fp, f in findings.items()},
        })
        why = "reinitialisee" if baseline_exists else "creee (premier passage)"
        print(f"[GATE] BASELINE {why} : {len(findings)} failles enregistrees.")
        print("[GATE] Cet etat devient la reference. Les prochains builds seront")
        print("[GATE] jugés sur les NOUVELLES failles uniquement.")
        summary["decision"] = "BASELINE_CREATED"
        summary["baseline_total"] = len(findings)
        write_json(os.path.join(args.reports, "summary.json"), summary)
        return 0

    baseline = load_json(args.baseline).get("findings", {})
    new = [f for fp, f in findings.items() if fp not in baseline]
    fixed = [fp for fp in baseline if fp not in findings]
    new_blocking = [f for f in new if f["severity"] in BLOCKING]
    critical_all = [f for f in findings.values() if f["severity"] == "CRITICAL"] \
        if args.fail_on_critical else []

    summary.update({
        "baseline_total": len(baseline),
        "new_findings": len(new),
        "new_blocking": len(new_blocking),
        "fixed_since_baseline": len(fixed),
        "fail_on_critical": args.fail_on_critical,
    })

    print(f"  baseline : {len(baseline)} failles | nouvelles : {len(new)} "
          f"(dont bloquantes : {len(new_blocking)}) | corrigees : {len(fixed)}")

    blocked = bool(new_blocking or critical_all)
    summary["decision"] = "BLOCKED" if blocked else "PASSED"
    write_json(os.path.join(args.reports, "summary.json"), summary)

    if new_blocking:
        print("[GATE] NOUVELLES failles HIGH/CRITICAL introduites :")
        for f in new_blocking[:20]:
            print(f"   - [{f['severity']}] {f['tool']} {f['rule']} -> {f['location']}")
    if critical_all:
        print(f"[GATE] Jalon 'zero CRITICAL' actif : {len(critical_all)} faille(s) CRITICAL presente(s).")
        for f in critical_all[:20]:
            print(f"   - {f['tool']} {f['rule']} -> {f['location']}")

    print("[GATE] DECISION :", summary["decision"])
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
