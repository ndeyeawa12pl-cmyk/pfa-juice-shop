#!/usr/bin/env python3
"""Security Gate DevSecOps - politique fail-closed pour le PFA."""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
BLOCKING_NEW = {"HIGH", "CRITICAL"}
REPORT_FILES = {
    "semgrep": "semgrep.json",
    "dependency-check": "dependency-check.json",
    "trivy": "trivy.json",
    "zap": "zap.json",
}


class ReportError(Exception):
    pass


def obj(value, where):
    if not isinstance(value, dict):
        raise ReportError(f"{where}: objet JSON attendu")
    return value


def array(value, where):
    if not isinstance(value, list):
        raise ReportError(f"{where}: tableau JSON attendu")
    return value


def severity(value, tool, where):
    raw = str(value or "").strip().upper()
    raw = {"MODERATE": "MEDIUM", "ERROR": "HIGH", "WARNING": "MEDIUM"}.get(raw, raw)
    if raw not in RANK:
        raise ReportError(f"{tool}: gravité absente/inconnue {value!r} dans {where}")
    return raw


def load(path):
    try:
        with open(path, encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ReportError(f"{path}: JSON illisible: {exc}") from exc


def make(tool, rule, location, sev, title="", package=""):
    rule, location, package = str(rule or "?"), str(location or "?"), str(package or "")
    # Empreinte sans numéro de ligne; le package/lieu préserve le contexte.
    fp = "|".join((tool, rule, location, package))
    return {
        "tool": tool, "rule": rule, "location": location,
        "package": package, "severity": sev, "title": str(title or "")[:500],
        "fingerprint": fp,
    }


def parse_semgrep(path):
    root = obj(load(path), "Semgrep")
    results = array(root.get("results"), "Semgrep.results")
    output = []
    for i, result in enumerate(results):
        result = obj(result, f"Semgrep.results[{i}]")
        extra = obj(result.get("extra", {}), f"Semgrep.results[{i}].extra")
        sev = severity(extra.get("severity"), "Semgrep", f"results[{i}]")
        output.append(make("semgrep", result.get("check_id"), result.get("path"),
                           sev, extra.get("message")))
    return output


def parse_trivy(path):
    root = obj(load(path), "Trivy")
    results = array(root.get("Results"), "Trivy.Results")
    output = []
    for i, result in enumerate(results):
        result = obj(result, f"Trivy.Results[{i}]")
        target = result.get("Target") or "image"
        vulns = array(result.get("Vulnerabilities") or [], f"Trivy.Results[{i}].Vulnerabilities")
        for j, vuln in enumerate(vulns):
            vuln = obj(vuln, f"Trivy vulnerability[{i}:{j}]")
            sev = severity(vuln.get("Severity"), "Trivy", f"{target}[{j}]")
            output.append(make("trivy", vuln.get("VulnerabilityID"), target, sev,
                               vuln.get("Title") or vuln.get("Description"),
                               vuln.get("PkgName")))
    return output


def parse_depcheck(path):
    root = obj(load(path), "Dependency-Check")
    dependencies = array(root.get("dependencies"), "Dependency-Check.dependencies")
    output = []
    for i, dep in enumerate(dependencies):
        dep = obj(dep, f"Dependency-Check.dependencies[{i}]")
        for j, vuln in enumerate(dep.get("vulnerabilities") or []):
            vuln = obj(vuln, f"Dependency-Check vulnerability[{i}:{j}]")
            sev = severity(vuln.get("severity"), "Dependency-Check", f"dependency[{i}]")
            filename = dep.get("fileName") or dep.get("filePath") or "?"
            output.append(make("dependency-check", vuln.get("name"), filename, sev,
                               vuln.get("description"), filename))
    return output


def parse_zap(path):
    root = obj(load(path), "ZAP")
    sites = array(root.get("site"), "ZAP.site")
    risk_map = {"0": "INFO", "1": "LOW", "2": "MEDIUM", "3": "HIGH"}
    output = []
    for i, site in enumerate(sites):
        site = obj(site, f"ZAP.site[{i}]")
        alerts = array(site.get("alerts"), f"ZAP.site[{i}].alerts")
        for j, alert in enumerate(alerts):
            alert = obj(alert, f"ZAP alert[{i}:{j}]")
            risk = str(alert.get("riskcode", ""))
            if risk not in risk_map:
                raise ReportError(f"ZAP: riskcode inconnu {risk!r}")
            instances = alert.get("instances") or []
            if not instances:
                output.append(make("zap", alert.get("pluginid"), alert.get("name"),
                                   risk_map[risk], alert.get("desc")))
            for k, instance in enumerate(instances):
                instance = obj(instance, f"ZAP instance[{i}:{j}:{k}]")
                uri = instance.get("uri") or site.get("@name") or "?"
                output.append(make("zap", alert.get("pluginid"), uri, risk_map[risk],
                                   alert.get("desc"), instance.get("param")))
    return output


PARSERS = {
    "semgrep": parse_semgrep,
    "dependency-check": parse_depcheck,
    "trivy": parse_trivy,
    "zap": parse_zap,
}


def write_json(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    temp = path + ".tmp"
    with open(temp, "w", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2, ensure_ascii=False)
        stream.write("\n")
    os.replace(temp, path)


def load_baseline(path):
    root = obj(load(path), "baseline")
    entries = obj(root.get("findings"), "baseline.findings")
    result = {}
    for fp, value in entries.items():
        # Compatibilité avec l'ancien format: fingerprint -> "HIGH".
        val = value.get("severity") if isinstance(value, dict) else value
        result[fp] = severity(val, "baseline", fp)
    return result


def main():
    ap = argparse.ArgumentParser(description="Security Gate DevSecOps")
    ap.add_argument("--reports", required=True)
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--require", default="semgrep,trivy,zap,dependency-check")
    ap.add_argument("--reset-baseline", action="store_true")
    # Jalon "zéro CRITICAL" : bloque aussi les CRITICAL déjà présentes.
    ap.add_argument("--fail-on-critical", action="store_true",
                    help="bloquer aussi toute faille CRITICAL existante")
    args = ap.parse_args()

    required = [x.strip() for x in args.require.split(",") if x.strip()]
    if not required or len(required) != len(set(required)):
        print("[GATE] Liste --require vide ou avec doublons.")
        return 2
    unknown = [x for x in required if x not in PARSERS]
    if unknown:
        print(f"[GATE] Outils inconnus: {unknown}")
        return 2

    by_fp, missing, invalid = {}, [], []
    for tool in required:
        path = os.path.join(args.reports, REPORT_FILES[tool])
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            missing.append(tool)
            continue
        try:
            for finding in PARSERS[tool](path):
                fp = finding["fingerprint"]
                previous = by_fp.get(fp)
                if previous is None or RANK[finding["severity"]] > RANK[previous["severity"]]:
                    by_fp[fp] = finding
        except (ReportError, TypeError, KeyError, AttributeError) as exc:
            invalid.append(f"{tool}: {exc}")

    findings = list(by_fp.values())
    counts = {}
    for finding in findings:
        tool = finding["tool"]
        counts.setdefault(tool, {s: 0 for s in SEVERITIES})
        counts[tool][finding["severity"]] += 1

    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "counts": counts, "total_findings": len(findings),
        "missing_reports": missing, "invalid_reports": invalid,
    }
    write_json(os.path.join(args.reports, "findings.json"), findings)

    if missing or invalid:
        summary["decision"] = "INCOMPLETE"
        write_json(os.path.join(args.reports, "summary.json"), summary)
        print(f"[GATE] BLOCK: rapports absents={missing}; invalides={invalid}")
        return 2

    critical = [f for f in findings if f["severity"] == "CRITICAL"]

    if args.reset_baseline:
        if critical and args.fail_on_critical:
            summary["decision"] = "BASELINE_REJECTED_CRITICAL_PRESENT"
            write_json(os.path.join(args.reports, "summary.json"), summary)
            print("[GATE] BLOCK: baseline refusée, des CRITICAL sont présentes.")
            return 1
        baseline_data = {
            "schema_version": 2,
            "created_at": summary["generated_at"],
            "findings": {fp: {"severity": f["severity"]} for fp, f in by_fp.items()},
        }
        write_json(args.baseline, baseline_data)
        summary["decision"] = "BASELINE_CREATED"
        summary["baseline_total"] = len(findings)
        write_json(os.path.join(args.reports, "summary.json"), summary)
        print(f"[GATE] Baseline créée: {len(findings)} alertes. Aucun déploiement sur ce build.")
        return 0

    if not os.path.isfile(args.baseline):
        summary["decision"] = "BASELINE_MISSING"
        write_json(os.path.join(args.reports, "summary.json"), summary)
        print("[GATE] BLOCK: baseline absente. Revue puis RESET_BASELINE explicite requis.")
        return 2

    try:
        baseline = load_baseline(args.baseline)
    except ReportError as exc:
        summary["decision"] = "BASELINE_INVALID"
        summary["baseline_error"] = str(exc)
        write_json(os.path.join(args.reports, "summary.json"), summary)
        print(f"[GATE] BLOCK: {exc}")
        return 2

    new = [f for fp, f in by_fp.items() if fp not in baseline]
    escalated = []
    for fp, finding in by_fp.items():
        old_sev = baseline.get(fp)
        if old_sev and RANK[finding["severity"]] > RANK[old_sev]:
            if finding["severity"] in BLOCKING_NEW:
                escalated.append(finding)

    new_blocking = [f for f in new if f["severity"] in BLOCKING_NEW]
    critical_blocking = critical if args.fail_on_critical else []
    blocked = bool(new_blocking or escalated or critical_blocking)
    summary.update({
        "baseline_total": len(baseline),
        "new_findings": len(new),
        "new_blocking": len(new_blocking),
        "severity_escalations_blocking": len(escalated),
        "critical_present": len(critical),
        "fixed_since_baseline": len(set(baseline) - set(by_fp)),
        "decision": "BLOCKED" if blocked else "PASSED",
    })
    write_json(os.path.join(args.reports, "summary.json"), summary)

    print(f"[GATE] total={len(findings)} nouvelles={len(new)} "
          f"nouvelles_bloquantes={len(new_blocking)} escalades={len(escalated)} "
          f"CRITICAL_presentes={len(critical)}")
    print(f"[GATE] DECISION: {summary['decision']}")
    return 1 if blocked else 0


if __name__ == "__main__":
    sys.exit(main())
