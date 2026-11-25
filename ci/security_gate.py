#!/usr/bin/env python3
"""Security Gate DevSecOps - politique fail-closed pour le PFA."""

import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

SEVERITIES = ("UNKNOWN", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: index for index, name in enumerate(SEVERITIES)}
BLOCKING_NEW = {"CRITICAL"}
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
    raw = {
        "MODERATE": "MEDIUM",
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "": "UNKNOWN",
    }.get(raw, raw)
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
    results = array(root.get("Results") or [], "Trivy.Results")
    output = []
    for i, result in enumerate(results):
        result = obj(result, f"Trivy.Results[{i}]")
        target = result.get("Target") or "image"
        # La cible des paquets OS contient le tag de l'image (donc le numéro de
        # build) : on la remplace par une valeur stable pour que l'empreinte
        # d'une même faille reste identique d'un build à l'autre.
        if result.get("Class") == "os-pkgs":
            target = "os-packages:" + str(result.get("Type") or "os")
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
