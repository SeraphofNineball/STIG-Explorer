"""Extract the concrete settings a STIG rule changes from its check/fix text.

Every extracted setting is a dict:
    {"type": <kind>, "target": <where>, "name": <what>, "value": <required value>}

Kinds:
    registry      Windows registry value (hive\\path, value name, type+value)
    gpo           Group Policy path and required state
    sysctl        Linux kernel parameter
    audit_rule    Linux auditd rule line
    config        Line in a Linux configuration file
    dconf         GNOME dconf key or lock
    service       systemd unit action
    package       Package install/remove
    permission    chmod/chown/chgrp/setfacl on a path
    feature       Windows role/feature/optional component removal
    command       Other remediation command (fallback, Linux only)
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------- Windows ---

_REG_HIVE = re.compile(r"Registry Hive:\s*(HKEY_[A-Z_]+)", re.I)
_REG_PATH = re.compile(r"Registry Path:\s*(\S.*)", re.I)
_REG_NAME = re.compile(r"Value Name:\s*(\S.*)", re.I)
_REG_TYPE = re.compile(r"(?:Value )?Type:\s*(REG_[A-Z_]+)", re.I)
_REG_VALUE = re.compile(r"^Value:\s*(\S.*)", re.I)


def _registry(check: str) -> list[dict]:
    out, hive, path, name, rtype = [], "", "", "", ""
    for line in check.split("\n"):
        s = line.strip()
        if m := _REG_HIVE.search(s):
            hive = m.group(1).upper()
            continue
        if m := _REG_PATH.search(s):
            path = m.group(1).strip()
            continue
        if m := _REG_NAME.search(s):
            name = m.group(1).strip()
            rtype = ""
            continue
        if m := _REG_TYPE.match(s):
            rtype = m.group(1).upper()
            continue
        if (m := _REG_VALUE.match(s)) and name:
            value = m.group(1).strip()
            full = f"{hive}{path if path.startswith(chr(92)) else chr(92) + path}" if hive else path
            out.append({
                "type": "registry",
                "target": full.rstrip("\\"),
                "name": name,
                "value": f"{rtype} = {value}" if rtype else value,
            })
    return _dedupe(out)


_GPO_START = re.compile(r"(?:Computer|User) Configuration\s*>>")
_GPO_SPLIT = re.compile(
    r"\s(?:to|with|is set to)\s+(?=\"|include|only|be\b|a\b|at least|Success|Failure|this\b|\d|the following)")


def _gpo(fix: str) -> list[dict]:
    out = []
    lines = fix.split("\n")
    for idx, line in enumerate(lines):
        for m in _GPO_START.finditer(line):
            sentence = line[m.start():]
            last = sentence.rfind(">>")
            head, tail = sentence[:last], sentence[last + 2:]
            sm = _GPO_SPLIT.search(tail)
            if sm:
                name, value = tail[:sm.start()], tail[sm.end():]
            else:
                name, value = re.split(r"(?<=[a-z\")])\.\s|\.$", tail)[0], ""
            value = re.split(r"(?<=[\"a-z0-9)])\.(?:\s|$)", value)[0].strip()
            if re.search(r"(include only|only include|the following)", value, re.I):
                members = []
                for nxt in lines[idx + 1:]:
                    t = nxt.strip()
                    if not t and not members:
                        continue
                    if not t:
                        break
                    bullet = t.startswith(("-", "*", "\u2022"))
                    item = t.lstrip("-*\u2022 ").strip()
                    if item.endswith(":"):
                        continue  # sub-heading such as "Domain Systems Only:"
                    # Member lines are short names, not prose sentences.
                    if len(item.split()) > 7 or ">>" in item or re.match(r"[\w ]+:\s", item) \
                            or (item.endswith(".") and not bullet):
                        break
                    members.append(item.rstrip("."))
                if members:
                    value = "Only: " + ", ".join(members)
            elif re.search(r"be defined but containing no entries", value, re.I):
                value = "No accounts or groups (defined, blank)"
            parts = [p.strip() for p in head.split(">>")]
            out.append({
                "type": "gpo",
                "target": " >> ".join(parts),
                "name": name.strip().strip('"'),
                "value": value.rstrip(":").strip(),
            })
    return _dedupe(out)


_FEATURE = re.compile(
    r"(?:Uninstall|Remove|Disable)\s+(?:the\s+)?\"([^\"]+)\"\s+(?:feature|role|optional feature)", re.I)
_PS_FEATURE = re.compile(
    r"(?:Uninstall-WindowsFeature|Remove-WindowsFeature|Disable-WindowsOptionalFeature)[^\n]*?"
    r"(?:-Name|-FeatureName)\s+([\w-]+)", re.I)


def _features(fix: str) -> list[dict]:
    out = []
    for m in _FEATURE.finditer(fix):
        out.append({"type": "feature", "target": "Windows feature", "name": m.group(1), "value": "Removed"})
    for m in _PS_FEATURE.finditer(fix):
        out.append({"type": "feature", "target": "Windows feature", "name": m.group(1), "value": "Removed"})
    return _dedupe(out)


# ------------------------------------------------------------------ Linux ---

_PATH = re.compile(r"(/(?:etc|usr|var|boot|lib|proc|sys|root|home|opt|run)/[\w./*@+:-]*\w)")
_CFG_PATH = re.compile(r"(/(?:etc|usr/lib|usr/share|boot|root)/[\w./*@+:-]*[\w*])")
_SYSCTL = re.compile(r"^((?:kernel|net|fs|vm|user|crypto|dev)\.[\w.\-/*]+)\s*=\s*(\S+)$")
_AUDIT = re.compile(r"^(-[aw]\s.+|-e\s+2|--loginuid-immutable|-f\s+\d|-b\s+\d+)$")
_ROOT_CMDS = (
    "aide|auditctl|augenrules|authconfig|authselect|awk|blkid|cat|chage|chattr|chcon|chgrp|chmod|chown|cp|dconf|"
    "df|dnf|dracut|echo|find|fips-mode-setup|firewall-cmd|grep|grub2-mkconfig|grub2-setpassword|grubby|ip|ln|ls|"
    "mkdir|modprobe|more|mount|mv|nmcli|passwd|postconf|restorecon|rm|rpm|sed|semanage|service|setfacl|setsebool|"
    "stat|sudo|sysctl|systemctl|touch|update-crypto-policies|usbguard|useradd|usermod|vi|visudo|yum"
)
# "$ cmd" / "$ sudo cmd" (RHEL 8+) or "# cmd" root prompt (RHEL 7). The root form
# only matches known commands so "# comment" lines in config examples are ignored.
_CMD = re.compile(rf"^(?:\$\s*|#\s+(?=(?:{_ROOT_CMDS})\b|/usr/))(?:sudo\s+)?(.+)$")
_PKG = re.compile(r"\b(?:dnf|yum)\s+(?:-y\s+)?(install|remove|erase)\s+(?:-y\s+)?([\w.+\- ]+)")
_SVC = re.compile(r"\bsystemctl\s+((?:enable|disable|mask|unmask|start|stop)(?:\s+--now)?)\s+(?:--now\s+)?([\w@.\-]+)")
_PERM = re.compile(r"^(chmod|chown|chgrp|setfacl|restorecon|semanage|setsebool|chcon)\s+(.+)$")
_DCONF_SECTION = re.compile(r"^\[(org/[\w/.\-]+)\]$")
_DCONF_LOCK = re.compile(r"^(/org/[\w/.\-]+)$")
_KV = re.compile(r"^([A-Za-z_][\w.\-]*)(\s*=\s*|\s+)(\S.*)$")
_SKIP_CMDS = ("vi ", "vim ", "nano ", "cat ", "grep ", "touch ", "mkdir ", "ls ", "echo ")


def _looks_like_config(line: str) -> bool:
    if len(line) > 160 or line.endswith((":", ".")) and not re.search(r"\s=\s", line):
        return False
    if line.startswith(("$", "#", "-", "*", "[", "/", "<", "\"", "(", "http")):
        return False
    m = _KV.match(line)
    if not m:
        return False
    key, sep, rest = m.groups()
    if key.lower() in {"the", "a", "an", "if", "add", "edit", "to", "this", "for", "note", "run",
                       "then", "and", "or", "use", "with", "remove", "set", "configure", "verify",
                       "example", "create", "update", "restart", "replace", "in", "on", "all", "any",
                       "where", "check", "reboot", "ensure", "modify", "rebuild", "select", "enable",
                       "disable", "install", "uninstall", "start", "stop", "load", "apply", "it", "is",
                       "start", "please", "include", "there", "by", "make", "change", "only", "value"}:
        return False
    if sep.strip() != "=" and len(rest.split()) > 6:
        return False
    if len(key) < 2 or ":" in key or rest.lstrip().startswith((":", "=")) or key.isupper() and len(key) > 12 and "_" not in key:
        return False
    return True


def _linux(fix: str) -> list[dict]:
    out = []
    current_file = ""
    dconf_section = ""
    in_example_output = False
    for raw in fix.split("\n"):
        line = raw.strip()
        if not line:
            dconf_section = dconf_section if dconf_section else ""
            continue
        low = line.lower()
        if low.startswith(("example output", "the output", "output:")):
            in_example_output = True
            continue
        # Track the most recently mentioned config file (from prose lines only)
        # so config lines get a target.
        paths = _CFG_PATH.findall(line)
        if paths and not line.startswith(("$", "-")) and (len(line.split()) >= 4 or line.endswith(":")):
            if not in_example_output or re.match(r"(add|edit|create|modify|configure|remove|update|set)\b", low):
                in_example_output = False
                current_file = paths[-1]

        if m := _CMD.match(line):
            in_example_output = False
            cmd = m.group(1).strip()
            if pk := _PKG.search(cmd):
                action = "Installed" if pk.group(1) == "install" else "Removed"
                for name in pk.group(2).split():
                    if not name.startswith("-"):
                        out.append({"type": "package", "target": "dnf", "name": name, "value": action})
                continue
            if sv := _SVC.search(cmd):
                out.append({"type": "service", "target": "systemd", "name": sv.group(2),
                            "value": sv.group(1).replace(" --now", " (now)")})
                continue
            if pm := _PERM.match(cmd):
                out.append({"type": "permission", "target": pm.group(1), "name": pm.group(2), "value": ""})
                continue
            if fp := _PATH.findall(cmd):
                if any(cmd.startswith(s) for s in ("vi ", "vim ", "nano ", "touch ")):
                    current_file = fp[-1]
            if not cmd.startswith(_SKIP_CMDS):
                out.append({"type": "command", "target": "shell", "name": cmd, "value": ""})
            continue

        if in_example_output:
            continue

        if m := _SYSCTL.match(line):
            out.append({"type": "sysctl", "target": current_file or "/etc/sysctl.d/",
                        "name": m.group(1), "value": m.group(2)})
            continue
        if _AUDIT.match(line):
            tgt = current_file if current_file.startswith("/etc/audit") else "/etc/audit/rules.d/audit.rules"
            out.append({"type": "audit_rule", "target": tgt,
                        "name": line, "value": ""})
            continue
        if m := _DCONF_SECTION.match(line):
            dconf_section = m.group(1)
            continue
        if (m := _DCONF_LOCK.match(line)) and "dconf" in fix:
            out.append({"type": "dconf", "target": current_file or "/etc/dconf/db/local.d/locks/",
                        "name": m.group(1), "value": "locked"})
            continue
        if dconf_section and "=" in line and not line.startswith("$"):
            k, _, v = line.partition("=")
            out.append({"type": "dconf", "target": f"[{dconf_section}]",
                        "name": k.strip(), "value": v.strip()})
            continue
        if current_file and _looks_like_config(line):
            m = _KV.match(line)
            key, sep, rest = m.groups()
            out.append({"type": "config", "target": current_file, "name": key,
                        "value": rest.strip() if sep.strip() == "=" else rest.strip(),
                        "line": line})
            continue
    return _dedupe(out)


def _dedupe(items: list[dict]) -> list[dict]:
    seen, out = set(), []
    for it in items:
        k = (it["type"], it["target"], it["name"], it["value"])
        if k not in seen:
            seen.add(k)
            out.append(it)
    return out


def extract(rule: dict, platform: str) -> list[dict]:
    if platform == "windows":
        items = _registry(rule["check"]) + _gpo(rule["fix"]) + _features(rule["fix"])
    else:
        items = _linux(rule["fix"])
    return items


TYPE_LABELS = {
    "registry": "Registry value",
    "gpo": "Group Policy",
    "sysctl": "Kernel parameter (sysctl)",
    "audit_rule": "Audit rule",
    "config": "Config file setting",
    "dconf": "GNOME (dconf) setting",
    "service": "Service (systemd)",
    "package": "Software package",
    "permission": "File permission / ownership / label",
    "feature": "Windows feature",
    "command": "Remediation command",
}


def setting_categories(items: list[dict], fix: str) -> list[str]:
    """High-level 'how is this implemented' tags used as a search facet."""
    cats = {TYPE_LABELS[i["type"]] for i in items if i["type"] != "command"}
    if not cats:
        low = fix.lower()
        if re.search(r"\b(document|isso|issm|organization|policy|procedur|approv|authoriz)", low):
            cats.add("Procedural / documentation")
        elif items:
            cats.add("Remediation command")
        else:
            cats.add("Manual configuration")
    return sorted(cats)
