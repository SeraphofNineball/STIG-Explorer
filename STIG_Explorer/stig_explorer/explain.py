"""Compose rule-specific explanation pieces for the three audience levels.

Topic-level text is stored once (in topics.py / the data file) and referenced
by id. This module produces only the parts that are unique to each rule.
"""

from __future__ import annotations

import re

from . import topics

_PRODUCT = re.compile(
    r"(?:The )?(?:(?:RHEL|Red Hat Enterprise Linux) ?\d+|(?:Microsoft )?Windows(?: Server)? ?(?:\d{4}|1[01])|Window 10|Windows 2016)"
    r"(?P<os> operating systems?| systems?)?",
    re.I,
)

SEVERITY_PLAIN = {
    "high": ("High priority (CAT I)",
             "If this setting is wrong, an attacker could directly and immediately gain access, take control, "
             "or cause serious damage. These are fixed first."),
    "medium": ("Medium priority (CAT II)",
               "If this setting is wrong, it could help an attacker gain access, cause damage, or hide what they did. "
               "Most rules fall into this category."),
    "low": ("Low priority (CAT III)",
            "This setting adds an extra layer of protection. A gap here on its own is less likely to cause harm, "
            "but it weakens the overall defenses."),
}

SEVERITY_PRO = {
    "high": "CAT I: any vulnerability whose exploitation will directly and immediately result in loss of confidentiality, availability or integrity.",
    "medium": "CAT II: any vulnerability whose exploitation has a potential to result in loss of confidentiality, availability or integrity.",
    "low": "CAT III: any vulnerability whose existence degrades measures to protect against loss of confidentiality, availability or integrity.",
}


def plain_title(title: str) -> str:
    t = title.strip()
    m = _PRODUCT.match(t)
    if m:
        rest = t[m.end():].lstrip()
        if m.group("os") or re.match(r"(must|shall|is|are|has|have|should)\b", rest):
            t = "This computer " + rest
        elif re.match(r"[a-z]+ing\b", rest):
            t = "On this computer, " + rest
        else:
            t = "This computer's " + rest
    # Mid-sentence product names: drop after an article, "this computer" otherwise.
    t = re.sub(r"\b(a|an|the)(\s+(?:[a-z]+\s+)?)" + _PRODUCT.pattern, r"\1\2", t, flags=re.I)
    t = re.sub(r"\s{2,}", " ", t)
    t = _PRODUCT.sub("this computer", t)
    t = re.sub(r"\bthis computer's (must|shall)\b", r"this computer \1", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t[0].upper() + t[1:] if t else t


_CHECK_CMD = re.compile(r"^\s*\$\s*(?:sudo\s+)?(.+)$")


def check_commands(check: str, limit: int = 6) -> list[str]:
    cmds = []
    for line in check.split("\n"):
        m = _CHECK_CMD.match(line)
        if m:
            c = m.group(1).strip()
            if c and c not in cmds:
                cmds.append(c)
        if len(cmds) >= limit:
            break
    return cmds


def normalize_title(title: str) -> str:
    t = _PRODUCT.sub(" ", title.lower())
    t = re.sub(r"\b(the|a|an|must|be|configured|so|that|to|system|systems|operating|computer)\b", " ", t)
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def enrich(rule: dict, platform: str) -> dict:
    """Add rule-specific explanation fields in place and return the rule."""
    body = rule["fix"] + "\n" + rule["check"]
    rule["topics"] = topics.classify(rule["title"], body, platform)
    rule["plain"] = plain_title(rule["title"])
    fix_prose = re.sub(r"\$\s*sudo\s+", "$ ", rule["fix"])
    rule["glossary"] = topics.glossary_terms(rule["title"] + "\n" + fix_prose)
    rule["check_cmds"] = check_commands(rule["check"])
    return rule
