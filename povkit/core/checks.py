"""Check results, shared by preflight, discovery and drift. Same shape and exit codes as the demo kit."""

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


def check(cid, label, status, detail="", fix="", fixable=False, console=None):
    """One check result. A warning or failure also carries `howto`: the step-by-step fix from fixes.json."""
    out = {"id": cid, "label": label, "status": status, "detail": detail, "fix": fix, "fixable": fixable,
           "console": console}
    if status in (WARN, FAIL):
        from ..fixes import find
        out["howto"] = find([cid], detail)
    return out


def exit_code(checks) -> int:
    """0 all pass, 2 warnings, 1 any failure."""
    st = {c["status"] for c in checks}
    return 1 if FAIL in st else 2 if WARN in st else 0


MARK = {OK: "ok  ", WARN: "warn", FAIL: "FAIL", INFO: "info"}


def render(checks, steps=True, pov_id=None) -> str:
    """Plain text. steps=False prints only the one-line fix, not the step-by-step one."""
    from ..fixes import as_text
    lines = []
    for c in checks:
        lines.append(f"  [{MARK[c['status']]}] {c['label']}" + (f": {c['detail']}" if c["detail"] else ""))
        if c["status"] in (WARN, FAIL):
            if c["fix"]:
                lines.append(f"         fix: {c['fix']}")
            h = c.get("howto")
            if steps and h:
                t = as_text(h)
                lines.append(t.replace("<pov-id>", pov_id) if pov_id else t)
    return "\n".join(lines)
