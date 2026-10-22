"""Check results, shared by preflight, discovery and drift. Same shape and exit codes as the demo kit."""

OK, WARN, FAIL, INFO = "ok", "warn", "fail", "info"


def check(cid, label, status, detail="", fix="", fixable=False, console=None):
    return {"id": cid, "label": label, "status": status, "detail": detail, "fix": fix, "fixable": fixable,
            "console": console}


def exit_code(checks) -> int:
    """0 all pass, 2 warnings, 1 any failure."""
    st = {c["status"] for c in checks}
    return 1 if FAIL in st else 2 if WARN in st else 0


MARK = {OK: "ok  ", WARN: "warn", FAIL: "FAIL", INFO: "info"}


def render(checks) -> str:
    lines = []
    for c in checks:
        lines.append(f"  [{MARK[c['status']]}] {c['label']}" + (f": {c['detail']}" if c["detail"] else ""))
        if c["fix"] and c["status"] in (WARN, FAIL):
            lines.append(f"         fix: {c['fix']}")
    return "\n".join(lines)
