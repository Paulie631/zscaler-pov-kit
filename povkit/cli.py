"""pov-kit commands. See README.md; the lifecycle is in docs/DESIGN.md."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import VERSION, evidence, handover, lifecycle, products, rolespec, updater
from .core import KitError, pov as povs, secrets
from .core.changelist import ChangeList
from .core.checks import exit_code, render


def tenant_for(pov, which):
    from .tenant import Tenant
    return Tenant(pov, which)


def say(level, msg):
    mark = {"ok": "  ok  ", "warn": "  warn", "info": "  ·   ", "fail": "  FAIL"}.get(level, "      ")
    print(f"{mark} {msg}")


def yesno(q, default=False, assume=False):
    if assume:
        return True
    a = input(f"{q} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not a else a.startswith("y")


def _pov(args):
    return povs.current(getattr(args, "pov", None))


# ---------------------------------------------------------------- commands
def c_new(a):
    names = [x.strip() for x in a.products.split(",") if x.strip()]
    bad = [x for x in names if x not in products.REGISTRY]
    if bad:
        raise KitError(f"Unknown product(s): {', '.join(bad)}. Choose from {', '.join(products.ORDER)}.")
    p = povs.new(a.customer, names, a.prefix)
    print(f"POV {p.id} for {a.customer}: {', '.join(names)}, prefix '{p.prefix}'. Folder: {p.dir}")
    print("Next: `pov-kit set vanity_domain ACME`, `pov-kit set pilot_group \"POV Pilot\"`, then `pov-kit role-spec`.")


def c_list(a):
    cur = povs.CURRENT.read_text().strip() if povs.CURRENT.exists() else ""
    for pid in povs.all_povs():
        p = povs.Pov(pid)
        print(f"{'*' if pid == cur else ' '} {pid:28} {p.cfg['customer']:24} {p.cfg.get('state')}")


def c_use(a):
    povs.Pov(a.pov_id)
    povs.use(a.pov_id)
    print(f"Using POV {a.pov_id}.")


SETTABLE = {"vanity_domain", "cloud", "pilot_group", "placement", "criteria"}


def c_set(a):
    p = _pov(a)
    if a.key not in SETTABLE:
        raise KitError(f"Settable: {', '.join(sorted(SETTABLE))}.")
    v = a.value
    if a.key == "placement" and v not in ("top", "bottom"):
        raise KitError("placement is 'top' or 'bottom'.")
    if a.key == "criteria":
        v = [x.strip() for x in v.split(",") if x.strip()]
    p.cfg[a.key] = v
    p.save()
    print(f"{a.key} = {v}")


def c_role_spec(a):
    p = _pov(a)
    text = rolespec.render(p)
    out = p.path("role-spec.md")
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"(saved to {out})")


def c_connect(a):
    p = _pov(a)
    which = "apply" if a.apply else "discovery"
    cid = a.client_id or input(f"{which} client ID: ").strip()
    secret = getpass.getpass(f"{which} client secret (hidden): ").strip()
    if not (cid and secret):
        raise KitError("Both the client ID and the secret are needed.")
    secrets.put(p.id, f"{which}-client-secret", secret)
    p.cfg.setdefault("clients", {})[which] = {"client_id": cid}
    p.save()
    p.log("connect", f"{which} client saved")
    print(f"Saved the {which} client (secret in the keychain).")


def c_preflight(a):
    p = _pov(a)
    from .core.checks import FAIL, OK, check
    good, why = secrets.keychain_works()
    checks = [check("keychain", "Keychain works on this computer", OK if good else FAIL, why,
                    "" if good else "Unlock the login keychain (Mac) or install a keyring service (Linux).")]
    try:
        _, more = lifecycle.discover(p, tenant_for)
        checks += more
    except KitError as e:
        checks.append(check("connect", "Discovery client signs in", FAIL, str(e)[:200]))
    if a.json:
        print(json.dumps(checks, indent=2))
    else:
        print(render(checks))
    return exit_code(checks)


def c_discover(a):
    p = _pov(a)
    _, checks = lifecycle.discover(p, tenant_for)
    print(render(checks))
    print(f"Snapshot saved to {p.path('discovery.json')} (stays on this laptop).")
    return exit_code(checks)


def c_plan(a):
    p = _pov(a)
    items, notes, h, checks = lifecycle.plan(p, tenant_for)
    print(render(checks))
    creates = [i for i in items if i["action"] != "customer_action"]
    print(f"\nChange list {h[:16]}: {len(creates)} objects to create, {len(items) - len(creates)} customer actions.")
    for i in items:
        print(f"  {'customer' if i['action'] == 'customer_action' else 'create  '}  {i['name']}")
    for n in notes:
        print(f"  note: {n}")
    print(f"\nShow the customer {p.path('plan.html')}, then: pov-kit approve --by \"Name, title\"")
    return exit_code(checks)


def c_approve(a):
    p = _pov(a)
    rec = ChangeList(p.dir).approve(a.by, a.note or "")
    p.log("approve", f"change list {rec['hash'][:12]} approved by {rec['by']}")
    print(f"Approved {rec['hash'][:16]} by {rec['by']}. Next: create the apply client, `pov-kit connect --apply`, "
          "then `pov-kit apply`.")


def c_apply(a):
    p = _pov(a)
    led = lifecycle.apply(p, tenant_for, say)
    print(f"Done: {len(led.active())} POV objects in the ledger. Next: `pov-kit status`, then run the probe.")


def c_status(a):
    p = _pov(a)
    checks = lifecycle.status(p, tenant_for, fix=a.fix, log=say)
    print(render(checks))
    return exit_code(checks)


def c_probe(a):
    from . import probe
    crit = [c for c in products.base.load_catalog() if c.get("probe")]
    if a.criteria:
        want = set(a.criteria.split(","))
        crit = [c for c in crit if c["id"] in want]
    else:
        crit = [c for c in crit if c.get("phase") == "v1"]
    res = probe.run(crit)
    out = Path(a.out or f"pov-probe-{res['run_id']}.json")
    probe.save(res, out)
    ok = sum(r["pass"] for r in res["results"])
    for r in res["results"]:
        say("ok" if r["pass"] else "warn", f"{r['criterion']}: {r['outcome']} (expected {r['expect']}) {r['detail']}")
    print(f"{ok} of {len(res['results'])} as expected. Send {out} to the SE: `pov-kit import-probe {out.name}`.")


def c_import_probe(a):
    p = _pov(a)
    d = evidence.import_probe(p, Path(a.file))
    print(f"Imported run {d['run_id']} from {d.get('device')}: {len(d['results'])} results.")


def c_attest(a):
    p = _pov(a)
    rec = evidence.attest(p, a.criterion, a.note, a.by or getpass.getuser(), a.file)
    print(f"Recorded for {rec['criterion']}.")


def c_test(a):
    p = _pov(a)
    rows = evidence.evaluate(p, set(a.criteria.split(",")) if a.criteria else None)
    for r in rows:
        say({"pass": "ok", "fail": "fail"}.get(r["status"], "warn"), f"{r['criterion']['id']} {r['criterion']['title']}: {r['status']}")
    return 1 if any(r["status"] == "fail" for r in rows) else 2 if any(r["status"] != "pass" for r in rows) else 0


def c_report(a):
    from .report import render_report
    p = _pov(a)
    rows = evidence.evaluate(p)
    out = p.path("report.html")
    out.write_text(render_report(p, rows, ChangeList(p.dir).approval()), encoding="utf-8")
    print(f"Report: {out} (print to PDF from the browser).")


def c_handover(a):
    p = _pov(a)
    led = lifecycle.ledger(p)
    if a.how == "teardown":
        act = led.active()
        adopted = [e for e in act if e["state"] == "adopted"]
        for e in act:
            print(f"  {e['product']:4} {e['kind']:20} {e['name']}{'  (built by hand, adopted)' if e['state'] == 'adopted' else ''}")
        if act and not yesno(f"Delete these {len(act)} POV objects from {p.cfg['customer']}'s tenant?", False, a.yes):
            print("Cancelled.")
            return 1
        incl = bool(adopted) and yesno("Delete the adopted (hand-built) ones too?", False, a.yes)
        checks = lifecycle.teardown(p, tenant_for, say, include_adopted=incl)
        print(render(checks))
        if led.active():
            print("Some objects are still in the ledger; secrets and data are kept until teardown finishes.")
            return 2
    else:
        out, exported, skipped = handover.terraform(p, led)
        print(f"Terraform folder: {out} ({len(exported)} objects, {len(skipped)} not exportable). See its README.md.")
    gone, purged = handover.finish(p)
    print(f"Deleted {len(gone)} secrets from the keychain and {', '.join(purged) or 'no'} customer data files. "
          "Remind the customer to delete the POV's two API clients in the console.")


def c_diagnostics(a):
    from . import diagnostics
    p = _pov(a)
    out = Path(a.out or f"pov-kit-diagnostics-{p.id}.zip")
    out.write_bytes(diagnostics.build(p))
    print(f"Diagnostics: {out} (no secrets, no customer object names).")


def c_update(a):
    if a.rollback:
        updater.rollback()
        print("Rolled back one version.")
        return
    info, newer = updater.check()
    if not newer:
        print(f"Up to date ({VERSION}).")
        return
    print(f"{info['version']} is available (you have {VERSION}).")
    if a.check:
        return 2
    print(f"Installed {updater.install(info)}.")


def c_version(a):
    print(VERSION)


# ---------------------------------------------------------------- parser
def parser():
    ap = argparse.ArgumentParser(prog="pov-kit", description="Zscaler POV Kit")
    ap.add_argument("--pov", help="POV ID (default: the one last used)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def cmd(name, fn, help_):
        s = sub.add_parser(name, help=help_)
        s.set_defaults(fn=fn)
        return s

    s = cmd("new", c_new, "start a POV for a customer")
    s.add_argument("customer")
    s.add_argument("--products", default="zia,zcc")
    s.add_argument("--prefix", default="ZPOV")
    cmd("list", c_list, "list POVs on this laptop")
    s = cmd("use", c_use, "switch to another POV")
    s.add_argument("pov_id")
    s = cmd("set", c_set, "set vanity_domain, cloud, pilot_group, placement or criteria")
    s.add_argument("key")
    s.add_argument("value")
    cmd("role-spec", c_role_spec, "the two API clients' roles")
    s = cmd("connect", c_connect, "save an API client (secret to the keychain)")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--discovery", action="store_true")
    g.add_argument("--apply", action="store_true")
    s.add_argument("--client-id")
    s = cmd("preflight", c_preflight, "read-only checks (exit 0/2/1)")
    s.add_argument("--json", action="store_true")
    cmd("discover", c_discover, "read-only snapshot of the tenant")
    cmd("plan", c_plan, "write the change list for the customer to approve")
    s = cmd("approve", c_approve, "record the customer's approval of the change list")
    s.add_argument("--by", required=True)
    s.add_argument("--note")
    cmd("apply", c_apply, "create the approved objects")
    s = cmd("status", c_status, "drift on POV objects; --fix repairs only those")
    s.add_argument("--fix", action="store_true")
    s = cmd("probe", c_probe, "on a pilot device: run the probe tests (no keys)")
    s.add_argument("--criteria")
    s.add_argument("--out")
    s = cmd("import-probe", c_import_probe, "import a probe results file")
    s.add_argument("file")
    s = cmd("attest", c_attest, "record what a person saw for a criterion")
    s.add_argument("criterion")
    s.add_argument("--note", required=True)
    s.add_argument("--by")
    s.add_argument("--file")
    s = cmd("test", c_test, "evaluate the success criteria")
    s.add_argument("--criteria")
    cmd("report", c_report, "write the evidence report")
    s = cmd("handover", c_handover, "the clean exit: teardown, or terraform")
    s.add_argument("how", choices=["teardown", "terraform"])
    s.add_argument("--yes", action="store_true")
    s = cmd("diagnostics", c_diagnostics, "a zip for the kit owner (no secrets, no customer data)")
    s.add_argument("--out")
    s = cmd("update", c_update, "self-update from GitHub releases")
    s.add_argument("--check", action="store_true")
    s.add_argument("--rollback", action="store_true")
    cmd("version", c_version, "print the version")
    return ap


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return args.fn(args) or 0
    except KitError as e:
        print(f"\n  {e}\n", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n  Stopped.", file=sys.stderr)
        return 130
