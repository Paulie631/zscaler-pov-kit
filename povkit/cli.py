"""pov-kit commands. See README.md; the lifecycle is in docs/DESIGN.md."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import VERSION, evidence, handover, lifecycle, products, rolespec, settings, updater
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


def c_set(a):
    p = _pov(a)
    v = settings.set_value(p, a.key, a.value)
    print(f"{a.key} = {v}")


def c_role_spec(a):
    p = _pov(a)
    text = rolespec.render(p)
    out = p.path("role-spec.md")
    out.write_text(text, encoding="utf-8")
    print(text)
    print(f"(saved to {out})")


def save_client(p, slot, cid, secret):
    if not (cid and secret):
        raise KitError("Both the client ID and the secret are needed.")
    secrets.put(p.id, f"{slot}-client-secret", secret)
    p.cfg.setdefault("clients", {})[slot] = {"client_id": cid}
    p.save()
    p.log("connect", f"{slot} client saved")


def c_connect(a):
    p = _pov(a)
    if a.discovery or a.apply:
        p.cfg["client_mode"] = "separate"
        slot = "apply" if a.apply else "discovery"
    else:
        slot = "main" if p.cfg.get("client_mode", "single") == "single" else "discovery"
    cid = a.client_id or input(f"{slot} client ID: ").strip()
    save_client(p, slot, cid, getpass.getpass(f"{slot} client secret (hidden): ").strip())
    print(f"Saved the {slot} client (secret in the keychain).")


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
    nxt = ("create the apply client, `pov-kit connect --apply`, then `pov-kit apply`"
           if p.cfg.get("client_mode") == "separate" else "`pov-kit apply`")
    print(f"Approved {rec['hash'][:16]} by {rec['by']}. Next: {nxt}.")


def c_apply(a):
    p = _pov(a)
    led = lifecycle.apply(p, tenant_for, say)
    print(f"Done: {len(led.active())} POV objects in the ledger. Next: `pov-kit status`, then run the probe.")


def c_status(a):
    p = _pov(a)
    checks = lifecycle.status(p, tenant_for, fix=a.fix, log=say)
    print(render(checks))
    return exit_code(checks)


def c_probe_pack(a):
    p = _pov(a)
    pack = evidence.probe_pack(p, set(a.criteria.split(",")) if a.criteria else None)
    out = Path(a.out or f"pov-probe-pack-{p.id}.json")
    out.write_text(json.dumps(pack, indent=2), encoding="utf-8")
    n = sum(len(c["probe"]) for c in pack["criteria"])
    print(f"Probe pack: {out} ({len(pack['criteria'])} criteria, {n} tests). Copy it to the pilot device with the kit "
          f"and run `pov-kit probe --pack {out.name}`.")


def c_probe(a):
    from . import probe
    if a.pack:
        crit = json.loads(Path(a.pack).read_text(encoding="utf-8"))["criteria"]
    else:   # no pack: the catalog's tests that need no POV values
        crit = [c for c in products.base.load_catalog() if c.get("probe")]
        crit = [dict(c, probe=[s for s in c["probe"] if not any("{" in str(v) and "{b64}" not in str(v) for v in s.values())])
                for c in crit]
        crit = [c for c in crit if c["probe"]]
    if a.criteria:
        want = set(a.criteria.split(","))
        crit = [c for c in crit if c["id"] in want]
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
    ids = set(a.criteria.split(",")) if a.criteria else None
    if a.api:
        for cid, r in lifecycle.api_proofs(p, tenant_for, ids).items():
            say({"pass": "ok", "fail": "fail"}.get(r["status"], "warn"), f"{cid} API proof: {r['status']} ({r.get('detail', '')})")
    rows = evidence.evaluate(p, ids)
    for r in rows:
        say({"pass": "ok", "fail": "fail"}.get(r["status"], "warn"), f"{r['criterion']['id']} {r['criterion']['title']}: {r['status']}")
    return 1 if any(r["status"] == "fail" for r in rows) else 2 if any(r["status"] != "pass" for r in rows) else 0


def c_zpa_template(a):
    from . import connector_template
    p = _pov(a)
    if not lifecycle.ledger(p).find("zpa.provisioning_key"):
        raise KitError("No POV provisioning key yet. Run `pov-kit apply` with ZPA in the POV first.")
    out = Path(a.out or f"pov-{p.id}-app-connectors.json")
    connector_template.write(out, p.id, p.prefix)
    print(f"CloudFormation template: {out}. In the customer's AWS account: CloudFormation > Create stack > upload it, "
          "then enter the provisioning key, the App Connector AMI (from the AWS Marketplace), the VPC and subnet.")
    if a.show_key:
        key = secrets.get(p.id, "zpa-provisioning-key")
        print(f"Provisioning key (paste into the stack, don't save it anywhere else): {key or '(not in the keychain)'}")
    else:
        print("Add --show-key to print the provisioning key for the stack.")


def c_aiguard_policy(a):
    from .core.guard import LedgerTenant
    p = _pov(a)
    led = lifecycle.ledger(p)
    t = LedgerTenant(tenant_for(p, "apply"), led, [])
    products.get("aiguard").set_profile(t, p, led, a.profile, say)


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


def c_users(a):
    p = _pov(a)
    led = lifecycle.ledger(p)
    made = [e for e in led.active("zia") if e["kind"] == "user"]
    if not made:
        print("This POV has no Hosted DB test users (`pov-kit set identity.test_users 2` before planning).")
        return
    plan = {i["key"]: i for i in ChangeList(p.dir).plan()["items"]}
    for e in made:
        n = e["key"].rsplit(".", 1)[-1]
        pw = secrets.get(p.id, f"zia-test-user-{n}") if a.show else "(add --show to print it)"
        print(f"  {plan.get(e['key'], {}).get('body', {}).get('email', e['name'])}   {pw}")
    print("Sign in to Client Connector on a pilot device with one of these. Passwords stay in this computer's keychain.")


def c_gui(a):
    from . import gui
    gui.serve(port=a.port, open_browser=not a.no_browser)


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
    s.add_argument("--products", default="zia,zcc", help="any of: zia,zcc,zpa,aiguard,zdx,casb")
    s.add_argument("--prefix", default="ZPOV")
    cmd("list", c_list, "list POVs on this laptop")
    s = cmd("use", c_use, "switch to another POV")
    s.add_argument("pov_id")
    s = cmd("set", c_set, "set vanity_domain, cloud, pilot_group, placement or criteria")
    s.add_argument("key")
    s.add_argument("value")
    cmd("role-spec", c_role_spec, "the two API clients' roles")
    s = cmd("connect", c_connect, "save the API client (secret to the keychain); --discovery/--apply: separate mode")
    g = s.add_mutually_exclusive_group()
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
    s = cmd("probe-pack", c_probe_pack, "write this POV's probe tests for the pilot devices")
    s.add_argument("--criteria")
    s.add_argument("--out")
    s = cmd("probe", c_probe, "on a pilot device: run the probe tests (no keys)")
    s.add_argument("--pack")
    s.add_argument("--criteria")
    s.add_argument("--out")
    s = cmd("import-probe", c_import_probe, "import a probe results file")
    s.add_argument("file")
    s = cmd("attest", c_attest, "record what a person saw for a criterion")
    s.add_argument("criterion")
    s.add_argument("--note", required=True)
    s.add_argument("--by")
    s.add_argument("--file")
    s = cmd("test", c_test, "evaluate the success criteria (--api runs the automated API proofs first)")
    s.add_argument("--criteria")
    s.add_argument("--api", action="store_true")
    s = cmd("zpa", c_zpa_template, "zpa template: the App Connector CloudFormation template")
    s.add_argument("what", choices=["template"])
    s.add_argument("--out")
    s.add_argument("--show-key", action="store_true")
    s = cmd("aiguard", c_aiguard_policy, "aiguard policy monitor|attacks|data: what the POV's AI Guard policy blocks")
    s.add_argument("what", choices=["policy"])
    s.add_argument("profile", choices=["monitor", "attacks", "data"])
    cmd("report", c_report, "write the evidence report")
    s = cmd("handover", c_handover, "the clean exit: teardown, or terraform")
    s.add_argument("how", choices=["teardown", "terraform"])
    s.add_argument("--yes", action="store_true")
    s = cmd("diagnostics", c_diagnostics, "a zip for the kit owner (no secrets, no customer data)")
    s.add_argument("--out")
    s = cmd("update", c_update, "self-update from GitHub releases")
    s.add_argument("--check", action="store_true")
    s.add_argument("--rollback", action="store_true")
    s = cmd("gui", c_gui, "the POV console in your browser (setup wizard, status, criteria, handover, logs)")
    s.add_argument("--port", type=int, default=8790)
    s.add_argument("--no-browser", action="store_true")
    s = cmd("users", c_users, "the POV's Hosted DB test users (--show prints their passwords)")
    s.add_argument("--show", action="store_true")
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
