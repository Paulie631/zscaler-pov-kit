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
    from .remind import parse_date
    p = povs.new(a.customer, names, a.prefix, parse_date(a.ends) if a.ends else None)
    print(f"POV {p.id} for {a.customer}: {', '.join(names)}, prefix '{p.prefix}', ends {p.cfg['ends']}. Folder: {p.dir}")
    print("Next: `pov-kit set vanity_domain ACME`, `pov-kit set pilot_group \"POV Pilot\"`, then `pov-kit role-spec`.")


def c_list(a):
    cur = povs.CURRENT.read_text().strip() if povs.CURRENT.exists() else ""
    for pid in povs.all_povs():
        p = povs.Pov(pid)
        from .remind import ends
        print(f"{'*' if pid == cur else ' '} {pid:28} {p.cfg['customer']:24} {p.cfg.get('state'):16} ends {ends(p)}")


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
    if a.file:
        rec = ChangeList(p.dir).approve_file(a.file)
    elif a.by:
        rec = ChangeList(p.dir).approve(a.by, a.note or "")
    else:
        raise KitError("Either `--by \"Name, title\"` (approved in front of you) or `--file approval-....json` (saved "
                       "by the customer on the change-list page).")
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
    out = Path(a.out or f"pov-{p.id}-app-connectors{'-azure' if a.cloud == 'azure' else ''}.json")
    connector_template.write(out, p.id, p.prefix, a.cloud)
    if a.cloud == "azure":
        print(f"Azure template: {out}. In the customer's subscription, accept the image terms once (az vm image terms "
              "accept --publisher zscaler --offer zscaler-private-access --plan zpa-con-azure), then Deploy a custom "
              "template > upload it, and enter the provisioning key, the subnet's resource ID and an SSH public key.")
    else:
        print(f"CloudFormation template: {out}. In the customer's AWS account: CloudFormation > Create stack > upload "
              "it, then enter the provisioning key, the App Connector AMI (from the AWS Marketplace), the VPC and subnet.")
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
    if a.summary:
        from . import summary
        s = summary.write(p, a.note or "")
        print(f"Executive summary: {s['headline']}")
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


def c_ai(a):
    from . import ai
    p = _pov(a)
    if a.what == "connect":
        k = getpass.getpass("AI Guard app proxy key (hidden): ").strip()
        if len(k) < 16:
            raise KitError("Paste the AI Guard app's proxy key (PROXY mode, with an Anthropic provider key behind it).")
        secrets.put(*ai.OWN_KEY, k)
        print("Saved to the keychain. Every use-case request now goes to Claude through that AI Guard app.")
    elif a.what == "consent":
        if not a.by:
            raise KitError("Say who agreed: `pov-kit ai consent --by \"Name, title\"`.")
        ai.record_consent(p, a.by)
        how = "the full" if ai.share(p) == "full" else "the names-replaced"
        print(f"Recorded: {a.by} agreed to share {how} discovery snapshot of {p.cfg['customer']} with Claude through "
              "AI Guard.")
    else:
        key, where = ai.proxy_key()
        c = ai.consent(p)
        print(f"AI Guard proxy key: {where if key else 'none. ' + where}")
        print(f"Sharing: {ai.share(p)} (`pov-kit set ai.share names_only|full`)")
        print(f"Customer agreement: {c['by'] + ' on ' + c['at'][:10] if c else 'not yet (for this way of sharing)'}")


def c_usecase(a):
    from . import usecases
    p = _pov(a)
    if a.action == "ask":
        text = " ".join(a.rest).strip()
        snaps, _ = lifecycle.discover(p, tenant_for)
        uc = usecases.propose(p, snaps, text)
        show_usecase(uc)
        print(f"\nNext: `pov-kit usecase accept {uc['id']}` (adds it to the change list; the customer approves again), "
              f"`usecase directions {uc['id']}` or `usecase discard {uc['id']}`.")
    elif a.action == "list":
        for u in usecases.load(p):
            print(f"  {u['id']}  {u['status']:10} {u['prompt'][:80]}")
    elif a.action == "show":
        uc = usecases.get(p, a.rest[0])
        show_usecase(uc)
        if uc["status"] == "directions":
            print("\n" + usecases.directions_md(uc))
    elif a.action == "refine":
        if len(a.rest) < 2:
            raise KitError("`pov-kit usecase refine UC-01 \"make it Caution, not Block\"`")
        snaps, _ = lifecycle.discover(p, tenant_for)
        uc = usecases.refine(p, snaps, a.rest[0], " ".join(a.rest[1:]))
        show_usecase(uc)
    elif a.action == "save":
        from . import library
        e = library.save(p, usecases.get(p, a.rest[0]), title=a.title)
        print(f"Saved to the library as '{e['id']}' ({library.folder()})" + ("; proved in this POV" if e["proved"] else ""))
    elif a.action == "library":
        from . import library
        if a.folder:
            print(f"Library folder: {library.set_folder(a.folder)}")
        for e in library.entries():
            print(f"  {e['id']:40} {'proved ' if e.get('proved') else '       '} {e['title'][:70]}")
        if not library.entries():
            print(f"  (empty: {library.folder()})")
    elif a.action == "use":
        from . import library
        snaps, _ = lifecycle.discover(p, tenant_for)
        uc = library.use(p, snaps, a.rest[0])
        show_usecase(uc)
        print(f"\nNo AI call was made. Next: `pov-kit usecase accept {uc['id']}`.")
    elif a.action in ("accept", "directions", "discard", "proposed"):
        uc = usecases.set_status(p, a.rest[0], "accepted" if a.action == "accept" else a.action)
        if uc["status"] == "accepted":
            print(f"{uc['id']} joins the change list. Run `pov-kit plan`, get it approved again, then `pov-kit apply`.")
        else:
            print(f"{uc['id']}: {uc['status']}")


def show_usecase(uc):
    s = uc["spec"]
    print(f"{uc['id']} ({uc['status']}): {s['summary']}")
    if s["already_covered_by"]:
        print(f"  already proved by: {', '.join(s['already_covered_by'])}")
    for ch in s["changes"]:
        print(f"  change: {ch['kind']} '{ch['name']}' {json.dumps({k: v for k, v in ch.items() if k not in ('kind', 'name', 'why')})}")
    for d in s["dropped"]:
        print(f"  not built: {d['why']}")
    for d in s["directions"]:
        print(f"  directions ({d['product']}{': ' + d['console_page'] if d['console_page'] else ''}): " + " / ".join(d["steps"]))
    t = s["test"]
    print(f"  test: {t['title']}: {len(t['probe'])} probe tests, {len(t.get('aiguard') or [])} AI Guard prompts"
          + (f"; check: {t['attest']}" if t["attest"] else ""))


def c_backup(a):
    from . import backup
    if a.what == "setup":
        if not a.folder:
            raise KitError("Name the folder: `pov-kit backup setup ~/OneDrive/pov-backups`.")
        pw = getpass.getpass("Backup passphrase (12+ characters; keep it in your password manager): ")
        if pw != getpass.getpass("Again: "):
            raise KitError("The passphrases didn't match.")
        d = backup.setup(a.folder, pw)
        print(f"Backups go to {d}, encrypted. Every POV on this laptop is backed up now and after every change.")
    elif a.what == "now":
        out = backup.save(_pov(a), quiet=False)
        print(f"Backed up to {out}." if out else "Backups aren't set up: `pov-kit backup setup FOLDER`.")
    elif a.what == "restore":
        if not a.folder:
            raise KitError("Name the backup file or POV ID: `pov-kit backup restore acme-corp-3f2a`.")
        p = backup.restore(a.folder, getpass.getpass("Backup passphrase: "), overwrite=a.overwrite)
        print(f"Restored POV {p.id} ({p.cfg['customer']}). Save the API client again (`pov-kit connect`), then "
              "`pov-kit status`.")


def c_recover(a):
    from . import recover
    if not (povs.POVS / a.pov_id / "pov.json").exists():
        if not (a.customer and a.products):
            raise KitError("This POV isn't on this laptop. If you have a backup, `pov-kit backup restore "
                           f"{a.pov_id}`. Otherwise: `pov-kit recover {a.pov_id} --customer NAME --products zia,zpa,...`.")
        p = povs.create_with_id(a.pov_id, a.customer, [x.strip() for x in a.products.split(",") if x.strip()], a.prefix)
        print(f"Made an empty POV folder for {p.id}. Save the API client (`pov-kit connect`), then run "
              f"`pov-kit recover {p.id}` again to find its objects.")
        return 0
    p = povs.Pov(a.pov_id)
    povs.use(p.id)
    finds, problems = recover.run(p, tenant_for, write=a.write)
    for f in finds:
        print(f"  {f['proof']:10} {f['product']:8} {f['name']}  -> {f['status']}")
    for x in problems:
        print(f"  couldn't read {x}")
    n = sum(1 for f in finds if f["proof"] != "other POV")
    print(f"\n{n} objects of POV {p.id} found (read-only)." + ("" if a.write else " Run again with --write to record "
          "them in the ledger, then `pov-kit handover teardown` or `pov-kit status`."))
    return 2 if problems else 0


def c_remind(a):
    from . import remind
    if a.what == "install":
        print(f"Reminders on: {remind.install()}. They read only the POV folders on this laptop.")
    elif a.what == "uninstall":
        remind.uninstall()
        print("Reminders off.")
    else:
        urgent, summary = remind.run(weekly=True if a.weekly else None)
        if not (urgent or summary):
            print("Nothing needs doing.")


def c_record(a):
    from . import recorder
    p = _pov(a)
    if a.what in ("on", "off"):
        p.cfg["record"] = a.what == "on"
        p.save()
        print(f"Recording {'on: every API call is saved, redacted, to ' + str(p.path('recordings')) if a.what == 'on' else 'off'}.")
    else:
        out, n = recorder.export(p, a.name or p.id, a.out)
        print(f"Exported {n} distinct calls to {out} (field names, types and Zscaler's own values only).")


def c_selftest(a):
    from . import selftest
    p = _pov(a)
    if not a.lab:
        raise KitError("selftest creates and deletes one object per product. Run it only in your own lab tenant: "
                       "`pov-kit selftest --lab`.")
    res = selftest.run(p, tenant_for, say, lab=True)
    for x in res["steps"]:
        say("ok" if x["ok"] else "fail", f"{x['product']:8} {x['step']:8} {x.get('detail', '')}")
    print(f"\nselftest {'passed' if res['ok'] else 'FAILED'} in {res['seconds']} s.")
    return 0 if res["ok"] else 1


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
    s.add_argument("--ends", help="end date, YYYY-MM-DD (default: 30 days from now)")
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
    s = cmd("approve", c_approve, "record the customer's approval (--by, or --file from the change-list page)")
    s.add_argument("--by")
    s.add_argument("--file")
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
    s = cmd("zpa", c_zpa_template, "zpa template [--cloud aws|azure]: the App Connector template")
    s.add_argument("what", choices=["template"])
    s.add_argument("--cloud", choices=["aws", "azure"], default="aws")
    s.add_argument("--out")
    s.add_argument("--show-key", action="store_true")
    s = cmd("aiguard", c_aiguard_policy, "aiguard policy monitor|attacks|data: what the POV's AI Guard policy blocks")
    s.add_argument("what", choices=["policy"])
    s.add_argument("profile", choices=["monitor", "attacks", "data"])
    s = cmd("report", c_report, "write the evidence report (--summary: Claude drafts the executive summary first)")
    s.add_argument("--summary", action="store_true")
    s.add_argument("--note", help="with --summary: what to emphasize")
    s = cmd("handover", c_handover, "the clean exit: teardown, or terraform")
    s.add_argument("how", choices=["teardown", "terraform"])
    s.add_argument("--yes", action="store_true")
    s = cmd("diagnostics", c_diagnostics, "a zip for the kit owner (no secrets, no customer data)")
    s.add_argument("--out")
    s = cmd("update", c_update, "self-update from GitHub releases")
    s.add_argument("--check", action="store_true")
    s.add_argument("--rollback", action="store_true")
    s = cmd("ai", c_ai, "ai connect|consent|status: Claude through AI Guard for use cases")
    s.add_argument("what", choices=["connect", "consent", "status"])
    s.add_argument("--by")
    s = cmd("usecase", c_usecase, "usecase ask \"...\" | list | show ID | refine ID \"...\" | accept ID | directions ID | "
            "discard ID | save ID | library | use NAME")
    s.add_argument("action", choices=["ask", "list", "show", "refine", "accept", "directions", "discard", "proposed",
                                      "save", "library", "use"])
    s.add_argument("rest", nargs="*")
    s.add_argument("--title", help="with save: the library entry's title")
    s.add_argument("--folder", help="with library: use this folder (e.g. a shared, synced team folder)")
    s = cmd("gui", c_gui, "the POV console in your browser (setup wizard, status, criteria, handover, logs)")
    s.add_argument("--port", type=int, default=8790)
    s.add_argument("--no-browser", action="store_true")
    s = cmd("users", c_users, "the POV's Hosted DB test users (--show prints their passwords)")
    s.add_argument("--show", action="store_true")
    s = cmd("backup", c_backup, "backup setup FOLDER | now | restore FILE-or-POV-ID: encrypted ledger backups")
    s.add_argument("what", choices=["setup", "now", "restore"])
    s.add_argument("folder", nargs="?")
    s.add_argument("--overwrite", action="store_true")
    s = cmd("recover", c_recover, "find a POV's objects in the tenant (read-only) and rebuild its ledger")
    s.add_argument("pov_id")
    s.add_argument("--customer")
    s.add_argument("--products")
    s.add_argument("--prefix", default="ZPOV")
    s.add_argument("--write", action="store_true")
    s = cmd("remind", c_remind, "remind install|uninstall|run: a daily check for POVs ending or left behind")
    s.add_argument("what", choices=["install", "uninstall", "run"])
    s.add_argument("--weekly", action="store_true", help="with run: include the weekly summary")
    s = cmd("record", c_record, "record on|off|export NAME: save redacted API traffic for the offline tests")
    s.add_argument("what", choices=["on", "off", "export"])
    s.add_argument("name", nargs="?")
    s.add_argument("--out")
    s = cmd("selftest", c_selftest, "in YOUR LAB tenant: read, create, read back and delete one object per product")
    s.add_argument("--lab", action="store_true")
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
