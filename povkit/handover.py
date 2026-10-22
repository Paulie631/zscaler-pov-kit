"""Handover: the POV's clean exit.

teardown   delete every ledger object (lifecycle.teardown), then clear secrets and discovery data
terraform  write a Terraform folder that adopts the POV objects in place: one `import` block per object with its live
           ID, and Terraform (1.5 or later) writes the matching configuration itself with
           `terraform plan -generate-config-out=generated.tf`. Nothing is recreated. The ledger then marks the
           objects handed over, and the kit never touches them again.
"""
from __future__ import annotations

import re
import textwrap

from . import products
from .core import KitError, secrets
from .core.ledger import HANDED_OVER

PROVIDERS = {"zia": ("zscaler/zia", "zia"), "zpa": ("zscaler/zpa", "zpa")}


def tf_name(n):
    return re.sub(r"[^a-z0-9_]+", "_", n.lower()).strip("_") or "obj"


def terraform(pov, led):
    exports, skipped = [], []
    for e in led.active():
        p = products.get(e["product"])
        spec = p.terraform(e, None) if p.ready else None
        (exports if spec else skipped).append((e, spec))
    if not exports:
        raise KitError("None of this POV's objects can be exported to Terraform yet.")
    out = pov.path("terraform")
    out.mkdir(exist_ok=True)
    used = sorted({e["product"] for e, _ in exports if e["product"] in PROVIDERS})
    req = "\n".join(f'    {PROVIDERS[p][1]} = {{\n      source = "{PROVIDERS[p][0]}"\n    }}' for p in used)
    (out / "versions.tf").write_text(
        f'terraform {{\n  required_version = ">= 1.5"\n  required_providers {{\n{req}\n  }}\n}}\n\n'
        + "".join(f'# Sign-in: give the provider a OneAPI client of your own (see the provider docs).\n'
                  f'provider "{PROVIDERS[p][1]}" {{}}\n' for p in used), encoding="utf-8")
    blocks, seen = [], set()
    for e, spec in exports:
        addr = tf_name(e["name"])
        while addr in seen:
            addr += "_2"
        seen.add(addr)
        note = "" if spec["confirmed"] else \
            "# check: resource type and import ID not yet confirmed against the provider docs\n"
        blocks.append(f'{note}# {e["name"]} ({e["kind"]}, POV {pov.id})\nimport {{\n  to = {spec["type"]}.{addr}\n'
                      f'  id = "{e["id"]}"\n}}\n')
    (out / "imports.tf").write_text("\n".join(blocks), encoding="utf-8")
    (out / "README.md").write_text(textwrap.dedent(f"""\
        # {pov.cfg['customer']}: POV configuration as Terraform

        These {len(exports)} objects were created during POV {pov.id}. The import blocks adopt them as they are, so
        nothing is recreated.

        1. Give the provider a OneAPI client of your own (not the POV kit's, which is being deleted).
        2. `terraform init`
        3. `terraform plan -generate-config-out=generated.tf` writes the configuration for every imported object.
        4. Review `generated.tf`: rename rules (drop the `{pov.prefix}:` prefix) and widen them beyond the pilot group
           when you are ready. The `zpov:{pov.id}` text in descriptions can go too.
        5. `terraform apply` imports them. The first apply changes nothing in the tenant unless you edited the config.

        Not exported (handle in the console): {', '.join(e['name'] for e, _ in skipped) or 'none'}.
        """), encoding="utf-8")
    for e, _ in exports:
        led.mark(e, HANDED_OVER)
    return out, exports, skipped


def finish(pov):
    """Both exits end here: secrets out of the keychain, customer data off the laptop."""
    from . import usecases
    gone = secrets.delete_all(pov.id, usecases.secret_names(pov))
    purged = pov.purge_customer_data()
    pov.cfg["state"] = "handed_over"
    from . import backup
    backup.save(pov)
    pov.cfg["clients"] = {k: ({"client_id": v.get("client_id"), "deleted_secret": True} if v else None)
                          for k, v in (pov.cfg.get("clients") or {}).items()}
    pov.save()
    pov.log("handover", f"handover: {len(gone)} secrets deleted, {', '.join(purged) or 'no'} customer data files removed")
    return gone, purged
