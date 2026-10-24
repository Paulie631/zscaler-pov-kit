"""Proxy mode for Anthropic and OpenAI side by side, from what the customer's AI Guard has."""
from povkit import aiguard_runner as runner, gui, lifecycle
from povkit.core import secrets
from povkit.core.changelist import ChangeList
from povkit.products import aiguard as ag


def items_of(p, tenant_for):
    items, *_ = lifecycle.plan(p, tenant_for)
    return {i["key"]: i for i in items if i["product"] == "aiguard"}


def both(tenant):
    tenant.store["aiguard.llm_providers"].append({"id": 801, "name": "OpenAI", "type": "openai"})
    tenant.store["aiguard.llm_provider_credentials"].append({"id": 802, "name": "Acme OpenAI key", "providerId": 801})


def test_old_single_provider_settings_still_work(pov_all):
    pov_all.cfg["aiguard"] = {"proxy": "se", "provider": "openai", "model": "gpt-x"}
    s = ag.proxy_setup(pov_all)
    assert s["openai"] == {"use": "se", "cred": None, "model": "gpt-x"} and s["anthropic"]["use"] == "off"
    assert ag.proxy_cfg(pov_all) == ("se", "openai", "gpt-x")


def test_both_providers_get_their_own_key_and_rule(pov_all, tenant, tenant_for):
    both(tenant)
    pov_all.cfg["aiguard"] = {"providers": {"anthropic": {"use": "customer", "cred": 702},
                                            "openai": {"use": "se", "model": "gpt-4o-mini"}}}
    pov_all.save()
    secrets.put(pov_all.id, ag.provider_secret("openai"), "sk-openai-" + "x" * 30)
    by = items_of(pov_all, tenant_for)
    assert by["aiguard.proxy_key"]["body"]["providerCredentialsId"] == 702
    assert by["aiguard.proxy_key_openai"]["body"]["providerCredentialsId"] == "{ref:aiguard.provider_cred_openai}"
    assert by["aiguard.provider_cred_openai"]["body"]["apiCredentials"]["token"] == "{secret:aiguard-provider-key-openai}"
    orders = sorted(by[k]["body"]["ruleOrder"] for k in ("aiguard.proxy_rule", "aiguard.proxy_rule_openai"))
    assert orders[1] == orders[0] + 1
    assert "sk-openai" not in ChangeList(pov_all.dir).plan_file.read_text()
    ChangeList(pov_all.dir).approve("Jane")
    lifecycle.apply(pov_all, tenant_for, lambda *a: None)
    assert set(runner.proxy_keys(pov_all)) == {"anthropic", "openai"}
    made = next(c for c in tenant.store["aiguard.llm_provider_credentials"] if c["name"].startswith("ZPOV"))
    assert made["apiCredentials"]["token"].startswith("sk-openai")
    seen = []
    chat = lambda pt, key, model, text, user=None: (seen.append((pt, model)), ("hi", 5, False))[1]   # noqa: E731
    tests = runner.find_tests(pov_all, preset="attacks")[:4]
    runner.run(pov_all, tests, mode="proxy", chat=chat, pause=0, providers=["anthropic", "openai"])
    assert {p for p, _ in seen} == {"anthropic", "openai"} and ("openai", "gpt-4o-mini") in seen
    lifecycle.teardown(pov_all, tenant_for, lambda *a: None)
    assert not [c for c in tenant.store["aiguard.llm_provider_credentials"] if c["name"].startswith("ZPOV")]


def test_console_shows_both_from_the_tenant(pov_all, tenant, tenant_for, monkeypatch):
    both(tenant)
    monkeypatch.setattr(gui, "tf", tenant_for)
    gui.api("POST", "/api/preflight", {}, {})
    d = gui.api("GET", "/api/aiguard", {}, {})[1]["proxy"]["providers"]
    assert d["anthropic"]["available"] and d["openai"]["available"]
    assert d["openai"]["creds"] == [{"id": 802, "name": "Acme OpenAI key"}] and d["openai"]["use"] == "off"
    gui.api("POST", "/api/aiguard/settings", {"providers": {"anthropic": {"use": "off"},
                                                            "openai": {"use": "customer", "cred": 802}}}, {})
    s = ag.proxy_setup(__import__("povkit.core.pov", fromlist=["Pov"]).Pov(pov_all.id))
    assert s["openai"]["use"] == "customer" and s["openai"]["cred"] == 802 and s["anthropic"]["use"] == "off"
    gui.api("POST", "/api/aiguard/provider-key", {"key": "sk-openai-" + "y" * 30, "provider": "openai"}, {})
    assert secrets.get(pov_all.id, "aiguard-provider-key-openai").startswith("sk-openai")


def test_an_approved_single_provider_plan_stays_approved(pov_all, tenant_for, monkeypatch):
    """A POV set up before both providers were offered keeps the same change list (no re-approval after updating)."""
    import json
    from povkit.core.changelist import digest
    pov_all.cfg["aiguard"] = {"proxy": "customer", "provider": "anthropic"}
    pov_all.save()
    items, *_ = lifecycle.plan(pov_all, tenant_for)
    px = [i for i in items if i["key"] in ("aiguard.proxy_key", "aiguard.proxy_rule")]
    assert px[0]["why"].startswith("A proxy key for the POV app on the customer's anthropic key")
    assert px[1]["why"] == "Sends the POV's proxy traffic to the POV policy, after the customer's rules."
    assert json.loads(json.dumps(px))   # serializable
    assert digest(items)
