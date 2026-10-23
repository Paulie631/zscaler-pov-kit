"""Endpoint AI (draft): catalog, harmless probe test files, cleanup, and its place in a POV."""
import json

from povkit import evidence, lifecycle, probe, products


def test_catalog_is_marked_draft_and_needs_a_person(pov_all):
    cs = products.get("eai").criteria()
    assert {c["id"] for c in cs} == {f"EP-AIE-0{i}" for i in range(1, 6)}
    assert all(c["draft"] and ("attested" in c["proofs"]) for c in cs)   # the console is the proof, not the device


def test_probe_files_are_harmless_named_and_cleaned_up(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "AI_DIR", tmp_path / "zpov-ai-test")
    monkeypatch.setattr(probe, "SKILLS", tmp_path / ".claude" / "skills")
    paths = probe.ai_artifacts("r1")
    assert all("zpov-test-r1" in str(p) or p.name == ".mcp.json" for p in paths)
    assert paths[0].read_bytes()[:4] == b"GGUF"
    assert json.loads(paths[1].read_text())["mcpServers"]["zpov-test-r1"]["command"] == "echo"
    got, where = probe.ai_risky_skill("r1", 10, sleep=lambda s: None)
    assert got == "present" and not (tmp_path / ".claude/skills/zpov-risky-r1").exists()   # removed afterwards
    assert probe.cleanup_ai() == 2 and not (tmp_path / "zpov-ai-test").exists()


def test_a_removed_risky_skill_counts_as_blocked(tmp_path, monkeypatch):
    monkeypatch.setattr(probe, "SKILLS", tmp_path)

    def agent_removes(_):   # Endpoint AI quarantines the file
        for f in tmp_path.glob("zpov-risky-*/SKILL.md"):
            f.unlink()
    assert probe.ai_risky_skill("r2", 10, sleep=agent_removes)[0] == "blocked"


def test_local_prompt_without_ollama_is_reported(monkeypatch):
    class S:
        def get(self, *a, **k):
            raise ConnectionError("refused")
    assert probe.ai_local_prompt(S())[0] == "no local model"


def test_endpoint_ai_in_a_pov_needs_no_api(home, tenant, tenant_for):
    from povkit.core import pov as povs
    p = povs.new("Acme", ["zia", "eai"])
    p.cfg.update(vanity_domain="acme", pilot_group="POV Pilot")
    p.save()
    items, _, _, checks = lifecycle.plan(p, tenant_for)
    assert not [i for i in items if i["product"] == "eai"]
    assert any(c["id"] == "eai-later" for c in checks)
    assert {c["id"] for c in evidence.probe_pack(p)["criteria"]} >= {"EP-AIE-01", "EP-AIE-02", "EP-AIE-04"}
