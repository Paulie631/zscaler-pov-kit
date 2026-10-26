"""ZIA: 'If DENY_AI_ML_UPLOAD is specified, then ALLOW_AI_ML_WEB_USE must also be specified.' (seen live)"""
from povkit.core import KitError
from povkit.products import zia as Z


def test_upload_block_keeps_web_use():
    assert Z.with_companions("AI_ML", ["DENY_AI_ML_UPLOAD"]) == ["DENY_AI_ML_UPLOAD", "ALLOW_AI_ML_WEB_USE"]
    assert Z.with_companions("AI_ML", ["BLOCK_AI_ML_WEB_USE"]) == ["BLOCK_AI_ML_WEB_USE"]
    assert Z.with_companions("AI_ML", ["DENY_AI_ML_UPLOAD"], ["DENY_AI_ML_UPLOAD"]) == ["DENY_AI_ML_UPLOAD"]
    assert Z.with_companions("FILE_SHARE", ["BLOCK_FILE_SHARE_UPLOAD"]) == ["BLOCK_FILE_SHARE_UPLOAD"]


def test_apply_adds_the_action_zia_names(monkeypatch):
    sent = []

    class T:
        def create(self, key, res, method, *a, **body):
            sent.append(list(body["actions"]))
            if "ALLOW_AI_ML_WEB_USE" not in body["actions"]:
                raise KitError('cloudappcontrol.add_rule failed: {"status": 400, "message": "If DENY_AI_ML_UPLOAD is '
                               'specified, then ALLOW_AI_ML_WEB_USE must also be specified."}')
            return "77"
    monkeypatch.setattr(Z, "list_kind", lambda *a, **k: [])
    it = {"key": "zia.cac.uc01", "kind": "cloud_app_control", "rule_type": "AI_ML", "name": "POV ChatGPT no upload",
          "body": {"name": "POV ChatGPT no upload", "actions": ["DENY_AI_ML_UPLOAD"]}}
    assert Z.ZIA()._place(T(), it) == "77"
    assert sent == [["DENY_AI_ML_UPLOAD"], ["DENY_AI_ML_UPLOAD", "ALLOW_AI_ML_WEB_USE"]]
