import pytest

BYPASS_PROBES = {
    "english_keyword": "Rotate this password: Hunter2!",
    "french_mdp": "Voici le mot de passe root du serveur : Hunter2!",
    "french_cle": "Vérifie ma clé API Anthropic",
    "raw_anthropic_key": "Why does sk-ant-api03-AbCdEf123 return 401?",
    "raw_aws_key": "AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY fails",
    "private_key_block": "-----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNzaC1rZXk...",
    "zero_width": "My pass\u200bword is Hunter2!",
    "leet": "My p4ssw0rd is Hunter2!",
    "spaced": "p a s s w o r d = Hunter2!",
    "fullwidth": "My \uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44 is Hunter2!",
    "french_sante": "Résume le dossier santé de mon père: diabète type 2",
    "iban": "Pay FR76 3000 6000 0112 3456 7890 189 today",
    "synonym_passphrase": "The passphrase for the vault is correct-horse-battery",
    "jwt": "Decode eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc",
}


@pytest.mark.parametrize("task", BYPASS_PROBES.values(), ids=BYPASS_PROBES.keys())
async def test_bypass_probe_is_critical_and_local(make, task):
    o, _ = make()
    r = await o.call("route_task", {"task": task})
    assert r["data"]["privacy_level"] == "critical"
    assert r["data"]["primary_route"].startswith("local")


@pytest.mark.parametrize("task", [
    "Refactor my 2000-line ML pipeline for performance",
    "Write a blog post about surfing in winter",
    "What are the latest LLM releases?",
])
async def test_benign_task_stays_cloud_routable(make, task):
    o, _ = make()
    r = await o.call("route_task", {"task": task})
    assert r["data"]["primary_route"] == "claude_api"


async def test_custom_critical_keyword_from_config(make):
    o, _ = make({"privacy_keywords": {"critical": ["projet-atlas"]}})
    r = await o.call("route_task", {"task": "Summarise the projet-atlas acquisition memo"})
    assert r["data"]["privacy_level"] == "critical"


async def test_declared_privacy_can_only_raise(make):
    o, _ = make()
    raised = await o.call("route_task", {"task": "Write a haiku", "privacy": "critical"})
    lowered = await o.call("route_task", {"task": "my password is Hunter2!", "privacy": "low"})
    assert raised["data"]["privacy_level"] == "critical"
    assert lowered["data"]["privacy_level"] == "critical"
