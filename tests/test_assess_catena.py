"""hermes-assess lungo la catena vera: server su stdio, gate, canary, log.

Senza root e senza wrapper: AS-05 e AS-06 si applicano, AS-03 no, e il
referto deve dirlo. I canary sono quelli del repo, con lo SHA calcolato dal
file: lo stesso che il bootstrap scrive nella configurazione.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from mcp_server.executor import sha256_file

RADICE = Path(__file__).resolve().parent.parent
CANARY = RADICE / "agents" / "assess_canary" / "run.py"

BLOCCO_HOST = """
[[tool]]
tool_id = "assess.canary_host"
owner_agent = "echo_dummy"
default_tier = "verde"
personal_data = false
requires_container = false
exec_path = "agents/assess_canary/run.py"
exec_sha256 = "{sha}"
target_kind = "host"
exec_args = ["--bersaglio"]
description = "canary con bersaglio"
"""


def _config(tmp_path: Path, *, con_host: bool) -> Path:
    (tmp_path / "logs").mkdir()
    scope = tmp_path / "scope.toml"
    scope.write_text('reti = ["10.99.0.0/24"]\n\n[alias]\nlaboratorio = "10.99.0.5"\n')
    sha = sha256_file(CANARY)
    testo = textwrap.dedent(f"""\
        [server]
        agent = "echo_dummy"
        repo_root = "{RADICE}"
        log_path = "{tmp_path / 'logs' / 'audit.jsonl'}"
        scope_file = "{scope}"
        tool_python = "{sys.executable}"

        [vault]
        backend = "stub"

        [[tool]]
        tool_id = "assess.canary"
        owner_agent = "echo_dummy"
        default_tier = "verde"
        personal_data = false
        requires_container = false
        exec_path = "agents/assess_canary/run.py"
        exec_sha256 = "{sha}"
        description = "canary"
        """)
    if con_host:
        testo += BLOCCO_HOST.format(sha=sha)
    percorso = tmp_path / "hermes.toml"
    percorso.write_text(testo)
    return percorso


def _assess(config: Path, *argomenti: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "mcp_server.assess", str(config), "--json", *argomenti],
        capture_output=True, text=True, cwd=RADICE, timeout=180, check=False,
    )


@pytest.mark.slow
def test_il_giro_completo_tiene(tmp_path: Path):
    esito = _assess(_config(tmp_path, con_host=True), "--solo", "AS-03,AS-05,AS-06")
    assert esito.returncode == 0, esito.stderr
    voci = {v["minaccia"]: v for v in json.loads(esito.stdout)["voci"]}
    assert voci["AS-03"]["esito"] == "non_applicabile"
    assert voci["AS-05"]["esito"] == "tiene", voci["AS-05"]
    assert voci["AS-06"]["esito"] == "tiene", voci["AS-06"]


@pytest.mark.slow
def test_le_righe_sono_del_server_e_hermes_assess_non_ne_scrive(tmp_path: Path):
    config = _config(tmp_path, con_host=False)
    _assess(config, "--solo", "AS-05")
    righe = [json.loads(r) for r in (tmp_path / "logs" / "audit.jsonl").read_text().splitlines()]
    invocazioni = [r for r in righe if r["action"] == "agent_invoked"]
    assert len(invocazioni) == 1
    assert invocazioni[0]["agent"] == "echo_dummy"


@pytest.mark.slow
def test_senza_canary_host_il_perimetro_non_e_applicabile(tmp_path: Path):
    esito = _assess(_config(tmp_path, con_host=False), "--solo", "AS-06")
    voce = json.loads(esito.stdout)["voci"][0]
    assert voce["esito"] == "non_applicabile"
    assert "assess.canary_host" in voce["nota"]


def test_minacce_sconosciute_non_eseguono_niente(tmp_path: Path):
    esito = _assess(_config(tmp_path, con_host=False), "--solo", "AS-99")
    assert esito.returncode == 3
    assert "AS-99" in esito.stderr


def test_una_config_illeggibile_e_non_eseguito(tmp_path: Path):
    esito = _assess(tmp_path / "manca.toml")
    assert esito.returncode == 3


def test_il_lanciatore_senza_argomenti_non_esegue():
    esito = subprocess.run(
        [str(RADICE / "bin" / "hermes-assess")], capture_output=True, text=True, check=False
    )
    assert esito.returncode == 3
