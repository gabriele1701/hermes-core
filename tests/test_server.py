"""Test del server MCP e del caricamento della configurazione (M0 passo 6b).

Oltre al funzionamento, i test fissano tre proprietà di sicurezza della
superficie esposta: nessuna funzione restituisce segreti, nessuna accetta
l'identità dell'agente, nessuna accetta una conferma.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from mcp_server.audit import LogAction
from mcp_server.config import ConfigError, load_config
from mcp_server.contracts import CallOutcome, OwnerAgent, RiskTier
from mcp_server.executor import sha256_file
from mcp_server.server import HermesServer, crea_server, main

SCRIPT = "agents/echo_agent/run.py"
SORGENTE = "print('{\"ok\": true}')\n"
SHA_FINTO = "0" * 64


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "agents" / "echo_agent").mkdir(parents=True)
    (tmp_path / SCRIPT).write_text(SORGENTE, encoding="utf-8")
    (tmp_path / "config").mkdir()
    return tmp_path


def scrivi_config(
    repo: Path,
    *,
    agent: str = "echo_dummy",
    tier: str = "verde",
    personal_data: bool = False,
    requires_container: bool = False,
    sha: str | None = None,
    extra_tool: str = "",
    sezioni_extra: str = "",
) -> Path:
    sha = sha if sha is not None else sha256_file(repo / SCRIPT)
    testo = textwrap.dedent(f"""\
        [server]
        agent = "{agent}"
        repo_root = ".."
        log_path = "../logs/audit.jsonl"
        container_available = false

        [vault]
        backend = "stub"
        stub_secrets = ["ssh/lab-kali"]

        [[tool]]
        tool_id = "echo.ping"
        owner_agent = "{agent}"
        default_tier = "{tier}"
        personal_data = {str(personal_data).lower()}
        requires_container = {str(requires_container).lower()}
        exec_path = "{SCRIPT}"
        exec_sha256 = "{sha}"
        description = "Agente dummy."
        """) + extra_tool + sezioni_extra
    percorso = repo / "config" / "hermes.toml"
    percorso.write_text(testo, encoding="utf-8")
    return percorso


@pytest.fixture()
def server(repo: Path) -> HermesServer:
    return crea_server(scrivi_config(repo))


# --------------------------------------------------------------------------- #
# Configurazione
# --------------------------------------------------------------------------- #


def test_config_caricata(repo: Path):
    cfg = load_config(scrivi_config(repo))
    assert cfg.agent is OwnerAgent.ECHO_DUMMY
    assert cfg.repo_root == repo.resolve()
    assert cfg.container_available is False
    assert cfg.vault.backend == "stub"
    assert cfg.vault.stub_secrets == ("ssh/lab-kali",)
    assert len(cfg.tools) == 1


def test_config_assente(tmp_path: Path):
    with pytest.raises(ConfigError, match="assente"):
        load_config(tmp_path / "mai-esistita.toml")


def test_config_malformata(repo: Path):
    percorso = repo / "config" / "rotta.toml"
    percorso.write_text("[server\nagent =", encoding="utf-8")
    with pytest.raises(ConfigError, match="malformata"):
        load_config(percorso)


def test_sezione_server_obbligatoria(repo: Path):
    percorso = repo / "config" / "vuota.toml"
    percorso.write_text("[vault]\nbackend = \"stub\"\n", encoding="utf-8")
    with pytest.raises(ConfigError, match=r"\[server\] assente"):
        load_config(percorso)


def test_agente_obbligatorio(repo: Path):
    percorso = repo / "config" / "senza-agente.toml"
    percorso.write_text('[server]\nrepo_root = ".."\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="agent"):
        load_config(percorso)


def test_agente_inesistente_rifiutato(repo: Path):
    """Un agente non riconosciuto non può diventare un default."""
    with pytest.raises(ConfigError, match="non riconosciuto"):
        load_config(scrivi_config(repo, agent="agente_inventato"))


def test_sezione_ignota_rifiutata(repo: Path):
    """Un refuso in una config di sicurezza è un controllo che credi di avere."""
    with pytest.raises(ConfigError, match="non riconosciute"):
        load_config(
            scrivi_config(repo, sezioni_extra='\n[sicurezza]\ndisattiva = true\n')
        )


def test_chiave_ignota_in_server_rifiutata(repo: Path):
    percorso = repo / "config" / "chiave.toml"
    percorso.write_text(
        f'[server]\nagent = "echo_dummy"\nrepo_root = "{repo}"\nskip_checks = true\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="skip_checks"):
        load_config(percorso)


def test_repo_root_inesistente_rifiutato(repo: Path):
    percorso = repo / "config" / "radice.toml"
    percorso.write_text(
        '[server]\nagent = "echo_dummy"\nrepo_root = "./non-esiste"\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="non è una directory"):
        load_config(percorso)


def test_container_available_deve_essere_booleano(repo: Path):
    percorso = repo / "config" / "bool.toml"
    percorso.write_text(
        f'[server]\nagent = "echo_dummy"\nrepo_root = "{repo}"\n'
        'container_available = "si"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="booleano"):
        load_config(percorso)


def test_interprete_default_assoluto_e_isolato(repo: Path):
    cfg = load_config(scrivi_config(repo))
    assert cfg.tool_python.is_absolute()
    assert cfg.tool_python == Path("/usr/bin/python3")
    assert cfg.tool_python_flags == ("-I", "-S")


def test_interprete_relativo_rifiutato(repo: Path):
    """Un nome risolto dal PATH non è deterministico: va rifiutato all'avvio."""
    percorso = scrivi_config(repo, sezioni_extra='\n')
    testo = percorso.read_text(encoding="utf-8").replace(
        'container_available = false',
        'container_available = false\ntool_python = "python3"',
    )
    percorso.write_text(testo, encoding="utf-8")
    with pytest.raises(ConfigError, match="assoluto"):
        load_config(percorso)


def test_interprete_inesistente_rifiutato(repo: Path):
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        'container_available = false',
        'container_available = false\ntool_python = "/usr/bin/python-inesistente"',
    )
    percorso.write_text(testo, encoding="utf-8")
    with pytest.raises(ConfigError, match="non esiste"):
        load_config(percorso)


def test_interprete_non_eseguibile_rifiutato(repo: Path, tmp_path: Path):
    finto = tmp_path / "python-finto"
    finto.write_text("#!/bin/sh\n", encoding="utf-8")
    finto.chmod(0o644)
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        'container_available = false',
        f'container_available = false\ntool_python = "{finto}"',
    )
    percorso.write_text(testo, encoding="utf-8")
    with pytest.raises(ConfigError, match="non è eseguibile"):
        load_config(percorso)


def test_flag_interprete_configurabili(repo: Path):
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        'container_available = false',
        'container_available = false\ntool_python_flags = ["-I"]',
    )
    percorso.write_text(testo, encoding="utf-8")
    assert load_config(percorso).tool_python_flags == ("-I",)


@pytest.mark.parametrize(
    "guasto",
    ['tool_python_flags = "-I"', 'tool_python_flags = ["/etc/passwd"]',
     'tool_python_flags = ["-I", 42]'],
)
def test_flag_interprete_malformati_rifiutati(repo: Path, guasto: str):
    """I flag accettano solo opzioni, non percorsi o argomenti."""
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        'container_available = false', f'container_available = false\n{guasto}'
    )
    percorso.write_text(testo, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(percorso)


def test_limiti_di_default(repo: Path):
    cfg = load_config(scrivi_config(repo))
    assert cfg.max_output_bytes == 1024 * 1024
    assert cfg.max_concurrent_tools == 2


def test_limiti_configurabili(repo: Path):
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        "container_available = false\nmax_output_bytes = 4096\n"
        "max_concurrent_tools = 5",
    )
    percorso.write_text(testo, encoding="utf-8")
    cfg = load_config(percorso)
    assert cfg.max_output_bytes == 4096
    assert cfg.max_concurrent_tools == 5


@pytest.mark.parametrize(
    "guasto",
    [
        "max_output_bytes = 0",
        "max_output_bytes = -1",
        "max_output_bytes = 10",
        "max_concurrent_tools = 0",
        "max_concurrent_tools = -3",
        'max_output_bytes = "molti"',
        "max_concurrent_tools = true",
    ],
)
def test_limiti_che_disattiverebbero_il_tetto_rifiutati(repo: Path, guasto: str):
    """Zero non è «nessun limite»: è un limite scritto male.

    Trattarlo come illimitato trasformerebbe un refuso nella rimozione di un
    controllo.
    """
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false", f"container_available = false\n{guasto}"
    )
    percorso.write_text(testo, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(percorso)


def test_server_propaga_i_limiti(repo: Path):
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        "container_available = false\nmax_output_bytes = 8192\n"
        "max_concurrent_tools = 1",
    )
    percorso.write_text(testo, encoding="utf-8")
    srv = crea_server(percorso)
    assert srv._executor.max_output_bytes == 8192
    assert srv._executor.max_concurrent == 1


def test_truncated_nella_risposta(repo: Path):
    """Il modello deve poter sapere che sta leggendo un output tagliato."""
    (repo / SCRIPT).write_text(
        "import sys\nsys.stdout.write('A' * 20000)\n", encoding="utf-8"
    )
    percorso = scrivi_config(repo)
    testo = percorso.read_text(encoding="utf-8").replace(
        "container_available = false",
        "container_available = false\nmax_output_bytes = 2048",
    )
    percorso.write_text(testo, encoding="utf-8")

    r = crea_server(percorso)._invoke_tool("echo.ping")
    assert r["output"]["truncated"] is True
    assert len(r["output"]["stdout"]) == 2048


def test_server_usa_l_interprete_della_config(repo: Path):
    srv = crea_server(scrivi_config(repo))
    assert srv._executor.tool_python == Path("/usr/bin/python3")
    assert srv._executor.tool_python_flags == ("-I", "-S")


def test_backend_vault_sconosciuto_fa_fallire_avvio(repo: Path):
    """Credere di avere credenziali reali e averne di finte è un guasto silenzioso."""
    cfg = scrivi_config(repo, sezioni_extra="")
    testo = cfg.read_text(encoding="utf-8").replace(
        'backend = "stub"', 'backend = "pass"'
    )
    cfg.write_text(testo, encoding="utf-8")
    with pytest.raises(NotImplementedError, match="non collegato"):
        crea_server(cfg)


def test_tool_non_conforme_fa_fallire_avvio(repo: Path):
    """Un registro caricato a metà farebbe credere di avere tool che non ci sono."""
    cfg = scrivi_config(repo)
    testo = cfg.read_text(encoding="utf-8").replace(
        'default_tier = "verde"\n', ""
    )
    cfg.write_text(testo, encoding="utf-8")
    from mcp_server.registry import ToolSpecRejected

    with pytest.raises(ToolSpecRejected):
        crea_server(cfg)


def test_rifiuto_di_avvio_resta_nel_log(repo: Path):
    cfg = scrivi_config(repo)
    testo = cfg.read_text(encoding="utf-8").replace('default_tier = "verde"\n', "")
    cfg.write_text(testo, encoding="utf-8")
    from mcp_server.registry import ToolSpecRejected

    with pytest.raises(ToolSpecRejected):
        crea_server(cfg)
    righe = (repo / "logs" / "audit.jsonl").read_text(encoding="utf-8")
    assert "tool_registration_rejected" in righe


# --------------------------------------------------------------------------- #
# Superficie esposta
# --------------------------------------------------------------------------- #


@pytest.mark.anyio
async def test_funzioni_esposte(server: HermesServer):
    nomi = {t.name for t in await server.mcp.list_tools()}
    assert nomi == {
        "list_available_tools",
        "describe_tool",
        "invoke_tool",
        "raise_tool_tier",
    }


@pytest.mark.anyio
async def test_nessuna_funzione_espone_segreti(server: HermesServer):
    """Il vault non è raggiungibile dal client: i segreti si usano, non si danno."""
    for t in await server.mcp.list_tools():
        assert "secret" not in t.name.lower()
        assert "vault" not in t.name.lower()
        assert "credential" not in t.name.lower()


@pytest.mark.anyio
async def test_nessuna_funzione_accetta_identita_agente(server: HermesServer):
    """Un parametro 'agent' renderebbe decorativo il confine fra agenti."""
    for t in await server.mcp.list_tools():
        parametri = set((t.input_schema or {}).get("properties", {}))
        assert "agent" not in parametri
        assert "owner_agent" not in parametri


@pytest.mark.anyio
async def test_nessuna_funzione_accetta_conferma(server: HermesServer):
    """Una conferma fornita dal chiamante è un'autorizzazione a se stesso."""
    for t in await server.mcp.list_tools():
        parametri = set((t.input_schema or {}).get("properties", {}))
        assert "confirmed" not in parametri
        assert "authorized" not in parametri


def test_vault_resta_accessibile_internamente(server: HermesServer):
    """Non esposto non significa non collegato."""
    assert server.vault.e_stub is True
    assert server.vault.get_secret("ssh/lab-kali").reveal().startswith("STUB-NON-REALE:")


# --------------------------------------------------------------------------- #
# Elenco e descrizione
# --------------------------------------------------------------------------- #


def test_elenco_tool(server: HermesServer):
    risposta = server._list_available_tools()
    assert risposta["agent"] == "echo_dummy"
    assert risposta["vault_is_stub"] is True
    assert risposta["container_available"] is False
    assert [t["tool_id"] for t in risposta["tools"]] == ["echo.ping"]

    tool = risposta["tools"][0]
    assert tool["declared_tier"] == "verde"
    assert tool["effective_tier"] == "verde"
    assert tool["confirmation"]["required"] is False
    assert tool["executable_now"] is True


def test_elenco_filtrato_sull_agente(repo: Path):
    """Un agente non ha bisogno di sapere i tool degli altri."""
    altro = textwrap.dedent(f"""
        [[tool]]
        tool_id = "kali.scan"
        owner_agent = "pentest_kali"
        default_tier = "rosso"
        personal_data = false
        requires_container = true
        exec_path = "{SCRIPT}"
        exec_sha256 = "{sha256_file(repo / SCRIPT)}"
        description = "Tool di un altro agente."
        """)
    srv = crea_server(scrivi_config(repo, extra_tool=altro))
    assert len(srv.registry) == 2
    elencati = [t["tool_id"] for t in srv._list_available_tools()["tools"]]
    assert elencati == ["echo.ping"]


def test_descrizione_tool(server: HermesServer):
    d = server._describe_tool("echo.ping")
    assert d["unattended_safe"] is True
    assert d["shares_script_with"] == []


def test_descrizione_tool_di_altro_agente_come_inesistente(repo: Path):
    altro = textwrap.dedent(f"""
        [[tool]]
        tool_id = "kali.scan"
        owner_agent = "pentest_kali"
        default_tier = "rosso"
        personal_data = false
        requires_container = false
        exec_path = "{SCRIPT}"
        exec_sha256 = "{sha256_file(repo / SCRIPT)}"
        description = "Tool di un altro agente."
        """)
    srv = crea_server(scrivi_config(repo, extra_tool=altro))
    from mcp_server.registry import ToolNotRegistered

    with pytest.raises(ToolNotRegistered):
        srv._describe_tool("kali.scan")


# --------------------------------------------------------------------------- #
# Invocazione
# --------------------------------------------------------------------------- #


def test_invocazione_riuscita(server: HermesServer):
    r = server._invoke_tool("echo.ping")
    assert r["result"]["status"] == "ok"
    assert r["output"]["returncode"] == 0
    assert len(r["result"]["tool_calls"]) == 1
    assert r["result"]["tool_calls"][0]["authorized_by"] == "policy"


def test_invocazione_tracciata_sotto_un_correlation_id(server: HermesServer):
    r = server._invoke_tool("echo.ping", target="lab-kali")
    cid = r["result"]["correlation_id"]
    righe = [x for x in server.audit.read_all() if str(x.correlation_id) == cid]
    azioni = [x.action for x in righe]
    assert LogAction.AGENT_INVOKED in azioni
    assert LogAction.TOOL_CALL in azioni
    assert LogAction.AGENT_RESULT in azioni


def test_tool_call_non_duplicata_nel_log(server: HermesServer):
    """Riscrivere le righe già scritte dal gate renderebbe il log ambiguo."""
    r = server._invoke_tool("echo.ping")
    cid = r["result"]["correlation_id"]
    chiamate = [
        x
        for x in server.audit.read_all()
        if str(x.correlation_id) == cid and x.action is LogAction.TOOL_CALL
    ]
    assert len(chiamate) == 1


@pytest.mark.parametrize("tier", ["giallo", "rosso"])
def test_tool_che_richiede_conferma_non_viene_eseguito(repo: Path, tier: str):
    """Fail-closed: sospeso, non eseguito, e il client non può autorizzarsi."""
    srv = crea_server(scrivi_config(repo, tier=tier))
    r = srv._invoke_tool("echo.ping")
    assert r["result"]["status"] == "needs_confirmation"
    assert r["result"]["tool_calls"][0]["outcome"] == "pending"
    assert r["result"]["tool_calls"][0]["authorized_by"] == "none"
    assert r["output"] is None


def test_dati_personali_sospendono_anche_su_verde(repo: Path):
    srv = crea_server(scrivi_config(repo, personal_data=True))
    assert srv._invoke_tool("echo.ping")["result"]["status"] == "needs_confirmation"


def test_integrita_fallita_nega(repo: Path):
    srv = crea_server(scrivi_config(repo, sha=SHA_FINTO))
    r = srv._invoke_tool("echo.ping")
    assert r["result"]["status"] == "error"
    assert r["result"]["tool_calls"][0]["outcome"] == "denied"


def test_container_assente_nega(repo: Path):
    srv = crea_server(scrivi_config(repo, requires_container=True))
    r = srv._invoke_tool("echo.ping")
    assert r["result"]["status"] == "error"
    assert r["result"]["tool_calls"][0]["outcome"] == "denied"
    assert "container" in r["result"]["summary"]


def test_eccezione_inattesa_diventa_risultato_tracciato(
    server: HermesServer, monkeypatch
):
    """Nessuna eccezione deve risalire al framework MCP.

    Un'eccezione che risalisse lascerebbe nel log un `agent_invoked` orfano, e
    chi lo legge concluderebbe che non è stato eseguito nulla — mentre il tool
    potrebbe aver già agito.
    """

    def esplode(*args, **kwargs):
        raise RuntimeError("guasto inatteso")

    monkeypatch.setattr(server._executor, "execute", esplode)

    r = server._invoke_tool("echo.ping")
    assert r["result"]["status"] == "error"
    assert "RuntimeError" in r["result"]["summary"]

    azioni = [x.action for x in server.audit.read_all()]
    assert LogAction.AGENT_INVOKED in azioni
    assert LogAction.AGENT_RESULT in azioni, "la catena non resta orfana"


def test_output_non_utf8_attraverso_il_server(repo: Path):
    """Il caso del security review, lungo tutto il percorso del server."""
    (repo / SCRIPT).write_text(
        "import sys\nsys.stdout.buffer.write(b'banner \\xff\\xfe')\n", encoding="utf-8"
    )
    srv = crea_server(scrivi_config(repo))

    r = srv._invoke_tool("echo.ping")
    assert r["result"]["status"] == "ok"
    assert "�" in r["output"]["stdout"]

    cid = r["result"]["correlation_id"]
    azioni = [
        x.action for x in srv.audit.read_all() if str(x.correlation_id) == cid
    ]
    assert LogAction.TOOL_CALL in azioni
    assert LogAction.AGENT_RESULT in azioni


def test_tool_inesistente_errore_strutturato(server: HermesServer):
    r = server._invoke_tool("mai.registrato")
    assert r["result"]["status"] == "error"
    assert r["result"]["tool_calls"] == []


def test_tool_di_altro_agente_non_invocabile(repo: Path):
    altro = textwrap.dedent(f"""
        [[tool]]
        tool_id = "kali.scan"
        owner_agent = "pentest_kali"
        default_tier = "verde"
        personal_data = false
        requires_container = false
        exec_path = "{SCRIPT}"
        exec_sha256 = "{sha256_file(repo / SCRIPT)}"
        description = "Tool di un altro agente."
        """)
    srv = crea_server(scrivi_config(repo, extra_tool=altro))
    assert srv._invoke_tool("kali.scan")["result"]["status"] == "error"


@pytest.mark.anyio
async def test_invocazione_attraverso_il_protocollo(server: HermesServer):
    """Il percorso reale: chiamata via call_tool, come farebbe Hermes."""
    esito = await server.mcp.call_tool("invoke_tool", {"tool_id": "echo.ping"})
    assert esito.structured_content is not None
    assert esito.structured_content["result"]["status"] == "ok"


@pytest.mark.anyio
async def test_elenco_attraverso_il_protocollo(server: HermesServer):
    esito = await server.mcp.call_tool("list_available_tools", {})
    assert esito.structured_content["tools"][0]["tool_id"] == "echo.ping"


# --------------------------------------------------------------------------- #
# Override via protocollo
# --------------------------------------------------------------------------- #


def test_innalzamento_tier(server: HermesServer):
    r = server._raise_tool_tier("echo.ping", "rosso")
    assert r == {
        "ok": True,
        "tool_id": "echo.ping",
        "effective_tier": "rosso",
        "declared_tier": "verde",
    }
    assert server.registry.effective_tier("echo.ping") is RiskTier.ROSSO


def test_innalzamento_attribuito_all_istanza(server: HermesServer):
    """Il server passa la propria identità: l'audit dice chi ha alzato il tier."""
    server._raise_tool_tier("echo.ping", "rosso")
    riga = [
        r for r in server.audit.read_all() if r.action is LogAction.OVERRIDE_SET
    ][0]
    assert riga.agent is OwnerAgent.ECHO_DUMMY


def test_declassamento_rifiutato_attribuito(server: HermesServer):
    server._raise_tool_tier("echo.ping", "rosso")
    server._raise_tool_tier("echo.ping", "verde")
    riga = [
        r for r in server.audit.read_all() if r.action is LogAction.OVERRIDE_REJECTED
    ][0]
    assert riga.agent is OwnerAgent.ECHO_DUMMY


def test_innalzamento_rende_il_tool_non_eseguibile(server: HermesServer):
    server._raise_tool_tier("echo.ping", "rosso")
    assert server._invoke_tool("echo.ping")["result"]["status"] == "needs_confirmation"


def test_declassamento_rifiutato_via_protocollo(server: HermesServer):
    server._raise_tool_tier("echo.ping", "rosso")
    r = server._raise_tool_tier("echo.ping", "verde")
    assert r["ok"] is False
    assert "abbassare" in r["error"]
    assert server.registry.effective_tier("echo.ping") is RiskTier.ROSSO


def test_tier_inventato_rifiutato(server: HermesServer):
    r = server._raise_tool_tier("echo.ping", "arancione")
    assert r["ok"] is False
    assert "non valido" in r["error"]


def test_innalzamento_su_tool_di_altro_agente_rifiutato(repo: Path):
    altro = textwrap.dedent(f"""
        [[tool]]
        tool_id = "kali.scan"
        owner_agent = "pentest_kali"
        default_tier = "verde"
        personal_data = false
        requires_container = false
        exec_path = "{SCRIPT}"
        exec_sha256 = "{sha256_file(repo / SCRIPT)}"
        description = "Tool di un altro agente."
        """)
    srv = crea_server(scrivi_config(repo, extra_tool=altro))
    assert srv._raise_tool_tier("kali.scan", "rosso")["ok"] is False


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #


def test_entrypoint_avvia_su_stdio(repo: Path, monkeypatch):
    """main() costruisce il server e avvia il trasporto stdio."""
    avvii: list[str] = []
    monkeypatch.setattr(
        "mcp.server.mcpserver.MCPServer.run",
        lambda self, transport="stdio", **kw: avvii.append(transport),
    )
    assert main([str(scrivi_config(repo))]) == 0
    assert avvii == ["stdio"]


def test_config_esempio_valida_come_toml():
    """Il file d'esempio versionato deve almeno essere TOML valido."""
    import tomllib

    with open("config/hermes.example.toml", "rb") as fh:
        dati = tomllib.load(fh)
    assert dati["server"]["agent"] == "echo_dummy"
    assert dati["tool"][0]["tool_id"] == "echo.ping"
