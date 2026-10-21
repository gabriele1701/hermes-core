"""Test fumo del passo 0: l'ambiente è montato e le dipendenze importabili.

Non testa logica di dominio (arriva dai passi successivi), solo che lo
scaffolding regga: package importabili e dipendenze presenti nel venv.
"""


def test_dipendenze_importabili():
    import mcp  # noqa: F401
    import pydantic  # noqa: F401


def test_package_importabili():
    import agents  # noqa: F401
    import mcp_server  # noqa: F401
    from agents import echo_agent, orchestrator  # noqa: F401
