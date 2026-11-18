"""AS-03 — un tool raggiunge i file del servizio.

Le sonde partono dal wrapper installato, nell'unità **normale**: è quella
con meno restrizioni in cui un tool può girare, quindi la più severa da
mettere alla prova. Il percorso dei file arriva da hermes-assess, che ha
letto la configurazione da root; il canary non potrebbe saperlo senza
leggerla, cioè senza fare ciò che la prova deve dimostrare impossibile.

Per ogni file, prima il controllo positivo: la stessa operazione come utente
di servizio, che **deve** riuscire.
"""

from __future__ import annotations

from pathlib import Path

from mcp_server.assess import sonde
from mcp_server.assess.contesto import Contesto
from mcp_server.assess.prove import Prova, Risultato, da_evidenze
from mcp_server.overrides import NOME_FILE as NOME_FILE_OVERRIDE


def bersagli(ctx: Contesto) -> list[tuple[str, Path]]:
    """``(operazione, percorso)`` da tentare. Solo ciò che esiste."""
    cfg = ctx.cfg
    elenco: list[tuple[str, Path]] = [
        ("leggi", ctx.config_path),
        ("apri_scrittura", cfg.log_path),
    ]
    if cfg.state_dir is not None:
        elenco.append(("crea", cfg.state_dir))
        elenco.append(("leggi", cfg.state_dir / NOME_FILE_OVERRIDE))
    return [(op, p) for op, p in elenco if p.exists()]


def applicabile(ctx: Contesto) -> str | None:
    if ctx.cfg.tool_runner is None:
        return "server.tool_runner non configurato: i tool girano come il servizio"
    if not ctx.scende_di_identita:
        return "richiede root e un utente di servizio deducibile"
    return None


def esegui(
    ctx: Contesto,
    *,
    come=sonde.come,
    dal_wrapper=sonde.dal_wrapper,
) -> Risultato:
    positivi, negativi = [], []
    for operazione, percorso in bersagli(ctx):
        positivi.append(
            come(ctx, ctx.utente_servizio, operazione, percorso, controllo_positivo=True)
        )
        negativi.append(dal_wrapper(ctx, operazione, percorso))
    nota = ""
    if ctx.cfg.vault.backend == "stub":
        nota = "vault stub: nessun segreto su disco da proteggere"
    return da_evidenze(positivi, negativi, nota=nota)


PROVA = Prova(id="AS-03", applicabile=applicabile, esegui=esegui)
