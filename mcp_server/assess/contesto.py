"""Il contesto di un giro: chi siamo, cosa dice la configurazione, dove gira.

La configurazione si carica con il caricatore del server, non con uno
proprio: due caricatori dello stesso file sono due configurazioni.
"""

from __future__ import annotations

import os
import platform
import pwd
import shutil
import subprocess
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp_server.config import ServerConfig, load_config
from mcp_server.doctor import UTENTE_TOOL, _utente_di_servizio

#: La radice del repo da cui gira hermes-assess.
RADICE = Path(__file__).resolve().parent.parent.parent

SETPRIV = Path("/usr/bin/setpriv")


@dataclass(frozen=True, slots=True)
class Contesto:
    config_path: Path
    cfg: ServerConfig
    repo: Path
    #: Chi esegue davvero il server, dedotto come lo deduce il preflight.
    #: ``None`` se non si riesce a dedurlo.
    utente_servizio: str | None
    utente_tool: str
    root: bool

    def tool(self, tool_id: str) -> Mapping[str, Any] | None:
        """La registrazione di un tool **di questa istanza**, se c'è."""
        for voce in self.cfg.tools:
            if voce.get("tool_id") == tool_id and voce.get("owner_agent") == str(
                self.cfg.agent
            ):
                return voce
        return None

    @property
    def scende_di_identita(self) -> bool:
        """Se le prove possono girare sotto un'identità diversa da quella
        corrente: serve root, e un utente di servizio che non sia root."""
        return (
            self.root
            and self.utente_servizio is not None
            and self.utente_servizio != "root"
        )

    def come_servizio(self, argv: list[str]) -> list[str]:
        """``argv`` eseguito come l'utente di servizio, se si può scendere.

        Senza ``--no-new-privs``: il server deve poter chiamare ``sudo`` per
        il wrapper, e con quel bit sudo rifiuterebbe. Le sonde lo mettono.
        """
        if not self.scende_di_identita:
            return list(argv)
        return come_utente(self.utente_servizio or "", argv, nnp=False)

    def comando_server(self) -> list[str]:
        """Il server lanciato come lo lancia Hermes: dal lanciatore del repo,
        come l'utente di servizio. Fuori da root, nel processo corrente."""
        if self.scende_di_identita:
            return self.come_servizio(
                [str(self.repo / "bin" / "hermes-core-server"), str(self.config_path)]
            )
        return [sys.executable, "-m", "mcp_server.server", str(self.config_path)]


def come_utente(utente: str, argv: list[str], *, nnp: bool = True) -> list[str]:
    """``argv`` preceduto da ``setpriv`` per girare come ``utente``.

    ``--reset-env`` toglie l'ambiente di root; ``--init-groups`` dà i gruppi
    supplementari veri dell'utente, senza i quali una prova sottovaluterebbe
    ciò che quell'identità può fare. Il gruppo primario si legge dal database
    degli utenti: presumere che si chiami come l'utente è vero spesso, e
    falso proprio quando qualcuno ha preparato la macchina a mano.

    Solleva ``KeyError`` se l'utente non esiste.
    """
    voce = pwd.getpwnam(utente)
    return [
        str(SETPRIV),
        f"--reuid={voce.pw_uid}",
        f"--regid={voce.pw_gid}",
        "--init-groups",
        "--reset-env",
        *(["--no-new-privs"] if nnp else []),
        "--",
        *argv,
    ]


def stato_del_repo(repo: Path) -> tuple[str, bool]:
    """``(commit, albero_pulito)``. Se git non risponde: ``("sconosciuto", False)``.

    ``safe.directory`` perché da root il repo è di un altro utente, e git si
    rifiuterebbe di leggerlo: un commit «sconosciuto» per quella ragione
    sarebbe una causa falsa.
    """
    git = shutil.which("git")
    if git is None:
        return "sconosciuto", False
    base = [git, "-c", f"safe.directory={repo}", "-C", str(repo)]
    try:
        commit = subprocess.run(
            [*base, "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
        sporco = subprocess.run(
            [*base, "status", "--porcelain"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return "sconosciuto", False
    return commit, not sporco


def costruisci(config_path: str | Path) -> Contesto:
    """Solleva :class:`~mcp_server.config.ConfigError` se la config non si carica."""
    percorso = Path(config_path).resolve()
    cfg = load_config(percorso)
    return Contesto(
        config_path=percorso,
        cfg=cfg,
        repo=RADICE,
        utente_servizio=_utente_di_servizio(cfg),
        utente_tool=UTENTE_TOOL,
        root=os.geteuid() == 0,
    )


def host() -> str:
    return platform.node() or "sconosciuto"


__all__ = ["RADICE", "Contesto", "come_utente", "costruisci", "host", "stato_del_repo"]
