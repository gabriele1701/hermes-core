"""Perimetro dei bersagli ammessi: l'allowlist di scope.

Il buco che questo modulo chiude
--------------------------------

Prima, l'argomento ``target`` di un'invocazione era una stringa libera scelta
dal modello: non validata, non confrontata con niente, e nemmeno passata allo
script — quindi inerte, ma pronta a diventare il bersaglio reale appena un tool
ne avesse avuto bisogno. Con i tool reali in arrivo è il punto più direttamente
sfruttabile da una prompt injection: un testo malevolo nel contesto di un
agente non deve poter spostare uno scan su una rete che non è del laboratorio.

Il perimetro vive **fuori** dalla portata del servizio: un file di root, non
``state_dir``, perché un tool compromesso che potesse riscrivere la propria
allowlist non avrebbe un'allowlist. È la stessa forma di HC-04 — una
restrizione custodita da chi la subisce non è una restrizione.

Perché qui non c'è DNS
----------------------

La tentazione è accettare hostname e risolverli al momento del controllo. Non
si fa, per tre motivi che si sommano:

* **Rebinding.** Fra la validazione e l'esecuzione il nome può risolvere a un
  altro indirizzo: si valida una cosa e se ne esegue un'altra. Chiudere la
  finestra richiederebbe di passare al tool l'IP risolto, e non tutti i tool
  possono lavorare su un IP.
* **Ambiguità.** Un nome può risolvere a più indirizzi. Quale si valida?
* **Dipendenza.** La risoluzione dipende da un servizio che non è nel
  perimetro. Un ``lab.local`` via mDNS può non risolvere affatto dal server.

Qui i nomi esistono, ma sono **alias dichiarati dall'operatore** nello stesso
file di root: una tabella, non un'interrogazione. Il nome diventa una comodità
definita da chi scrive la policy, non un'affermazione di un servizio esterno.
Un alias non si avvelena e non cambia sotto il controllo.

Il limite da sapere, perché nessun codice lo chiude: questo modulo valida
**l'argomento con cui il tool parte**, non dove va il traffico del processo
dopo l'avvio. L'applicazione effettiva del perimetro di rete sta a livello di
rete — regole di egress per l'utente che esegue i tool, cioè qualcosa che
diventa possibile con l'uid separato di A1.

Fail-closed, nei due casi che non vanno confusi
-----------------------------------------------

Vale l'invariante del 6b, con una differenza importante: qui il degrado
silenzioso sarebbe la rinuncia al controllo, quindi nessuno dei due casi
permette tutto.

* **Perimetro non configurato** → i tool che dichiarano un bersaglio non sono
  invocabili, e la cosa è dichiarata nel preflight e nel catalogo. È una
  configurazione che non promette un perimetro, e chi la legge lo sa.
* **Perimetro configurato e non caricabile** → il gate rifiuta. Il perimetro è
  promesso e non applicabile, e si eseguirebbe senza il confine che la
  configurazione dichiara, proprio quando qualcosa già non va.
"""

from __future__ import annotations

import ipaddress
import tomllib
from pathlib import Path

from mcp_server.contracts import TargetKind

#: Lunghezza massima di un bersaglio. Coincide con il campo ``target`` del
#: log: un bersaglio che non entra nella riga di audit non è registrabile, e
#: un'esecuzione non registrabile non si fa.
MAX_TARGET = 256

#: Lunghezza massima di un nome di alias.
MAX_ALIAS = 64


class ScopeError(Exception):
    """Il perimetro è configurato ma non si riesce a caricarlo."""


class TargetRefused(Exception):
    """Il bersaglio non è ammesso, o non ha la forma attesa."""


class ScopeAllowlist:
    """Reti ammesse e alias dichiarati, caricati da un file di root.

    Immutabile dopo il caricamento: il perimetro non si modifica a runtime, e
    non esiste un modo per ampliarlo dall'interno del processo.
    """

    __slots__ = ("_reti", "_alias", "_percorso")

    def __init__(
        self,
        reti: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
        alias: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address],
        percorso: Path | None = None,
    ) -> None:
        self._reti = reti
        self._alias = dict(alias)
        self._percorso = percorso

    # -- caricamento --------------------------------------------------------- #

    @classmethod
    def carica(cls, percorso: str | Path) -> ScopeAllowlist:
        """Legge il perimetro, o solleva :class:`ScopeError`.

        Non inghiotte nulla e non ha un ramo «vuoto va bene»: un perimetro
        assente, illeggibile, non parsabile o **vuoto** solleva. Un'allowlist
        vuota che ammettesse tutto sarebbe il guasto peggiore di questo
        modulo; un'allowlist vuota che non ammette niente sarebbe un blocco
        silenzioso che nessuno sa diagnosticare. Si solleva, e chi chiama
        decide cosa dire.
        """
        p = Path(percorso)
        try:
            dati = tomllib.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError as err:
            raise ScopeError(f"perimetro non trovato: {p}") from err
        except OSError as err:
            raise ScopeError(f"perimetro non leggibile: {p}: {err}") from err
        except tomllib.TOMLDecodeError as err:
            raise ScopeError(f"perimetro non parsabile: {p}: {err}") from err

        ignote = set(dati) - {"reti", "alias"}
        if ignote:
            raise ScopeError(
                f"{p}: chiavi non riconosciute: {', '.join(sorted(ignote))}. "
                f"Un perimetro con una chiave scritta male sarebbe un "
                f"perimetro diverso da quello che si crede di avere."
            )

        grezze = dati.get("reti", [])
        if not isinstance(grezze, list) or not all(isinstance(r, str) for r in grezze):
            raise ScopeError(f"{p}: 'reti' deve essere una lista di stringhe")

        reti = []
        for voce in grezze:
            try:
                # strict=False accetta 192.168.1.5/24 come la sua rete; qui si
                # pretende la forma canonica, perché un /24 scritto a partire
                # da un host è quasi sempre un errore di chi lo scrive, e un
                # perimetro più largo di quello inteso è il difetto che questo
                # file esiste per evitare.
                reti.append(ipaddress.ip_network(voce, strict=True))
            except ValueError as err:
                raise ScopeError(f"{p}: rete non valida {voce!r}: {err}") from err

        grezzi = dati.get("alias", {})
        if not isinstance(grezzi, dict):
            raise ScopeError(f"{p}: 'alias' deve essere una tabella nome = indirizzo")

        alias: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address] = {}
        for nome, valore in grezzi.items():
            if not isinstance(valore, str):
                raise ScopeError(f"{p}: l'alias {nome!r} deve essere una stringa")
            if len(nome) > MAX_ALIAS or not nome.replace("-", "").replace(
                ".", ""
            ).replace("_", "").isalnum():
                raise ScopeError(
                    f"{p}: nome di alias non valido {nome!r}: ammessi "
                    f"alfanumerici, '.', '-' e '_'"
                )
            try:
                indirizzo = ipaddress.ip_address(valore)
            except ValueError as err:
                raise ScopeError(
                    f"{p}: l'alias {nome!r} deve puntare a un indirizzo IP, "
                    f"non a un nome: gli alias sono la risoluzione, non un "
                    f"secondo livello da risolvere ({err})"
                ) from err
            alias[nome] = indirizzo

        if not reti and not alias:
            raise ScopeError(
                f"{p}: perimetro vuoto. Un perimetro vuoto non può voler dire "
                f"«tutto ammesso», e se volesse dire «niente ammesso» sarebbe "
                f"un blocco che nessuno riesce a diagnosticare: dichiarare "
                f"almeno una rete o un alias."
            )

        # Un alias fuori dalle reti ammesse è una contraddizione: il file
        # direbbe nello stesso momento che quell'indirizzo è raggiungibile e
        # che non lo è. Si rifiuta al caricamento, non all'invocazione, perché
        # è un errore di chi scrive la policy e non del modello.
        for nome, indirizzo in alias.items():
            if reti and not any(indirizzo in rete for rete in reti):
                raise ScopeError(
                    f"{p}: l'alias {nome!r} punta a {indirizzo}, che non sta "
                    f"in nessuna delle reti ammesse"
                )

        return cls(tuple(reti), alias, p)

    # -- interrogazione ------------------------------------------------------ #

    @property
    def percorso(self) -> Path | None:
        return self._percorso

    @property
    def reti(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return self._reti

    @property
    def alias(self) -> tuple[str, ...]:
        return tuple(sorted(self._alias))

    def __len__(self) -> int:
        return len(self._reti) + len(self._alias)

    def risolvi(self, target: str) -> str:
        """Bersaglio ammesso in forma canonica, o :class:`TargetRefused`.

        Restituisce l'indirizzo IP come stringa: è ciò che verrà passato al
        tool e ciò che finirà nel log. Un alias viene sostituito dal suo
        indirizzo, così il log dice **cosa è stato toccato** e non solo come
        lo ha chiamato il modello.
        """
        pulito = target.strip()
        if not pulito:
            raise TargetRefused("bersaglio vuoto")
        if len(pulito) > MAX_TARGET:
            raise TargetRefused(
                f"bersaglio più lungo di {MAX_TARGET} caratteri: non entrerebbe "
                f"nella riga di audit, e un'esecuzione non registrabile non si fa"
            )
        if pulito != target:
            raise TargetRefused(
                "il bersaglio ha spazi iniziali o finali: si rifiuta invece di "
                "normalizzarlo, perché normalizzare significa eseguire qualcosa "
                "di diverso da ciò che è stato chiesto"
            )
        # Un bersaglio che inizia per '-' verrebbe letto come FLAG dal tool,
        # non come bersaglio: è injection di argomenti, la sola forma che
        # sopravvive quando non c'è una shell. Il separatore '--' in argv la
        # impedisce già, ma un controllo che dipende da un solo meccanismo non
        # è un controllo.
        if pulito.startswith("-"):
            raise TargetRefused(
                f"il bersaglio {pulito!r} inizia per '-': sarebbe letto come "
                f"un'opzione del tool, non come un bersaglio"
            )
        if any(c.isspace() for c in pulito) or "\x00" in pulito:
            raise TargetRefused(
                "il bersaglio contiene spazi o byte nulli: un bersaglio è un "
                "solo indirizzo o un solo alias"
            )

        if pulito in self._alias:
            return str(self._alias[pulito])

        try:
            indirizzo = ipaddress.ip_address(pulito)
        except ValueError:
            raise TargetRefused(
                f"{pulito!r} non è un indirizzo IP né un alias dichiarato. "
                f"Il perimetro non interroga il DNS: usare un indirizzo, o "
                f"dichiarare un alias nel file di perimetro "
                f"({', '.join(self.alias) or 'nessun alias dichiarato'})."
            ) from None

        for rete in self._reti:
            if indirizzo in rete:
                return str(indirizzo)
        raise TargetRefused(
            f"{indirizzo} è fuori dal perimetro ammesso "
            f"({', '.join(str(r) for r in self._reti) or 'nessuna rete dichiarata'})"
        )


def valida_bersaglio(
    kind: TargetKind, target: str | None, allowlist: ScopeAllowlist | None
) -> str | None:
    """Bersaglio da passare al tool, o solleva :class:`TargetRefused`.

    Un solo punto per ogni ``TargetKind``, così la regola «nessun kind senza
    validatore» è verificabile leggendo una funzione invece di cercare dove
    ciascun valore viene gestito. Il ``match`` è esaustivo di proposito: un
    valore nuovo dell'enum senza il suo ramo fa fallire qui, visibilmente,
    invece di scivolare in un ramo permissivo.
    """
    match kind:
        case TargetKind.NONE:
            if target is not None:
                raise TargetRefused(
                    "questo tool non accetta un bersaglio: passarne uno è un "
                    "rifiuto e non un valore ignorato, perché un argomento "
                    "accettato e buttato via fa credere di aver limitato "
                    "qualcosa"
                )
            return None
        case TargetKind.HOST:
            if target is None:
                raise TargetRefused(
                    "questo tool richiede un bersaglio e non ne ha ricevuto uno"
                )
            if allowlist is None:
                raise TargetRefused(
                    "nessun perimetro configurato: un tool con bersaglio non è "
                    "invocabile finché server.scope_file non è configurato. "
                    "L'assenza di perimetro non vale come «tutto ammesso»"
                )
            return allowlist.risolvi(target)
    raise TargetRefused(  # pragma: no cover - rete di sicurezza sull'enum
        f"TargetKind {kind!r} non ha un validatore: nessun kind senza validatore"
    )


__all__ = [
    "MAX_TARGET",
    "ScopeAllowlist",
    "ScopeError",
    "TargetRefused",
    "valida_bersaglio",
]
