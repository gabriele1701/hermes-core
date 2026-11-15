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

I bersagli di tipo percorso
---------------------------

Un tool che analizza un binario non punta a un host: punta a un file. Il suo
perimetro è una lista di **prefissi** (``percorsi``), e la domanda che per le
reti ha chiuso il DNS qui si chiama symlink: un percorso può dire una cosa e
portare altrove.

Qui la risoluzione si fa — a differenza dei nomi di host — perché non dipende
da un servizio esterno: la fa il kernel di questa macchina. Il gate risolve
il percorso richiesto, confronta il **risolto** con i prefissi, e al tool
passa il risolto. Ma fra il controllo e l'uso resta una finestra, perché un
symlink può essere sostituito dopo che è stato guardato. Per questo il gate
non è la sola difesa e nemmeno la principale: ``bin/hermes-tool-run`` avvia
il tool in un'unità il cui spazio dei nomi di mount contiene solo i prefissi
dichiarati. Lì un percorso fuori perimetro non esiste, e la finestra non ha
niente su cui aprirsi. La risoluzione qui resta come seconda rete, e per
scrivere nel log sia il percorso chiesto sia quello raggiunto.
"""

from __future__ import annotations

import ipaddress
import os
import re
import tomllib
from pathlib import Path

from mcp_server.contracts import TargetKind

#: Lunghezza massima di un bersaglio. Coincide con il campo ``target`` del
#: log: un bersaglio che non entra nella riga di audit non è registrabile, e
#: un'esecuzione non registrabile non si fa.
MAX_TARGET = 256

#: Lunghezza massima di un nome di alias.
MAX_ALIAS = 64


#: Caratteri ammessi in un prefisso di percorso. Stretto di proposito: un
#: prefisso finisce in una direttiva di systemd (``BindReadOnlyPaths=``), dove
#: lo spazio separa due percorsi e ``:`` separa sorgente e destinazione. Un
#: prefisso con uno di quei caratteri monterebbe qualcosa di diverso da ciò
#: che dichiara. Vale solo per i prefissi: il bersaglio richiesto viaggia in
#: argv e può contenere spazi.
_SEGMENTO_PREFISSO = re.compile(r"[A-Za-z0-9._-]+")


class ScopeError(Exception):
    """Il perimetro è configurato ma non si riesce a caricarlo."""


class TargetRefused(Exception):
    """Il bersaglio non è ammesso, o non ha la forma attesa."""


class ScopeAllowlist:
    """Reti, alias e prefissi di percorso ammessi, caricati da un file di root.

    Immutabile dopo il caricamento: il perimetro non si modifica a runtime, e
    non esiste un modo per ampliarlo dall'interno del processo.
    """

    __slots__ = ("_reti", "_alias", "_percorso", "_percorsi")

    def __init__(
        self,
        reti: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
        alias: dict[str, ipaddress.IPv4Address | ipaddress.IPv6Address],
        percorso: Path | None = None,
        *,
        percorsi: tuple[str, ...] = (),
    ) -> None:
        self._reti = reti
        self._alias = dict(alias)
        # Attenzione ai due nomi: ``percorso`` è il FILE da cui il perimetro è
        # stato letto, ``percorsi`` sono i prefissi che dichiara.
        self._percorso = percorso
        self._percorsi = tuple(percorsi)

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

        ignote = set(dati) - {"reti", "alias", "percorsi"}
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
                suggerimento = ""
                if nome == "percorsi":
                    # In TOML una chiave scritta DOPO l'intestazione [alias]
                    # appartiene a quella tabella. È l'errore più facile da
                    # fare aggiungendo i percorsi in fondo al file, e senza
                    # questa riga il messaggio parlerebbe di alias a chi sta
                    # scrivendo percorsi.
                    suggerimento = (
                        ". La chiave 'percorsi' va scritta PRIMA "
                        "dell'intestazione [alias]: dopo, TOML la legge come "
                        "un alias di nome 'percorsi'"
                    )
                raise ScopeError(
                    f"{p}: l'alias {nome!r} deve essere una stringa{suggerimento}"
                )
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

        percorsi = _carica_percorsi(p, dati.get("percorsi", []))

        if not reti and not alias and not percorsi:
            raise ScopeError(
                f"{p}: perimetro vuoto. Un perimetro vuoto non può voler dire "
                f"«tutto ammesso», e se volesse dire «niente ammesso» sarebbe "
                f"un blocco che nessuno riesce a diagnosticare: dichiarare "
                f"almeno una rete, un alias o un percorso."
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

        return cls(tuple(reti), alias, p, percorsi=percorsi)

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

    @property
    def percorsi(self) -> tuple[str, ...]:
        """Prefissi di percorso ammessi, nell'ordine in cui sono dichiarati."""
        return self._percorsi

    def __len__(self) -> int:
        return len(self._reti) + len(self._alias) + len(self._percorsi)

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


    def risolvi_percorso(self, target: str) -> str:
        """Percorso ammesso in forma risolta, o :class:`TargetRefused`.

        Restituisce il percorso **risolto** — symlink seguiti, ``..``
        eliminati — che è ciò che viene confrontato con i prefissi, ciò che
        viene passato al tool e ciò che il log affianca al percorso chiesto.
        Quando i due differiscono è esattamente l'informazione che un audit
        esiste per conservare.

        Il percorso deve esistere ed essere risolvibile da chi esegue il
        server: un percorso che non si riesce a risolvere fino in fondo non
        si sa dove porta, e si rifiuta invece di confrontare un valore
        risolto a metà.
        """
        if not target:
            raise TargetRefused("bersaglio vuoto")
        if len(target) > MAX_TARGET:
            raise TargetRefused(
                f"bersaglio più lungo di {MAX_TARGET} caratteri: non entrerebbe "
                f"nella riga di audit, e un'esecuzione non registrabile non si fa"
            )
        if target != target.strip():
            raise TargetRefused(
                "il bersaglio ha spazi iniziali o finali: si rifiuta invece di "
                "normalizzarlo, perché normalizzare significa eseguire qualcosa "
                "di diverso da ciò che è stato chiesto"
            )
        if any(ord(c) < 32 or ord(c) == 127 for c in target):
            raise TargetRefused(
                "il bersaglio contiene caratteri di controllo: un a-capo in un "
                "percorso è il modo di scrivere una seconda riga in un log"
            )
        # Assoluto, e non è solo forma: un percorso relativo si risolverebbe
        # rispetto alla directory di lavoro del server, che non è quella del
        # tool, e i due livelli controllerebbero due file diversi. Copre anche
        # il bersaglio che inizia per '-', che un tool leggerebbe come opzione.
        if not target.startswith("/"):
            raise TargetRefused(
                f"il percorso {target!r} non è assoluto: un percorso relativo "
                f"dipende da dove si trova chi lo legge, e il gate e il tool "
                f"non si trovano nello stesso posto"
            )
        if not self._percorsi:
            raise TargetRefused(
                "il perimetro non dichiara nessun prefisso di percorso "
                "('percorsi'): un tool con bersaglio di tipo percorso non è "
                "invocabile. L'assenza di prefissi non vale come «tutto ammesso»"
            )

        try:
            risolto = os.path.realpath(target, strict=True)
        except OSError as err:
            raise TargetRefused(
                f"il percorso {target!r} non è risolvibile "
                f"({type(err).__name__}): non esiste, non è attraversabile da "
                f"chi esegue il server, o contiene un ciclo di symlink. Un "
                f"percorso di cui non si sa dove porta non si confronta"
            ) from None
        if len(risolto) > MAX_TARGET:
            raise TargetRefused(
                f"il percorso risolto è più lungo di {MAX_TARGET} caratteri: "
                f"non entrerebbe nella riga di audit"
            )

        # Un prefisso che su questa macchina è a sua volta un symlink — o non
        # esiste — non delimita ciò che dichiara. Non lo si usa per ammettere
        # nulla, e lo si dice nel rifiuto: altrimenti chi legge «fuori dal
        # perimetro» cercherebbe l'errore nel bersaglio invece che nel file.
        non_canonici = []
        for prefisso in self._percorsi:
            try:
                reale = os.path.realpath(prefisso, strict=True)
            except OSError:
                non_canonici.append(f"{prefisso} (non esiste o non è risolvibile)")
                continue
            if reale != prefisso:
                non_canonici.append(f"{prefisso} (risolve in {reale})")
                continue
            if risolto == prefisso or risolto.startswith(prefisso + "/"):
                return risolto

        dove = (
            f"{target} risolve in {risolto}, che è"
            if risolto != target
            else f"{risolto} è"
        )
        nota = ""
        if non_canonici:
            nota = (
                f". Prefissi dichiarati e non utilizzabili su questa macchina: "
                f"{'; '.join(non_canonici)}"
            )
        raise TargetRefused(
            f"{dove} fuori dal perimetro dei percorsi "
            f"({', '.join(self._percorsi)}){nota}"
        )


def _carica_percorsi(p: Path, grezzi: object) -> tuple[str, ...]:
    """Prefissi di percorso validati, o :class:`ScopeError` con il motivo.

    Ogni regola ha il suo messaggio, perché chi corregge il file deve sapere
    quale ha violato. La chiave è **opzionale**: un perimetro senza percorsi è
    il perimetro di prima.

    Qui non si tocca il filesystem. Che un prefisso esista e non sia un
    symlink è un fatto della macchina, non del file: lo misura il preflight,
    e il gate lo ricontrolla a ogni invocazione.
    """
    if not isinstance(grezzi, list) or not all(isinstance(v, str) for v in grezzi):
        raise ScopeError(f"{p}: 'percorsi' deve essere una lista di stringhe")

    percorsi: list[str] = []
    for voce in grezzi:
        if not voce.startswith("/"):
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: deve essere assoluto. Un "
                f"prefisso relativo cambierebbe significato con la directory "
                f"di lavoro di chi lo legge"
            )
        if voce == "/":
            raise ScopeError(
                f"{p}: percorso non valido '/': la radice come prefisso è un "
                f"perimetro che non limita niente"
            )
        if voce.endswith("/"):
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: niente barra finale. Una "
                f"sola forma per prefisso, altrimenti '/srv/lab' e '/srv/lab/' "
                f"sarebbero due voci per lo stesso confine"
            )
        segmenti = voce.split("/")[1:]
        if ".." in segmenti:
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: contiene '..'. Un "
                f"prefisso che risale non dice dove finisce"
            )
        if "" in segmenti or "." in segmenti:
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: non è in forma canonica "
                f"(segmenti vuoti o '.'). Si rifiuta invece di normalizzarlo"
            )
        if not all(_SEGMENTO_PREFISSO.fullmatch(s) for s in segmenti):
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: nei prefissi sono ammessi "
                f"solo alfanumerici, '.', '_' e '-'. Il prefisso finisce in "
                f"una direttiva di montaggio, dove spazio e ':' sono sintassi"
            )
        if len(voce) > MAX_TARGET:
            raise ScopeError(
                f"{p}: percorso non valido {voce!r}: più lungo di "
                f"{MAX_TARGET} caratteri"
            )
        if voce in percorsi:
            raise ScopeError(
                f"{p}: percorso ripetuto {voce!r}: i prefissi devono essere "
                f"unici. Una voce doppia è quasi sempre una voce sbagliata"
            )
        percorsi.append(voce)
    return tuple(percorsi)


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
        case TargetKind.PATH:
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
            return allowlist.risolvi_percorso(target)
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
