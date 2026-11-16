# Vocabolari condivisi fra `hermes-core` e il pannello

`hermes-core` esegue e applica; il
[pannello di controllo](https://github.com/gabriele1701/Pannello-di-controllo-Hermes)
decide, consulta e conserva. Oggi fra i due **non c'è nessuna connessione
viva**: niente registrazione dei tool, niente lettura degli override, niente
ingestione del log. Questo documento esiste perché, quando arriverà, sia un
collegamento e non una riscrittura.

Dice, vocabolario per vocabolario, se le due parti usano le stesse parole. Un
valore che il server emette e il pannello non conosce è una riga di log che
l'ingestione perde **in silenzio**; un valore che il pannello accetta e il
server rifiuta è una policy dichiarata che non si applica.

Ogni voce ha uno di tre stati:

| Stato | Significato |
|---|---|
| **allineato** | stessi valori, stesso significato |
| **divergente per scelta** | differenza voluta, con la ragione scritta qui |
| **divergente da chiudere** | differenza che romperà l'integrazione se resta |

## Come è stato rilevato, e cosa garantisce

Confronto fatto il 15 novembre 2026 leggendo gli enum nel codice, non la
documentazione: `hermes-core` dopo l'aggiunta dei bersagli di tipo percorso,
il pannello a `6558313`.

**La colonna del server è verificata da un test** (`tests/test_vocabolari.py`):
se un enum cambia e questa tabella no, la suite cade. **La colonna del
pannello no** — questo repo non vede l'altro — ed è quindi una fotografia:
vale alla data scritta sopra, e va rifatta prima di collegare le due parti.

## I vocabolari

<!-- La tabella qui sotto è letta da tests/test_vocabolari.py: il nome nella
     prima colonna e i valori nella seconda devono restare fra accenti gravi. -->

| Vocabolario | `hermes-core` | Pannello | Stato |
|---|---|---|---|
| `RiskTier` | `verde`, `giallo`, `rosso` | identico | allineato |
| `OwnerAgent` | `orchestrator`, `echo_dummy`, `vuln_assessment`, `pentest_kali` | identico | allineato |
| `CallOutcome` | `ok`, `error`, `denied`, `pending` | identico | allineato |
| `AuthorizedBy` | `policy`, `user`, `none` | identico | allineato |
| `LogAction` | `agent_invoked`, `agent_result`, `tool_registered`, `tool_registration_rejected`, `tool_alias_detected`, `override_set`, `override_rejected`, `override_store_loaded`, `override_not_persisted`, `concurrency_not_shared`, `tool_call`, `secret_access` | identico, 12 valori | allineato |
| `TargetKind` | `none`, `host`, `path` | gli stessi più `process` | divergente per scelta |
| `OverrideScope` | `none`, `config`, `persistent`, `session` | `OverrideSource`: `config`, `persistent` | divergente per scelta |
| `AgentStatus` | `ok`, `error`, `denied`, `needs_confirmation` | non modellato | divergente per scelta |
| `Severity` | `info`, `low`, `medium`, `high`, `critical` | non modellato | divergente per scelta |
| `ConfirmationCadence` | `nessuna`, `una_tantum_per_scope`, `puntuale` | non modellato | divergente per scelta |

### `LogAction` — riverificato dopo la patch di sicurezza

Era la voce a rischio: la patch ha toccato il log in più punti, e un evento
aggiunto o tolto avrebbe lasciato il pannello con un vocabolario incompleto.
**Non è successo:** dodici valori da entrambe le parti, gli stessi.

Una cosa da sapere per l'ingestione. `concurrency_not_shared` **non viene più
emesso**: i posti condivisi configurati e non utilizzabili ora negano
l'esecuzione, e il rifiuto è una riga `tool_call`/`denied`. Il valore resta in
entrambi i vocabolari perché i log scritti prima lo contengono, e un log
append-only non si rilegge se si toglie un'azione che vi compare. Non va
tolto da nessuna delle due parti.

### `TargetKind` — `process` c'è solo nel pannello, ed è voluto

Il server ha un validatore per ogni valore, e la regola è scritta nell'enum:
**nessun kind senza validatore**. Un valore in più senza il suo controllo
sarebbe un passaggio libero verso la riga di comando di un tool.

Per `none`, `host` e `path` il validatore è un confronto con una lista: nessun
bersaglio, le reti e gli alias, i prefissi di percorso. Per un processo una
lista non esiste e non può esistere: un PID è effimero e viene riciclato,
quindi «il PID 4312 è autorizzato» sarebbe falso qualche secondo dopo essere
stato scritto. **Per i processi il perimetro è l'isolamento, non una lista** —
il tool vede solo i processi del proprio spazio dei nomi, e fuori da lì non
c'è niente da autorizzare o negare.

Quell'isolamento sul server non esiste ancora: l'unità dei tool di tipo
percorso non monta nemmeno `/proc`. Finché non c'è, `process` sul server
sarebbe un kind senza validatore. Il pannello può modellarlo perché **modella
la dichiarazione, non l'applica**; il server lo aggiungerà insieme al
meccanismo, col primo tool che ne ha bisogno (GDB, Frida).

Conseguenza per l'integrazione: un tool dichiarato `process` nel pannello non
è registrabile sul server, e la registrazione fallirà **dicendolo**. È il
comportamento giusto, non un difetto da prevenire.

### `OverrideScope` e `OverrideSource` — due nomi, due domande

Il server risponde a «da dove viene il tier effettivo di questo tool,
adesso?», e le risposte sono quattro. Il pannello risponde a «da dove viene
questo innalzamento registrato?», e sono due.

* `none` sul server è l'assenza di un override. Nel pannello è l'assenza di
  una riga: non c'è niente da modellare.
* `session` è un innalzamento che vive solo in memoria, perché lo store non è
  collegato o non è scrivibile. **Per definizione non arriva a un registro
  persistente.** Il pannello lo vede comunque, ma nel log, come evento
  `override_not_persisted` — che è il posto giusto: è un fatto accaduto, non
  uno stato in vigore.

Il nome diverso è voluto per la stessa ragione: `source` è una proprietà di
una riga, `scope` di una risposta.

### `AgentStatus` — si traduce prima di arrivare al log

È lo stato di un `AgentResult`, cioè di un oggetto che attraversa il confine
fra agente e orchestratore. Nel log non compare: `audit.esito_da_status` lo
traduce in `CallOutcome`, e la traduzione è una sola funzione di proposito.

| `AgentStatus` | `CallOutcome` nel log |
|---|---|
| `ok` | `ok` |
| `error` | `error` |
| `denied` | `denied` |
| `needs_confirmation` | `pending` |

Il pannello legge il log, quindi vede `CallOutcome`. Modellare anche
`AgentStatus` vorrebbe dire avere due vocabolari per lo stesso fatto.

### `Severity` — i finding non arrivano al log

È la severità di un `Finding`, e i finding **non vengono scritti nel log
d'audit**: `log_agent_result` registra la sintesi e le invocazioni di tool,
non le osservazioni. Il pannello non ha quindi niente da cui leggerla.

Deliberato oggi, da rivedere il giorno in cui il pannello dovesse mostrare i
risultati e non solo le decisioni: a quel punto serve prima un canale per i
finding, e poi il vocabolario.

### `ConfirmationCadence` — derivata, non dichiarata

La cadenza di conferma non è un campo del contratto di registrazione: la
**deriva** il server dal tier e dal flag sui dati personali
(`tiers.derive_policy`). Se un tool potesse dichiararla, potrebbe assegnarsi
una cadenza più lassa del proprio rischio.

Il pannello non la modella, ed è corretto finché non la mostra. **Se un giorno
la mostrasse, non deve ricalcolarla**: una seconda copia della tabella tier →
cadenza è una copia che diverge, ed è lo stesso difetto delle tre mappe
status → esito unificate al passo 8b. Va letta dal server.

## I nomi dei campi

Non sono vocabolari, ma sono ciò su cui l'ingestione inciampa per primo.

| Concetto | `hermes-core` | Pannello | Stato |
|---|---|---|---|
| tier dichiarato del tool | `ToolSpec.default_tier` | `tools.declared_tier` | divergente per scelta |
| agente proprietario del tool | `ToolSpec.owner_agent` | `tools.agent` | divergente per scelta |
| istante dell'evento | `LogRecord.ts` | `audit_events.occurred_at` | divergente per scelta |
| tipo dell'evento | `LogRecord.action` | `audit_events.event_type` | divergente per scelta |
| identificativo della riga | assente | `audit_events.id` | divergente per scelta |
| tutti gli altri campi del log | `correlation_id`, `peer_correlation_id`, `outcome`, `agent`, `tool_id`, `target`, `tier_effective`, `authorized_by`, `secret_name`, `detail` | identici | allineato |

**`default_tier` / `declared_tier`.** Sul server il campo dice cosa succede in
assenza d'altro: è il *default* su cui un override può solo salire. Nel
pannello lo stesso valore sta accanto al tier effettivo, e lì la parola che
serve è il contrario di «effettivo»: *dichiarato*. Stesso dato, guardato da
due lati.

**Gli altri tre** sono nomi di colonna scelti per leggersi in SQL (`agent`
accanto a `tool_id`, `occurred_at` come ogni timestamp di evento,
`event_type` perché `action` è una parola riservata in più di un dialetto).
Sono una mappa di quattro righe da scrivere nell'ingestione, **una volta e in
un posto solo**.

**`audit_events.id`** è la chiave del database. Il log JSONL non ha un
identificativo di riga, e non deve acquistarne uno per questo: la posizione
nel file è già un ordine.

## Le regole di forma del perimetro

Il perimetro lo dichiara l'operatore nel pannello e lo applica il server. La
direzione conta: **una regola più stretta nel pannello è innocua**, perché
tutto ciò che il pannello accetta il server lo accetta; **una più larga è una
policy che non si applica**.

| Regola | `hermes-core` | Pannello | Stato |
|---|---|---|---|
| reti in forma canonica | sì (`strict=True`) | sì | allineato |
| alias dentro una rete dichiarata | sì | sì (trigger) | allineato |
| nome di un alias | alfanumerici, `.`, `-`, `_`; fino a 64 | `^[a-z0-9]+([.-][a-z0-9]+)*$` | divergente per scelta |
| prefisso: assoluto, mai `/`, senza barra finale, senza `//` | sì | sì | allineato |
| prefisso: lunghezza massima | 256 | 256 | allineato |
| prefisso: `..` | vietato come **segmento** | vietato come **sottostringa** | divergente per scelta |
| prefisso: caratteri ammessi | solo alfanumerici, `.`, `_`, `-` | tutto tranne `\`, caratteri di controllo e spazi esterni | **divergente da chiudere** |
| prefisso: segmento `.` | vietato | non verificato | **divergente da chiudere** |
| prefisso: deve esistere e non essere un symlink | sì, sulla macchina | non verificabile | divergente per scelta |

**Nome di un alias, e `..`.** Il pannello è più stretto: niente maiuscole e
niente `_` negli alias, e rifiuta `/srv/lab..vecchio` che il server
accetterebbe. Direzione innocua. Non vale la pena allargare il pannello né
stringere il server.

**Caratteri del prefisso — da chiudere.** È l'unica divergenza che oggi
romperebbe qualcosa. Il pannello accetta `/srv/campioni lab` e
`/srv/a:b`; il server li rifiuta, perché un prefisso finisce in una direttiva
di montaggio di systemd dove lo spazio separa due percorsi e `:` separa
sorgente e destinazione. Un prefisso così, dichiarato nel pannello e portato
sul server, farebbe **fallire il caricamento dell'intero perimetro** — reti
comprese, perché il file è uno solo.

Va chiusa nel pannello, con un `CHECK` in più su `scope_paths` e lo stesso
messaggio. Non sul server: allargare lì vorrebbe dire dover fare l'escape di
un percorso dentro una direttiva, cioè reintrodurre la classe di difetto che
la regola esiste per escludere.

**Segmento `.` — da chiudere**, insieme alla precedente: `/srv/./lab` passa
i vincoli del pannello e non quelli del server.

**Esistenza del prefisso.** Il pannello non gira sulla macchina dei tool e
non può sapere se `/srv/lab` esiste lì. Lo verificano il preflight, il gate e
il wrapper. Resta così.

## Cosa manca perché l'integrazione sia un collegamento

In ordine, e nessuno dei tre è in questo repo oggi:

1. **Chiudere le due voci «da chiudere»** sui prefissi di percorso, nel
   pannello. È l'unico lavoro che questo documento rende necessario.
2. **Rifare la fotografia del pannello** contro il codice del momento. La
   colonna di destra invecchia senza che niente lo dica.
3. **Scrivere la mappa dei nomi di campo una volta sola**, nell'ingestione, e
   farla fallire su un valore che non conosce invece di scartarlo: una riga
   persa in silenzio è il difetto che questo documento esiste per prevenire.
