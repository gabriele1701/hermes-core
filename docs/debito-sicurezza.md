# Debito di sicurezza aperto

Registro delle lacune di sicurezza **note e consapevolmente non ancora chiuse**.
Una lacuna discussa e non scritta sparisce: dopo qualche settimana il codice
sembra più robusto di quanto sia, e la decisione di rimandare diventa
indistinguibile da una svista.

Ogni voce dice cosa manca, perché è stata rimandata e qual è la condizione di
chiusura. Una voce si rimuove solo quando la chiusura è in `main` e testata.

Priorità: **ALTA** = da chiudere prima che il componente interessato esegua
qualcosa di reale. **MEDIA** = da chiudere prima di un uso continuativo.
**ACCETTATA** = valutata e deliberatamente non chiusa, con mitigazione.

## Chiuse

| Voce | Chiusa in | Come |
|---|---|---|
| `exec_sha256` dichiarato ma mai verificato | passo 6a | `executor.py` ricalcola lo SHA e lo confronta **prima di ogni esecuzione**, non all'avvio; discordanza → esecuzione negata e riga di audit. Resta il residuo TOCTOU qui sotto. |
| HC-01 — esecuzione senza riga di audit | patch sic. 1 | Decodifica tollerante e, dopo lo spawn, ogni eccezione convertita in esito registrato. Rete di sicurezza finale nel server. |
| HC-03 — interprete ereditato dal `PATH`, user site e moduli omonimi | patch sic. 2 | Interprete assoluto dalla configurazione, verificato all'avvio, eseguito con `-I -S`. Preflight: posizione, permessi e isolamento effettivo. |
| HC-06 — processi orfani al timeout, output e concorrenza illimitati | patch sic. 3 | `start_new_session` + terminazione del gruppo (SIGTERM poi SIGKILL), tetto per stream con flag `truncated` dichiarato, semaforo con rifiuto tracciato. |
| Lo stdin dei tool era il canale MCP del server | patch sic. 3 | `stdin=DEVNULL`. Trovato verificando il report, non era fra i suoi finding: un tool poteva leggere e consumare i byte del protocollo. |

---

## ACCETTATA — l'interprete dei tool non è coperto da uno SHA

**Dove:** `mcp_server/config.py` (`tool_python`), `mcp_server/executor.py`.

L'interprete con cui girano i tool è ora un percorso assoluto deciso in
configurazione ed eseguito isolato, ma il suo **contenuto** non è verificato
come quello degli script: non c'è un hash atteso per `/usr/bin/python3`.

**Decisione:** pinnare anche l'interprete significherebbe inseguire ogni
aggiornamento di sistema, e il beneficio è marginale rispetto al vincolo che
lo sostituisce: quel file appartiene al sistema e non all'utente di servizio.

**Mitigazione:** il preflight verifica che l'interprete sia fuori da
`repo_root` e non scrivibile da gruppo o altri, e lo riporta con modo e
proprietario. Chi può riscrivere `/usr/bin/python3` è già root.

**Da rivalutare se:** i tool verranno eseguiti da un venv dedicato dentro il
perimetro del progetto, perché a quel punto l'interprete torna a essere un
file che il progetto controlla.

---

## ACCETTATA — finestra TOCTOU fra verifica dell'hash ed esecuzione

**Dove:** `mcp_server/executor.py`.

Lo SHA viene ricalcolato prima di ogni esecuzione, ma fra il calcolo
dell'hash e lo spawn del processo passano alcuni millisecondi in cui il file
potrebbe essere sostituito. La verifica legge il file, l'esecuzione lo rilegge
dal percorso: sono due letture distinte.

**Decisione:** chiuderla richiederebbe di eseguire dal descrittore già aperto
e verificato (`fexecve`), che Python non espone in modo portabile. Il costo di
aggirare il problema supera il beneficio, dato il contesto.

**Mitigazione:** la finestra è di millisecondi e sfruttarla richiede già
accesso in scrittura alla directory degli script. La protezione reale è
quella: **la directory degli script non deve essere scrivibile dall'utente che
esegue il server.** Chi può riscrivere gli script non ha bisogno di vincere
una corsa, cambia direttamente la configurazione.

**Da rivalutare se:** il server girerà con un utente che ha accesso in
scrittura al repo, o se gli script arriveranno da una sorgente non versionata.

---

## ALTA — l'aliasing di un tool non è rifiutabile: manca `exec_args`

**Dove:** `mcp_server/contracts.py` (`ToolSpec`), `mcp_server/registry.py`.

Il rifiuto del `tool_id` duplicato chiude la via più comoda al declassamento,
non tutte. Resta quella di registrare un **secondo `tool_id` sullo stesso
script** a tier più basso: stessa capacità, conferme più lasche, regola
sull'override aggirata.

Non è rifiutabile oggi perché il caso abusivo e quello legittimo — uno script
con più sottocomandi a rischio diverso, es. `nmap.ping_sweep` Verde e
`nmap.aggressive` Rosso — sono **indistinguibili**: `ToolSpec` non ha un campo
argomenti, quindi `exec_path` è l'intera identità di ciò che viene eseguito.

**Mitigazione in essere:** il registro *rileva e registra* l'anomalia
(`tool_alias_detected`) senza bloccarla, sia per l'alias a tier inferiore sia
per l'incoerenza di `exec_sha256` sullo stesso path. Visibile in review, non
bloccante.

**Condizione di chiusura:** aggiungere `exec_args` a `ToolSpec`, così che
l'identità di un tool diventi `(exec_path, exec_sha256, exec_args)`. A quel
punto due `tool_id` con identità identica e tier diverso sono aliasing
genuino, e il registro può **rifiutare** quello a tier inferiore invece di
limitarsi a segnalarlo. Da affrontare **quando i tool avranno bisogno di
argomenti**, cioè all'ingresso dei primi tool reali in Milestone 1.

---

## MEDIA — il limite di concorrenza è per processo, non complessivo

**Dove:** `mcp_server/executor.py` (semaforo), `docs/integrazione-hermes.md`.

Il tetto sulle esecuzioni contemporanee vive in un semaforo del processo
server, e Hermes avvia **un processo per connessione**. Contiene quindi un
modello in ciclo dentro una sessione, non la somma di più sessioni o
connessioni aperte in parallelo.

**Perché rimandata:** un limite complessivo richiede uno stato condiviso fra
processi — un file di lock o un contatore in `/var/lib/hermes` — e lo stesso
problema si presenta per gli override durevoli. Conviene risolverli insieme,
con un solo meccanismo di stato condiviso, invece di inventarne due.

**Mitigazione:** il limite per processo copre il caso realistico di oggi, cioè
un agente che invoca in ciclo nella sessione in cui sta lavorando. Ogni
rifiuto è tracciato, quindi una saturazione si vede nel log.

**Condizione di chiusura:** insieme alla persistenza degli override, con lo
stesso store append-only.

---

## MEDIA — il flusso di conferma non è collegato

**Dove:** `mcp_server/server.py`.

`invoke_tool` non accetta un parametro `confirmed`, e giustamente: un booleano
fornito dal chiamante sarebbe un'autorizzazione che il client concede a se
stesso, e la cadenza di conferma diventerebbe ornamentale.

La conseguenza è che oggi **un tool che richiede conferma non è eseguibile**
attraverso il server: l'invocazione ritorna `needs_confirmation` con la
chiamata in `pending`, e lì si ferma. È fail-closed, quindi il difetto è di
funzionalità e non di sicurezza — ma va chiuso perché altrimenti tutto ciò che
non è Verde resta inutilizzabile.

**Condizione di chiusura:** collegare il meccanismo di *elicitation* di MCP,
con cui il server chiede all'host di interpellare l'utente e riceve la
risposta lungo il protocollo. L'autorizzazione arriva così dall'host, non dal
chiamante, e resta `authorized_by=USER` con una provenienza verificabile.
Da affrontare insieme allo store dei consensi per scope, con cui condivide il
modello.

---

## MEDIA — il consenso per scope non è modellato

**Dove:** `mcp_server/tiers.py` (`ConfirmationPolicy.unattended_safe`).

La cadenza `una_tantum_per_scope` presuppone un registro dei consensi già
dati, che non esiste. `tiers.py` *risponde* se un tool sia eseguibile non
presidiato, ma non può verificare se il consenso per quello scope sia a
registro, perché è deliberatamente senza stato.

**Condizione di chiusura:** il gestore delle routine introduce lo store dei
consensi per scope e, insieme, il campo `authorization_ref` su `ToolCall` per
distinguere in audit un consenso dato in diretta da uno pre-autorizzato.
Aggiunta additiva, non rompe il contratto esistente.

---

## ACCETTATA — il log d'audit non è tamper-evident

**Dove:** `mcp_server/audit.py`.

Il log è append-only a livello di API, ma chi ha accesso in scrittura al file
può riscriverlo a posteriori.

**Decisione:** l'hash-chaining dei record è stato valutato ed escluso.
Imporrebbe di serializzare le scritture, perdendo il writer stateless e
concorrente; e senza un ancoraggio esterno dell'hash di coda non sposta il
modello di minaccia, perché chi controlla file e codice ricalcola l'intera
catena.

**Mitigazione:** `chattr +a` sul file di log (root per metterlo o toglierlo,
quindi efficace contro un processo non privilegiato) e spedizione a un
collector esterno, dove una copia già uscita dall'host non è raggiungibile da
una manomissione locale.

**Da rivalutare se:** il log dovrà reggere da solo come prova davanti a
terzi. In quel caso la strada è un digest periodico firmato con chiave
esterna, che non tocca il percorso di scrittura.

---

## ACCETTATA — il registro si fida della propria configurazione

**Dove:** `mcp_server/registry.py`.

Nessun controllo nel registro protegge da una configurazione malevola: chi
può scrivere la config può registrare qualunque tool con qualunque tier.

**Decisione:** il confine di fiducia è chi può scrivere nel repo. La config è
versionata e le modifiche passano da una pull request; autenticare le
registrazioni con una firma aggiungerebbe cerimonia senza aggiungere
sicurezza, in un contesto a utente singolo dove la firma che conta è già
quella di git.

**Mitigazione:** ogni registrazione, rifiuto e anomalia è un evento tracciato,
così che configurazione e log raccontino la stessa storia e una discrepanza
sia visibile.

**Da rivalutare se:** il registro verrà popolato da una fonte non versionata,
o da più di una persona.
