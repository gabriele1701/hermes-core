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
| HC-08 — `valida_nome_segreto` accettava un newline finale | patch sic. 4 | `fullmatch` invece di `match`: in `re` il `$` combacia anche prima di un `\n` finale. Si rifiuta, non si normalizza. |
| HC-07 — provenienza nel log controllata dal client | patch sic. 5 | `correlation_id` generato dal server, quello del client registrato come `peer_correlation_id` e collegato da entrambi i lati. Etichetta onesta: «richiesto dal client MCP», non «override utente». |
| Gli override di tier non sopravvivevano alla connessione | patch sic. 6a | Tre fonti e un solo `max()`: tier dichiarato (pavimento), `override_tier` in `[[tool]]`, store append-only in `state_dir`. Scrive **solo gli incrementi reali**, quindi ha un tetto strutturale di due righe per tool (`2 × tool × connessioni contemporanee` nel caso concorrente) e non va ruotato. `state_dir` assente o non scrivibile → innalzamento valido per la connessione, **dichiarato** in `override_scope` e registrato come `override_not_persisted`. |
| Il `detail` diceva «in attesa di conferma dell'utente» | patch sic. 6a | Non c'era nessuna attesa: nessun canale di conferma è collegato. Un modello che legge «in attesa» conclude che qualcuno risponderà e riprova — o cerca un'altra via per lo stesso effetto. Ora il testo dice che il tool non è stato eseguito e che riprovare non cambia l'esito. Il flusso resta aperto qui sotto. |
| Il limite di concorrenza era per processo | patch sic. 6b | Un file di lock per posto in `state_dir/slots/<agente>/`, preso con `flock(LOCK_EX|LOCK_NB)`. Il kernel lo rilascia alla morte del processo: niente lock orfani, niente scadenze da indovinare. Il semaforo in memoria resta come percorso veloce. Senza `state_dir` il tetto resta per processo, dichiarato nel preflight. |
| HC-05 — minimo di dipendenza falso | patch sic. 4 | `mcp>=2.3,<3` e `pydantic>=2.12,<3`. Il lockfile con hash, che e' la protezione vera, e' documentato in `docs/dipendenze.md` e resta da generare. |

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

## MEDIA — il log d'audit cresce senza tetto e non è ruotabile

**Dove:** `mcp_server/audit.py`, `docs/setup-vm-hermes.md`.

Il log cresce di tre righe per invocazione e non ha né tetto né rotazione. Con
`chattr +a` non è nemmeno ruotabile senza un `chattr -a` privilegiato, perché
un file append-only non si può rinominare né troncare — che è esattamente la
proprietà per cui lo abbiamo irrigidito.

Il punto che morde prima non è il disco: è che un file molto grande rende
lenta ogni operazione che lo rilegge, e `read_all` è usato in diagnostica.

**Come ci siamo arrivati.** La voce nasce da una domanda su un'altra cosa.
Avevo proposto di rimandare la rotazione dello *store degli override*,
trattandola come lavoro di progettazione; alla domanda se fosse una falla
effettiva o un accorgimento, è emerso che per gli override il problema **si
elimina invece di gestirlo** — lo store registra solo gli incrementi reali, e
un tier può salire al massimo due volte per tool, quindi ha un tetto
strutturale. Ragionando su quel confronto è diventato evidente che la crescita
illimitata resta vera, e non registrata, per il log d'audit: lì ogni
invocazione scrive, comprese le richieste ripetute che lo store non memorizza.

**Perché non si risolve con una rotazione locale.** Ruotare il log in locale
significa poter perdere righe, cioè perdere la traccia che il log esiste per
conservare. Il problema e la soluzione sono gli stessi della tamper-evidence:
serve una **copia fuori dall'host**.

**Condizione di chiusura:** spedizione a un collector esterno (già prevista in
`docs/setup-vm-hermes.md`). Con la copia remota al sicuro, la rotazione della
copia locale diventa un'operazione ordinaria e non una perdita di prove.

**Mitigazione intanto:** sorvegliare lo spazio e, quando serve, ruotare a mano
con `chattr -a`, copia, troncamento, `chattr +a` — annotando l'intervento.

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

**Corretto nel frattempo (patch sic. 6a):** il `detail` della chiamata diceva
«in attesa di conferma dell'utente», che non era vero — non c'è nessuna
attesa, perché non esiste un canale su cui la conferma possa arrivare. La
differenza non è di stile: un modello che legge «in attesa» conclude che
qualcuno risponderà, e il comportamento ragionevole diventa riprovare, o
cercare un'altra strada per ottenere lo stesso effetto, che è esattamente ciò
che la conferma doveva impedire. Ora il testo dice che il tool **non** è stato
eseguito, che riprovare non cambia l'esito e che serve un'autorizzazione fuori
banda. Il flusso resta da collegare.

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

## ACCETTATA — il tetto di concorrenza è per agente, non per macchina

**Dove:** `mcp_server/slots.py`.

I posti di esecuzione sono partizionati per agente
(`state_dir/slots/<agente>/`), quindi il tetto complessivo della macchina è
`max_concurrent_tools × agenti attivi`, non `max_concurrent_tools`.

**Perché così.** Un pool unico darebbe un tetto di macchina migliore, ma
sarebbe il primo punto dell'architettura in cui **un agente può degradarne un
altro**: l'agente di pentest in ciclo affamerebbe quello di vulnerability
assessment, e lo farebbe senza violare alcuna regola. Tutto il resto del
progetto tiene gli agenti separati per costruzione — un processo ciascuno, i
tool di proprietà, i tool altrui invisibili — e aprire proprio qui un canale
di denial-of-service fra agenti è il male peggiore fra i due.

**Perché non è un rinvio mascherato.** Un tetto di macchina vero non è lavoro
di questo processo: conta esecuzioni, non risorse. Due `nmap` pesanti saturano
una VM molto prima di dieci script che dormono. Lo strumento giusto è una
slice `systemd` o un cgroup con limiti di CPU e memoria, che vale per
qualunque cosa giri sulla macchina e non solo per i tool lanciati da qui.

**Da rivalutare se:** gli agenti attivi diventeranno molti, o se un agente
arriverà a poter saturare la VM da solo — nel qual caso serve il cgroup, non
un pool condiviso.

---

## ACCETTATA — un innalzamento è irreversibile dall'interfaccia, e può bloccare la toolbox

**Dove:** `mcp_server/overrides.py`, `mcp_server/registry.py` (`set_override`).

Il tier può solo salire, e da quando lo store è persistente **resta salito**.
Un tool portato a Rosso richiede conferma, e nessun canale di conferma è
collegato (voce sopra): quel tool non è più invocabile, e non torna da solo.

Prima di questa patch esisteva una valvola di sfogo accidentale: gli override
morivano con la connessione, quindi un innalzamento sbagliato si curava
riconnettendosi. Persistendoli l'abbiamo tolta, e va detto apertamente —
**è una conseguenza della patch, non una proprietà che c'era già.**

**Lo scenario che ne deriva:** `raise_tool_tier` lo chiama il modello. Un
modello in ciclo, o spinto da un'iniezione nel contesto, può innalzare a Rosso
ogni tool dell'agente e rendere la toolbox inutilizzabile in modo permanente,
senza che nessun controllo lo fermi — perché dal punto di vista del registro
sta chiedendo *più* severità, non meno.

**Perché si accetta.** È un attacco alla disponibilità, non all'integrità, e
la direzione del guasto è quella giusta: il risultato è una toolbox ferma, non
una toolbox che esegue cose rischiose con controlli allentati. Fra i due, il
primo è recuperabile in un minuto da chi ha accesso alla macchina; il secondo
no. Dare al modello un modo di abbassare un tier per uscire da questa
situazione annullerebbe l'intera regola.

**Mitigazioni in essere:**

* ogni innalzamento è nel log d'audit con `agent` e `correlation_id`, quindi
  si vede *quando* è successo e dentro quale catena;
* lo store contiene gli stessi dati, in poche righe leggibili a occhio;
* il tier dichiarato resta un pavimento: rimuovere una riga non può portare un
  tool **sotto** ciò che l'integratore ha dichiarato.

**Come si torna indietro** (richiede privilegi sulla macchina, di proposito —
la procedura è in `docs/setup-vm-hermes.md`):

```sh
sudo chattr -a /var/lib/hermes/state/overrides.jsonl   # solo se irrigidito
sudo -u hermes grep -v '"tool_id": "<tool>"' \
     /var/lib/hermes/state/overrides.jsonl > /tmp/o.new
sudo -u hermes cp /tmp/o.new /var/lib/hermes/state/overrides.jsonl
sudo chattr +a /var/lib/hermes/state/overrides.jsonl   # se lo si vuole di nuovo
```

**Deliberatamente non fatto:** un sottocomando che rimuova un override. Sarebbe
un declassamento con un'interfaccia comoda, e una volta che esiste finisce per
essere chiamato da qualcosa di automatico. La scomodità qui è il controllo.

**Da rivalutare se:** i tool diventeranno molti e l'innalzamento accidentale
sarà frequente, oppure quando il canale di conferma sarà collegato — a quel
punto un tool Rosso resta usabile, e l'innalzamento smette di essere un blocco.

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
