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
| HC-06 — processi orfani al timeout, output e concorrenza illimitati | patch sic. 3 | `start_new_session` + terminazione del gruppo (SIGTERM poi SIGKILL), tetto per stream con flag `truncated` dichiarato, semaforo con rifiuto tracciato. **Chiusa per il caso del timeout soltanto:** un tool che esce con 0 lasciando figli vivi non fa scattare nulla — voce aperta qui sotto. |
| Lo stdin dei tool era il canale MCP del server | patch sic. 3 | `stdin=DEVNULL`. Trovato verificando il report, non era fra i suoi finding: un tool poteva leggere e consumare i byte del protocollo. |
| HC-08 — `valida_nome_segreto` accettava un newline finale | patch sic. 4 | `fullmatch` invece di `match`: in `re` il `$` combacia anche prima di un `\n` finale. Si rifiuta, non si normalizza. |
| HC-07 — provenienza nel log controllata dal client | patch sic. 5 | `correlation_id` generato dal server, quello del client registrato come `peer_correlation_id` e collegato da entrambi i lati. Etichetta onesta: «richiesto dal client MCP», non «override utente». |
| Gli override di tier non sopravvivevano alla connessione | patch sic. 6a | Tre fonti e un solo `max()`: tier dichiarato (pavimento), `override_tier` in `[[tool]]`, store append-only in `state_dir`. Scrive **solo gli incrementi reali**, quindi ha un tetto strutturale di due righe per tool (`2 × tool × connessioni contemporanee` nel caso concorrente) e non va ruotato. `state_dir` assente o non scrivibile → innalzamento valido per la connessione, **dichiarato** in `override_scope` e registrato come `override_not_persisted`. |
| Il `detail` diceva «in attesa di conferma dell'utente» | patch sic. 6a | Non c'era nessuna attesa: nessun canale di conferma è collegato. Un modello che legge «in attesa» conclude che qualcuno risponderà e riprova — o cerca un'altra via per lo stesso effetto. Ora il testo dice che il tool non è stato eseguito e che riprovare non cambia l'esito. Il flusso resta aperto qui sotto. |
| Il limite di concorrenza era per processo | patch sic. 6b | Un file di lock per posto in `state_dir/slots/<agente>/`, preso con `flock(LOCK_EX|LOCK_NB)`. Il kernel lo rilascia alla morte del processo: niente lock orfani, niente scadenze da indovinare. Il semaforo in memoria resta come percorso veloce. **Assente è diverso da rotto:** senza `state_dir` il tetto resta per processo ed è dichiarato nel preflight e nel catalogo (`concurrency_shared_across_connections`); con `state_dir` configurata e la directory dei posti non utilizzabile il tetto è promesso e non applicabile, quindi il gate **rifiuta** invece di degradare — stessa regola del container assente. |
| HC-04 — il canale del servizio poteva auto-autorizzarsi | passo 7 | `ForceCommand` e `AuthorizedKeysFile` nel drop-in `config/sshd/10-hermes.conf`, quindi nella configurazione di sshd e non nella `authorized_keys` dentro la home del servizio: un tool compromesso non può più togliersi il comando vincolato né aggiungere una chiave. Chiavi in `/etc/ssh/authorized_keys.d/hermes`, root-owned. Password disattivata, `ufw` ristretto all'IP della postazione. Il preflight verifica il confine sul filesystem, non solo la configurazione. |
| A2 — il bersaglio di un'invocazione non era validato | passo 8 | Perimetro di reti e alias in un file di root (`server.scope_file`), `target_kind` nel contratto e un validatore per ciascun kind. Controllo **prima** dell'integrità e del container: un bersaglio fuori perimetro va rifiutato e registrato allo stesso modo sia che il container ci sia sia che non ci sia. Nessuna risoluzione DNS — gli alias sono dichiarati dall'operatore, quindi non c'è finestra di rebinding. Perimetro assente non vale come «tutto ammesso»: i tool con bersaglio non sono invocabili, e il catalogo lo dichiara in `scope_configured`. |
| ALTA — l'aliasing di un tool non era rifiutabile (`exec_args`) | passo 8 | `exec_args` nel contratto: l'identità di ciò che viene eseguito diventa `(exec_path, exec_sha256, exec_args)`. A identità **identica** e tier inferiore la registrazione è rifiutata, non più solo segnalata. A identità diversa — due sottocomandi dello stesso script a rischio diverso — resta la segnalazione `tool_alias_detected`, perché lì l'ambiguità c'è davvero. Chiusa al passo 8 e non in M1 perché la condizione era «quando i tool avranno bisogno di argomenti», e passare il bersaglio allo script è quel momento. |
| Un rifiuto del gate si presentava come un guasto | passo 8b | `AgentStatus.DENIED` accanto a `OK`, `ERROR` e `NEEDS_CONFIRMATION`. Prima un rifiuto — container assente, integrità fallita, posti esauriti, bersaglio fuori perimetro — finiva in `ERROR`: la riga sotto diceva `denied` e lo status in cima lo contraddiceva. È il difetto del `pending` formulato male un livello più su, perché un modello che legge `error` può concludere che qualcosa si è rotto e riprovare. L'invariante di `AgentResult` pretende una `tool_call` rifiutata: un rifiuto che non dice cosa ha rifiutato resta `ERROR`, ed è il caso del tool inesistente e di quello di un altro agente — dove dire «rifiutato» rivelerebbe che il tool esiste. Unificate le tre copie della mappa status → esito. |
| A1 — i tool giravano con l'identità del servizio | passo 9 | Uid dedicato `hermes-tool` senza shell, via un wrapper di root (`bin/hermes-tool-run`) autorizzato da una sola riga di sudoers. Unità transiente di tipo servizio e non scope, perché con `--scope` il processo lo lancia il chiamante e il cambio di uid fallisce. Il tool non può più aprire il log d'audit, cioè la traccia che dovrebbe registrarlo. Wrapper configurato e non utilizzabile → il gate rifiuta, non ricade sull'identità del servizio. |
| Il tetto di concorrenza era per agente, non per macchina | passo 9 | `MemoryMax` + `MemorySwapMax=0` + `TasksMax` nel cgroup dell'unità: il tetto ora misura risorse reali e non esecuzioni, che era la condizione di chiusura registrata. Valori provvisori, vedere la voce aperta qui sotto. |
| I figli di un'uscita pulita non venivano ripuliti | passo 9 | Il cgroup dell'unità muore con l'unità qualunque cosa contenga, quindi non serve che il gate distingua un figlio legittimo da un residuo — che era il motivo per cui non si poteva chiudere con un `killpg`. |
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

**Perché non si risolveva con una rotazione locale.** Ruotare il log in
locale significa poter perdere righe, cioè perdere la traccia che il log
esiste per conservare. Il problema e la soluzione erano gli stessi della
tamper-evidence: serviva una **copia fuori dall'host**.

**La copia c'è, da A5** (`docs/setup-vm-hermes.md` §10). Il blocco è quindi
caduto: ruotare non è più una perdita di prove, perché le righe sono già
altrove. Resta aperto il resto della voce, e ora è una cosa più piccola.

**Cosa manca:** la rotazione vera e propria, che è **deliberatamente
manuale**. Un rotatore automatico che sbagliasse l'offset distruggerebbe
prove da solo, ogni notte, senza che nessuno guardi. La regola quando la si
farà: si tronca **solo fino all'offset confermato dal collector**, mai oltre.

**Mitigazione intanto:** sorvegliare lo spazio e, quando serve, ruotare a mano
con `chattr -a`, copia, troncamento, `chattr +a` — annotando l'intervento, e
dopo aver verificato che la copia remota sia allineata.

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

**Mitigazione, dal novembre 2026 in due pezzi.** `chattr +a` sul file (root
per metterlo o toglierlo, quindi efficace contro un processo non
privilegiato); e **A5**, che non si limita a tenere una copia fuori
dall'host ma la rende un rilevatore: il ricevente rifiuta qualunque offset
che non sia la dimensione della sua copia, quindi un troncamento o una
riscrittura locale producono un **sintomo** invece di un silenzio. Una copia
che nessuno confronta sarebbe un backup, non una prova.

**Cosa resta scoperto, e va saputo:**

* **le righe false.** A5 difende dalla cancellazione a posteriori, non da un
  `hermes` compromesso che appende righe mentite. Quelle finiscono anche
  nella copia;
* **la finestra di cinque minuti.** Chi ottiene root e ripulisce prima della
  spedizione successiva cancella le righe di quella finestra, e nessuno lo
  saprà. Stringere la cadenza stringe la finestra e non la chiude;
* **fermare il mittente.** Root può disabilitare il timer. Non è silenzioso —
  il preflight riporta l'età dell'ultimo giro riuscito — ma è un avviso da
  guardare, non un blocco.

**Da rivalutare se:** il log dovrà reggere da solo come prova davanti a
terzi. In quel caso la strada è un digest periodico firmato con chiave
esterna, che non tocca il percorso di scrittura.

---

## MEDIA — i tetti di risorsa dei tool non sono calibrati

**Dove:** `bin/hermes-tool-run` (`MEMORY_MAX`, `TASKS_MAX`, `RUNTIME_MAX_CEILING`).

I limiti del cgroup sono in vigore e **mordono** — verificato: un processo che
sfonda `MemoryMax` con `MemorySwapMax=0` viene ucciso, e `TasksMax` ferma le
fork oltre il tetto. Quello che non è verificato è che i **valori** siano
quelli giusti: 1 GB di memoria e 128 processi sono stati scelti senza nulla da
misurare.

**Perché non si calibra adesso.** Non si sa quanto consumi un `nmap -A` su una
/24, né quanti processi lanci `trivy` su un'immagine grande. Misurarlo richiede
quei tool.

**Perché larghi e non stretti.** Sono i due errori possibili, e il secondo è
peggiore: un tetto troppo largo non limita molto, ma lo si sa e lo si è
scritto; un tetto troppo stretto uccide il primo scan vero a metà, e il sintomo
— un figlio morto con un codice d'uscita strano — non punta alla causa. Si
perderebbe un pomeriggio a cercare un bug nel tool o nel gate.

**Mitigazione in essere:** la causa di un'uccisione è leggibile. Il wrapper
propaga `128+segnale`, quindi OOM è `137` e il tempo limite `143`, e il nome
dell'unità contiene il `correlation_id`: `journalctl -u hermes-tool-<cid>` dà
`Result=oom-kill` e il consumo di picco.

**Condizione di chiusura:** l'ingresso del primo tool reale in M1. Allora i
valori si misurano, e probabilmente diventano per-tool invece di uno solo per
tutti — `nmap` e un controllo passivo non hanno bisogno dello stesso spazio.

---

## MEDIA — il traffico dei tool non è confinato a livello di rete

**Dove:** nessun punto del codice. È ciò che il perimetro dei bersagli non può
fare.

Il passo 8 valida **l'argomento con cui un tool parte**: un bersaglio fuori
dalle reti ammesse viene rifiutato prima dell'esecuzione. Non controlla dove va
il traffico del processo *dopo* l'avvio. Un tool che ignorasse il proprio
argomento, o che aprisse una connessione per conto suo, non incontrerebbe
alcun confine.

**Perché diventa chiudibile solo ora.** Un confine di rete ha bisogno di un
soggetto a cui applicarsi, e fino al passo 9 i tool condividevano l'identità
del server: una regola sull'uid avrebbe colpito anche il canale MCP. Con
`hermes-tool` il soggetto esiste.

**Il disegno, già deciso:** `nftables` con `meta skuid hermes-tool`, catena di
output, politica di rifiuto con le reti del perimetro in eccezione. La regola
va tenuta coerente con il file di scope — due fonti per lo stesso confine sono
due fonti che divergono, quindi conviene generarla da quel file invece di
scriverla a mano.

**Perché non nel passo 9:** avrebbe raddoppiato la superficie di un passo che
già cambia il modo in cui i tool vengono eseguiti, e un errore in una regola di
output si manifesta come «il tool non raggiunge niente» senza dire perché.

**Condizione di chiusura:** da fare insieme al primo tool che esce davvero in
rete, così la regola si verifica su traffico reale invece che su un dummy.

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
