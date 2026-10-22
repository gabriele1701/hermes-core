# Integrazione con Hermes

Come registrare `hermes-core` come server MCP in Hermes desktop.

Il server parla **MCP su stdio**: non ascolta su alcuna porta, viene lanciato
come sottoprocesso dall'host e dialoga sul proprio stdin/stdout. All'host
servono quindi solo due cose: **un comando da eseguire** e la cartella da cui
eseguirlo.

> **Architettura di riferimento: Hermes e il server stanno su macchine
> diverse.** Hermes desktop gira sulla postazione, il server su una VM
> dedicata, e il comando che Hermes lancia è `ssh`. Il motivo è che la
> toolbox non deve abitare sulle macchine che analizza: l'orchestratore
> custodisce il log d'audit, il vault e i controlli di scope, e un log che
> risiede sul bersaglio vale meno di uno che risiede altrove.
>
> La preparazione della VM — utenti, permessi, chiave SSH vincolata a un
> comando unico — è in **[setup-vm-hermes.md](setup-vm-hermes.md)**. Questo
> documento copre la registrazione in Hermes e la diagnostica, e vale sia per
> il caso remoto sia per un server sulla stessa macchina.

---

## 1. Preparare la macchina

Dalla radice del repo clonato:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp config/hermes.example.toml config/hermes.toml
```

`config/hermes.toml` è ignorato da git: è la tua copia locale, e lì dentro
finiscono i percorsi della tua macchina.

Nella config, l'unico campo che quasi certamente va corretto è `repo_root`,
che è relativo alla cartella del file di configurazione. Con il layout
standard (`config/hermes.toml` dentro il repo) il valore `".."` è già giusto.

---

## 2. Verificare **prima** di coinvolgere Hermes

```sh
python -m mcp_server.doctor config/hermes.toml
```

Questo è il passaggio che fa risparmiare tempo. Il preflight separa due
domande che altrimenti si confondono: *il server funziona?* e *Hermes lo sta
lanciando correttamente?*

Controlla configurazione, percorsi, permessi del log, integrità degli script
(SHA dichiarato contro SHA reale), backend del vault, e infine **avvia
davvero il server** facendo un handshake MCP, verificando che su stdout non
finisca nulla che non sia JSON-RPC.

Esce con codice `0` solo se non ci sono errori. Ogni problema riporta il
rimedio; per uno SHA non corrispondente, il rimedio contiene l'hash corretto
già pronto da incollare.

**Se il preflight è verde e Hermes non vede i tool, il problema è nella
registrazione lato Hermes, non nel server.** È esattamente l'informazione che
serve per non cercare nel posto sbagliato.

---

## 3. Il comando da dare a Hermes

### Server su VM dedicata (architettura di riferimento)

```
ssh -T -q hermes@<IP-VM>
```

SSH trasporta stdin e stdout in modo trasparente, quindi il protocollo
attraversa la connessione senza accorgersene: per Hermes è un normale server
stdio. Non serve indicare lo script, perché la chiave sulla VM è vincolata a
un comando unico (vedi [setup-vm-hermes.md](setup-vm-hermes.md)) e qualunque
cosa chieda il client, parte solo quel server.

`-T` è necessario, non opzionale: un pseudo-terminale farebbe eco e
traduzione dei caratteri, corrompendo il JSON-RPC. `-q` zittisce banner e
avvisi, che normalmente vanno su stderr ma su stdio non vale la pena
rischiare.

L'autenticazione **deve** essere a chiave: non c'è nessuno a digitare una
password, e con `no-pty` non ci sarebbe nemmeno dove chiederla.

### Server sulla stessa macchina di Hermes

```
/percorso/assoluto/del/repo/bin/hermes-core-server
```

Il wrapper esiste per un motivo pratico: il server va eseguito con il Python
del virtualenv, non con quello di sistema. Il wrapper ricava l'interprete
dalla propria posizione, quindi funziona **da qualunque directory** e senza
che Hermes debba conoscere il layout del progetto.

Senza argomenti usa `config/hermes.toml` del repo. Per un agente diverso,
passare la sua config:

```
/percorso/del/repo/bin/hermes-core-server /percorso/del/repo/config/pentest.toml
```

Provalo a mano prima di configurare Hermes — deve restare in attesa senza
stampare nulla, ed è il comportamento corretto: sta aspettando il protocollo
sullo stdin. Si esce con `Ctrl-C`.

> Il server **non è portabile su Windows** così com'è, e non conviene renderlo
> tale: `executor.py` lancia gli script con `python3`, il wrapper è uno script
> `sh`, e soprattutto `chmod 0600` sul log è di fatto inefficace su Windows
> mentre `chattr +a` non ha equivalente — si perderebbero due proprietà di
> sicurezza, non due comodità. Il posto del server è Linux, dove staranno
> comunque i tool che dovrà eseguire.

### Diagnostica specifica del caso remoto

Con il server su un'altra macchina si aggiungono due modi di fallire, nessuno
dei due dentro il nostro codice.

**La VM deve essere accesa** quando Hermes avvia il server. Un server stdio
viene lanciato su richiesta, non è un servizio sempre attivo: se la VM è
spenta, `ssh` fallisce e Hermes riporta un errore di connessione.

**L'indirizzo deve essere stabile.** La configurazione di Hermes contiene
l'indirizzo: con il DHCP la registrazione si rompe al primo rinnovo. IP
statico o riserva DHCP.

Se `ssh -T -q hermes@<IP-VM>` funziona dal terminale di Windows ma Hermes no,
il problema è nella registrazione. Se non funziona nemmeno dal terminale, è
rete, chiave o `authorized_keys`.

### Registrazione: usare la CLI, non scrivere la config a mano

Hermes tiene le registrazioni MCP in un file **YAML** sotto la chiave di primo
livello `mcp_servers`, indicato in `~/.hermes/config.yaml`. Le credenziali
stanno a parte, in `~/.hermes/.env`.

**Desktop e CLI condividono lo stesso file:** non esiste una configurazione
MCP separata per l'app desktop, il cui pannello *Impostazioni → MCP Servers*
modifica la medesima config. Una registrazione fatta dalla CLI compare quindi
nel desktop e viceversa.

> Il percorso e la condivisione desktop/CLI vengono da guide di terze parti
> concordi fra loro; la documentazione ufficiale è orientata alla CLI e non
> tratta il desktop. Vanno quindi considerati un'ipotesi solida ma da
> confermare sul file vero, cosa che il comando qui sotto permette di fare.

Conviene **non scrivere la config a mano** e lasciare che sia la CLI a
metterla dove quella installazione la tiene davvero:

```sh
hermes mcp add hermes-core \
    --command /percorso/assoluto/del/repo/bin/hermes-core-server

hermes mcp list                 # conferma che sia registrato
hermes mcp test hermes-core     # si connette, elenca i tool, esce con un codice
```

`hermes mcp test` esce `0` se la connessione riesce, `1` se fallisce, `3` se
il server non è in configurazione.

Accoppiato al preflight, questo dà una diagnosi a due lati: **il doctor dice
se il nostro server funziona, `hermes mcp test` se Hermes riesce a parlarci.**
Se il primo è verde e il secondo no, il problema è nella registrazione.

Dopo la registrazione vale la pena aprire il file che la CLI ha scritto: è
quello il percorso reale su questa macchina, e conoscerlo serve per le
modifiche successive.

### Forma YAML, se la scrivi a mano

```yaml
mcp_servers:
  hermes_core:
    command: ssh
    args: ["-T", "-q", "hermes@<IP-VM>"]
```

Campi disponibili secondo la documentazione: `command`, `args`, `env` per i
server stdio; `url` e `headers` per quelli HTTP; `enabled: false` per
disattivare senza cancellare; `tools` per filtrare ciò che viene esposto.

Il nostro server non richiede `env`: il wrapper ricava l'interprete dalla
propria posizione, quindi non dipende da variabili d'ambiente. E non richiede
`cwd`, perché i percorsi nella sua configurazione sono risolti rispetto al
file di configurazione e non alla directory corrente.

Per applicare una modifica fatta a mano: `/reload-mcp` dentro una sessione —
funziona anche nella chat del desktop — oppure aprirne una nuova.

### Dal pannello del desktop

In alternativa alla CLI: *Impostazioni → MCP Servers → aggiungi server
personalizzato*, indicando lo stesso comando assoluto. Il pannello scrive
nella stessa config, quindi le due vie sono interscambiabili.

Dopo l'aggiunta, verificare lo stato mostrato accanto al server: una voce può
risultare *installata ma disabilitata*, e in quel caso non espone nulla. I
tool abilitati sono registrati in config sotto
`mcp_servers.<nome>.tools.include`.

### Come si chiamano i tool dentro Hermes

Hermes espone i tool di un server MCP con un prefisso:
`mcp_<nome-server>_<nome-tool>`. Registrando il server come `hermes-core`, le
quattro funzioni compaiono quindi come:

```
mcp_hermes-core_list_available_tools
mcp_hermes-core_describe_tool
mcp_hermes-core_invoke_tool
mcp_hermes-core_raise_tool_tier
```

Vale la pena saperlo prima: cercando `invoke_tool` senza prefisso si
concluderebbe che la registrazione è fallita proprio mentre funziona.

Dato che il nome del server finisce dentro un identificatore, un nome senza
trattini — `hermes_core` — produce tool dal nome più pulito. È una preferenza,
non un requisito.

---

## 4. Verificare dentro Hermes

A registrazione avvenuta, Hermes dovrebbe mostrare quattro funzioni — col
prefisso `mcp_<nome-server>_` descritto sopra:

| Funzione | Cosa fa |
|---|---|
| `list_available_tools` | Elenca i tool di questo agente, con tier e conferme richieste |
| `describe_tool` | Dettaglio di un tool |
| `invoke_tool` | Esegue un tool applicando i controlli |
| `raise_tool_tier` | Innalza il tier di un tool (solo in salita) |

La prova che la catena funziona end-to-end è invocare `echo.ping`: deve
restituire `status: "ok"` e, in `output.stdout`, il JSON dell'agente dummy
con `"catena di esecuzione percorsa correttamente"`.

Contemporaneamente, nel log d'audit devono comparire le righe della catena:

```sh
tail -f logs/hermes-audit.jsonl
```

---

## 5. Cosa aspettarsi che **non** funzioni

Non sono guasti, sono confini voluti di questa milestone. Conoscerli evita di
cercare un errore dove non c'è.

**Un tool Giallo o Rosso non viene eseguito.** Ritorna `needs_confirmation`
con la chiamata in `pending`. Il flusso di conferma non è ancora collegato, e
`invoke_tool` non accetta un parametro `confirmed` di proposito: sarebbe
un'autorizzazione che il chiamante concede a se stesso. Si chiude collegando
l'*elicitation* di MCP — vedere [debito-sicurezza.md](debito-sicurezza.md).

**Un tool che richiede il container viene negato.** Finché
`container_available = false`, un tool con `requires_container = true` non
viene eseguito sull'host: la ricaduta silenziosa sull'ambiente meno isolato è
proprio ciò che si vuole impedire.

**Non esiste una funzione per ottenere un segreto.** Il vault è collegato ma
non esposto: i segreti vanno usati lungo il percorso di esecuzione, non
consegnati a un client.

**Un'istanza serve un solo agente.** L'identità è fissata nella config e non
è un parametro delle chiamate, altrimenti un client potrebbe dichiararsi
l'agente che gli conviene. Per più agenti servono più istanze, ciascuna con
la propria configurazione e il proprio comando.

---

## Diagnostica

**Hermes non vede il server.** Eseguire il comando a mano in un terminale: se
non resta in attesa, l'errore è su stderr. Verificare che il percorso sia
assoluto e che il wrapper abbia il bit di esecuzione (`ls -l bin/`).

**Hermes vede il server ma non i tool.** Il preflight elenca i tool
registrati: se li vede lui e non Hermes, il problema è nella registrazione
lato host. Se non li vede nemmeno lui, è la config.

**`hermes mcp test` esce con 1.** Connessione fallita: Hermes trova la
registrazione ma non riesce a dialogare. Il comando è sbagliato o non
eseguibile — provarlo a mano, esattamente come scritto nella config.

**`hermes mcp test` esce con 3.** Il server non è in configurazione: la
registrazione non è andata a buon fine, o la CLI e il processo che stai
interrogando leggono due file diversi.

**La CLI vede il server, il desktop no.** Dovrebbero condividere la stessa
config, quindi prima di tutto `/reload-mcp` nella chat del desktop, o una
sessione nuova. Se non basta, confrontare il file che la CLI ha scritto con
quello che il pannello mostra: è il punto in cui l'ipotesi della config
condivisa andrebbe smentita.

**Il server risulta registrato ma non espone tool.** Controllare lo stato nel
pannello: una voce può essere *installata ma disabilitata*. In config, i tool
abilitati stanno sotto `mcp_servers.<nome>.tools.include`.

**I tool non si trovano col nome che ti aspetti.** Hermes li espone come
`mcp_<nome-server>_<nome-tool>`: cercare `invoke_tool` senza prefisso non dà
risultati anche quando tutto funziona.

**Il server parte e muore subito.** L'avvio fallisce apposta se un tool non è
conforme o se il backend del vault è sconosciuto: partire con un registro
caricato a metà farebbe credere di avere tool che non ci sono. Il preflight
dice quale.

**Errori di protocollo o risposte incomprensibili.** Di solito è qualcosa che
scrive su stdout e corrompe il JSON-RPC. Il preflight ha un controllo
dedicato; se dovesse succedere con un tool nuovo, ricordare che **ogni output
diagnostico va su stderr**.

**Un tool smette di funzionare dopo che hai modificato il suo script.** È il
comportamento voluto: lo SHA non corrisponde più. Il preflight riporta l'hash
nuovo da mettere in config — ma vale la pena chiedersi se la modifica fosse
attesa prima di aggiornarlo.

---

## Messa in sicurezza, quando passi all'uso continuativo

Due misure che il preflight segnala come avvisi:

```sh
sudo chattr +a logs/hermes-audit.jsonl    # log non più riscrivibile
```

E, più importante: **eseguire il server con un utente che abbia solo lettura
sul repo**. La verifica dello SHA protegge dall'errore e dalla modifica
accidentale, ma non da chi controlla il conto che può riscrivere gli script.
È la mitigazione reale della finestra TOCTOU descritta in
[debito-sicurezza.md](debito-sicurezza.md).
