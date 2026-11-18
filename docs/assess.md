# `hermes-assess` — verificare che le difese reggano

**Stato:** M1.1. Catalogo, referto, lanciatore e tre prove: AS-03 (confine dei tool), AS-05 (traccia), AS-06 (perimetro di rete). Le altre risultano «non ancora implementate» nel referto.

## Cosa è

Il preflight (`python -m mcp_server.doctor`) risponde a **«l'installazione è conforme, posso partire?»**: legge configurazione, permessi e stato, e dice cosa manca.

`hermes-assess` risponde a un'altra domanda: **«le difese reggono?»**. Per ogni minaccia del catalogo **tenta l'operazione che la difesa deve impedire**, sotto l'identità vera e lungo la catena vera, e registra se viene impedita.

| | Preflight | `hermes-assess` |
|---|---|---|
| Domanda | è configurato? | regge? |
| Metodo | legge stato e permessi | tentativi non armati, con il loro controllo positivo |
| Identità | l'utente di servizio | root, che scende a ciascuna identità di servizio |
| Esito | PRONTO / NON PRONTO | per minaccia: tiene · cede · non verificabile · non applicabile · accettato |

Dal preflight si riusano i **lettori** (configurazione, drop-in, stato del wrapper, permessi effettivi), non i verdetti: due implementazioni dello stesso lettore sono due verità.

**Cosa non fa.** Non scansiona altri host, non contiene exploit né payload, non apre traffico in uscita dal server, non installa pacchetti, non invoca tool reali.

## Il catalogo

Il catalogo delle minacce è in [`mcp_server/assess/catalogo.py`](../mcp_server/assess/catalogo.py), e **questo documento non lo ripete**. Ogni voce dichiara la minaccia e la sua origine (finding della security review, debolezza architetturale, decisione di progetto), cosa si tenta, cosa deve riuscire perché il tentativo provi qualcosa, quando si applica, la gravità di base, gli effetti sulla macchina e il rimedio.

`tests/test_assess_catalogo.py` pretende per ogni voce:

- **un tentativo ha il suo controllo positivo**, e una misura dice perché non è un tentativo;
- ogni percorso del repo citato esiste;
- ogni voce del registro del debito citata è un'intestazione di [`debito-sicurezza.md`](debito-sicurezza.md), quindi una voce chiusa non resta citata;
- **ogni `TargetKind` del contratto ha una minaccia che ne esercita il perimetro**, come ogni kind ha il suo validatore.

## Principi

1. **Una prova riproduce l'operazione che la difesa deve impedire.** Si apre il file in scrittura, non si legge il suo modo.
2. **Ogni rifiuto è preceduto dal suo controllo positivo**: la stessa sonda, nella condizione in cui deve riuscire. È la regola di `bin/hermes-collauda-percorsi`. Se il controllo positivo fallisce, l'esito è *non verificabile*, mai *tiene*.
3. **Aprire, non scrivere.** La scrivibilità si prova aprendo con `O_WRONLY|O_APPEND|O_NOFOLLOW` e chiudendo senza scrivere; la creabilità in una directory con `O_TMPFILE`, che non lascia nomi.
4. **Dove il tentativo stesso sarebbe distruttivo, si usa un'esca.** Troncare il log vero per vedere se `+a` lo impedisce lo cancellerebbe se la difesa mancasse. Si legge l'attributo sul vero e si tenta su un'esca con lo stesso attributo. La voce è marcata *indiretta*.
5. **Mai un tool vero.** Lungo la catena si invocano solo i canary di `hermes-assess`. I bersagli di prova stanno in `192.0.2.0/24` (RFC 5737) o su loopback.
6. **Non esce nulla, e non è una promessa.** Il giro gira in un'unità transiente con `IPAddressDeny=any` e `IPAddressAllow=localhost`. Le vulnerabilità note si consultano dal PC a partire da un inventario esportato.
7. **Non distruttivo e autoripristinante.** Non ricarica `sshd`, non tocca `ufw` né la rete, **non alza tier** (l'innalzamento è irreversibile dall'interfaccia).
8. **Se una prova riesce dove doveva fallire**, ciò che ha creato si annulla, l'esito è *cede* con l'evidenza dell'annullamento, e il giro **continua**.
9. **L'esito è deterministico.** Nessun modello decide *tiene* o *cede*.
10. **La copertura è dichiarata.** Una prova locale gira sull'host sorvegliato, e un root compromesso può mentirle: il referto lo dice in testa.

## Il referto

Schema in [`mcp_server/assess/referto.py`](../mcp_server/assess/referto.py), versione `hermes-assess/1`.

- **I dati raccolti dalla macchina non sono fidati.** Nomi di file, di unità, righe di log: i caratteri di controllo, di formato e di direzione bidirezionale diventano `\uXXXX` visibili, e oltre 512 caratteri il valore è tagliato con il taglio dichiarato. La pulizia avviene alla costruzione dell'evidenza, non alla stampa.
- **Gravità nel contesto.** Ogni voce porta la gravità di base e quella sulla macchina, con i modificatori applicati scritti: per esempio, un tool registrato con un bersaglio vero alza le minacce sul confine dei tool.
- **Codici d'uscita distinti, non un massimo:**

| Codice | Significato |
|---|---|
| 0 | nessun cedimento, e nessuna minaccia alta o critica non verificabile |
| 1 | almeno un cedimento non accettato |
| 2 | nessun cedimento, ma almeno una minaccia alta o critica non verificabile |
| 3 | `hermes-assess` non ha potuto girare |

Un cedimento contro una voce **ACCETTATA** del registro del debito è *accettato* e non conta. Uno contro una voce **aperta** resta un cedimento, con il rimando alla voce.

## Uso

```sh
cd /opt/hermes-core
sudo bin/hermes-assess config/hermes.toml           # referto leggibile
sudo bin/hermes-assess config/hermes.toml --json    # referto JSON
sudo bin/hermes-assess config/hermes.toml --solo AS-03,AS-06
```

Il lanciatore rifiuta di partire senza root e senza systemd: senza unità il limite di rete non si applicherebbe. Il codice d'uscita è quello della tabella sopra, letto dall'unità: `systemd-run --wait` restituirebbe 1 per qualunque fallimento, e un giro mai partito sembrerebbe un giro con cedimenti.

`python -m mcp_server.assess` esegue il giro senza unità e senza discesa di identità. Serve ai test; il referto lo dichiara.

### Registrare i canary su una macchina già installata

Il bootstrap non tocca un `hermes.toml` esistente, e lo SHA di un tool aggiunto dopo si scrive a mano. Si copiano i blocchi `assess.canary` (e `assess.canary_host` se il perimetro ha almeno un alias) da `config/hermes.example.toml`, con `owner_agent` uguale a `server.agent`, e:

```sh
sha256sum agents/assess_canary/run.py
```

Dopo l'aggiornamento del repo va rilanciato `sudo bin/hermes-bootstrap`, come per ogni aggiornamento. Il servizio legge il repo **solo tramite il gruppo**, e `git` crea `agents/assess_canary/` con il gruppo primario di chi aggiorna: senza il bootstrap il gate non raggiunge lo script e lo dichiara assente. L'ACL di default di `agents/` copre `hermes-tool`, che esegue lo script, non il gruppo del servizio, che ne verifica lo SHA. Trovato al primo collaudo. Il preflight segnala il caso per ogni tool registrato.

### Collaudo sulla VM: vedere ogni prova cedere

Prima del merge ogni prova si vede **dire no**. Sulla VM del server, dopo aver registrato i canary:

1. `sudo bin/hermes-assess config/hermes.toml --solo AS-03,AS-05,AS-06`: le tre voci *tiene*.
2. **AS-03 cede.** Si apre `state_dir` all'utente dei tool, con due voci ACL e senza toccare i bit:
   ```sh
   sudo setfacl -m u:hermes-tool:--x /var/lib/hermes
   sudo setfacl -m u:hermes-tool:rwx /var/lib/hermes/state
   sudo bin/hermes-assess config/hermes.toml --solo AS-03      # atteso: CEDE su state_dir, uscita 1
   sudo setfacl -x u:hermes-tool /var/lib/hermes/state
   sudo setfacl -x u:hermes-tool /var/lib/hermes
   sudo bin/hermes-assess config/hermes.toml --solo AS-03      # di nuovo TIENE
   ```
3. **AS-06 senza controllo positivo.** Si registra `assess.canary_host` con un `exec_sha256` sbagliato: il gate rifiuta anche il bersaglio dentro il perimetro, e la voce deve dire *non verificabile*, non *tiene*. Poi si rimette lo SHA giusto.
4. **Il giro mai partito.** `sudo bin/hermes-assess /tmp/non-esiste.toml; echo $?` deve stampare 3, non 1. Il ramo in cui `systemd-run` stesso fallisce è stato visto su una macchina senza systemd come PID 1: anche lì 3.

AS-05 cede solo con un difetto del server (una riga di traccia che manca): sulla macchina non lo si provoca, e la suite lo esercita con righe costruite.

## Architettura (M1)

```
operatore ──sudo──► bin/hermes-assess   (unità transiente, IPAddressDeny=any)
                     ├─ contesto: config col caricatore del server, utenti, commit
                     ├─ prove, una per modulo in mcp_server/assess/prove/
                     │    ├─ sonde sotto ogni identità (setpriv)
                     │    ├─ sonde dal wrapper installato (proprietà dell'unità)
                     │    └─ catena via stdio: server → gate → wrapper → assess.canary*
                     ├─ valutazione come DynamicUser, senza privilegi
                     └─ referto.json + testo in /var/lib/hermes-assess/<data>/ (0600)
```

- **Lo lancia l'operatore**, non un agente e non MCP: serve root. Gira dal repo, con l'interprete assoluto e `-I`; il referto registra il commit e se l'albero di lavoro era pulito.
- **I canary passano dal registro.** `assess.canary` (`target_kind = "none"`) e `assess.canary_host` (`target_kind = "host"`) sono registrati in modo permanente come Verdi in ogni istanza, con lo script in `agents/assess_canary/` condiviso, la cui ACL la aggiunge il bootstrap. `assess.canary_host` prende stabilmente il ruolo di collaudo del perimetro che oggi ha `echo.bersaglio`, destinato a essere rimosso.
- **L'elenco atteso dei file `.pth`** si genera dal lock al momento dell'installazione, non si mantiene a mano.

## Piano

| Passo | Contenuto |
|---|---|
| M0 | questo documento, catalogo, schema del referto |
| M1.1 | canary e loro registrazione; prove sul confine dei tool, sulla traccia e sul perimetro |
| M1.2 | prove sotto le identità di servizio: SSH, interprete, log, sudoers, codice privilegiato, utenti |
| M1.3 | unità, rete, superficie, coerenza del log, orologio, tier; valutazione, modificatori, `--prova` |
| M1.4 | inventario e `bin/hermes-assess-vuln` sul PC |
| M1.5 | adattatori per strumenti esterni che girano offline (lynis, trivy con database copiato) |
| M2 | baseline e scostamento, referto spedito al collector |
| M3 | prove dal collector: superficie vista dall'esterno, confronto della copia del log |
| M4 | skill `/assess-review` di Hermes sul PC |

**Ogni prova della M1 si vede cedere su una VM di collaudo prima del merge**: una prova che non si è mai vista dire *cede* non ha dimostrato di poterlo dire.

### Strumenti esterni (M1.5)

Un adattatore dichiara il binario, la versione minima e se gli serve la rete, e se gli serve sul server non gira. Le sue voci portano l'origine (`lynis 3.x`) e restano distinte dalle prove: uno strumento esterno dice *è configurato male*, una prova dice *la difesa cede*. Se lo strumento non è installato la voce è *non applicabile*: `hermes-assess` non installa niente.

### Strato agentico (M4)

Una skill di Hermes, `/assess-review`, sul PC. Legge `referto.json` con un modello locale: il referto è la mappa delle debolezze della macchina, e non lascia il PC. Spiega, ordina per priorità e mette nel contesto. **Non esegue niente, non cambia gli esiti e non inventa rimedi**: quelli sono nel catalogo, collaudati insieme alla prova, e un comando proposto in alternativa va marcato *non collaudato*. L'agente non lancia `hermes-assess`: richiede root, e un agente con quella capacità sarebbe un modello a un passo da root.
