# hermes-core

Scaffolding condiviso della **toolbox multi-agente difensiva Hermes**.

Questo repository contiene il nucleo comune su cui poggiano gli agenti della toolbox:
l'**orchestratore** minimo, il **server MCP** con il contratto di registrazione dei
tool (risk tier tecnico + flag dati personali + override utente), il **logging
strutturato JSONL** e l'**interfaccia vault** per le credenziali.

Non è uno strumento d'uso diretto: è il prerequisito (Milestone 0) che abilita gli
agenti operativi delle milestone successive (vulnerability assessment, pentest/Kali
containerizzato).

## Natura del progetto

Hermes è una **toolbox difensiva di postura di sicurezza**, sviluppata come progetto
formativo nell'ambito di un percorso ITS in reti e sicurezza informatica (Pisa). Lo
scopo è automatizzare e rendere ripetibili attività di **assessment difensivo** su
sistemi di proprietà dell'autore: inventario della superficie esposta, verifica della
configurazione di sicurezza, rilevamento di vulnerabilità note, hardening guidato e
produzione di report.

Hermes **non è** uno strumento offensivo. Non contiene, non genera e non è destinato a
contenere exploit, payload, codice di persistenza, tecniche di evasione o capacità di
attacco verso sistemi terzi.

## Uso autorizzato e responsabilità

La toolbox è destinata **esclusivamente** ad attività di sicurezza autorizzate, su
target per cui esiste un mandato esplicito:

- macchine virtuali di laboratorio di proprietà dell'autore, su hypervisor locale;
- host per i quali l'autore detiene titolarità diretta o autorizzazione scritta
  esplicita del proprietario.

È fuori perimetro, in modo non negoziabile, qualsiasi sistema, rete o servizio di
terzi non autorizzato. Lo strumento non è progettato per commettere illeciti; l'autore
declina ogni responsabilità per l'uso malevolo da parte di terzi. Quando strumenti
OSINT operano su persone fisiche, l'operatore resta titolare del trattamento ai sensi
del GDPR.

## Struttura del repository

```
hermes-core/
├── mcp_server/        # server MCP: registry tool, risk tier, vault, logging
├── agents/
│   ├── orchestrator/  # orchestratore minimo (invoca un agente, riceve risultato)
│   └── echo_agent/    # agente dummy conforme al contratto (per i test e2e)
├── config/            # *.example.yaml versionati; copie reali ignorate
├── logs/              # log d'audit JSONL a runtime (non versionati)
└── tests/             # unit + end-to-end
```

## Requisiti

- Python >= 3.11
- Dipendenze in `pyproject.toml` (`mcp`, `pydantic`)

## Setup sviluppo

```sh
python3 -m venv .venv
source .venv/bin/activate      # su zsh/bash
pip install -e ".[dev]"
pytest
```

I test marcati `slow` avviano processi veri e dialogano in MCP su stdio
(~1,5 s l'uno). Durante l'iterazione:

```sh
pytest -m "not slow"
```

## Provare la catena

```sh
cp config/hermes.example.toml config/hermes.toml
python -m mcp_server.doctor config/hermes.toml     # preflight
bin/hermes-core-server                             # resta in attesa su stdio
```

Il **preflight** verifica configurazione, percorsi, permessi del log,
integrità degli script e handshake MCP reale, e dice cosa fare per ogni
problema che trova. Vale la pena eseguirlo prima di cercare un guasto
altrove.

Il server non è pensato per essere usato a mano: parla il protocollo MCP sul
proprio stdin/stdout e si aspetta un client. L'orchestratore in
`agents/orchestrator/` è il client minimo che lo avvia, lo interroga e ne
valida il risultato.

Per il dispiegamento e la registrazione in Hermes desktop:

- [docs/setup-vm-hermes.md](docs/setup-vm-hermes.md) — preparazione della VM
  dedicata: utenti, permessi, chiave SSH vincolata a un comando unico.
- [docs/integrazione-hermes.md](docs/integrazione-hermes.md) — registrazione
  in Hermes e diagnostica.

L'architettura di riferimento tiene il server su una **VM dedicata**, separata
dalle macchine che la toolbox analizza: l'orchestratore custodisce il log
d'audit, il vault e i controlli di scope, e un log che risiede sul bersaglio
vale meno di uno che risiede altrove.

## Stato

**Milestone 0 completa**, salvo l'integrazione con Hermes desktop.

Funziona la catena orchestratore → agente → gate di esecuzione → script →
log d'audit, con un unico `correlation_id` dall'invocazione alla riga finale.
L'unico tool registrato è un dummy: **nessun tool di sicurezza reale è ancora
integrato**.

Le lacune di sicurezza note e consapevolmente non ancora chiuse sono elencate
in [docs/debito-sicurezza.md](docs/debito-sicurezza.md), ciascuna con la
propria condizione di chiusura.

## Licenza

MIT — vedi [LICENSE](LICENSE).
