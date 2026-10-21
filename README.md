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

## Stato

Milestone 0 — scaffolding in corso. Nessun tool di sicurezza reale è ancora integrato.

## Licenza

MIT — vedi [LICENSE](LICENSE).
