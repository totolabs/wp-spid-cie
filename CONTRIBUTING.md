# Contributing

Questo repository adotta un flusso Git standard Totolabs.

## Branch strategy

- `main`: solo codice rilasciato/stabile.
- `develop`: branch di integrazione per sviluppo continuo.
- `feature/*`: nuove funzionalità, **sempre create da `develop`**.
- `fix/*`: bugfix, **sempre creati da `develop`**.

Esempi naming:

- `feature/login-spid-ui`
- `fix/session-timeout`

## Regole operative

- ❌ Non fare push diretto su `main`.
- ✅ Apri Pull Request verso `develop` per ogni `feature/*` o `fix/*`.
- ✅ Usa **Squash and merge** per mantenere una history pulita.
- ✅ Prima di aprire la PR, allinea il branch con `develop` e verifica i check CI.

## Flusso consigliato

1. Aggiorna `develop` locale:
   ```bash
   git checkout develop
   git pull origin develop
   ```
2. Crea il branch di lavoro:
   ```bash
   git checkout -b feature/nome-attivita
   # oppure
   git checkout -b fix/nome-bug
   ```
3. Commit atomici e descrittivi.
4. Push del branch e apertura PR verso `develop`.
5. Merge via **Squash and merge**.
