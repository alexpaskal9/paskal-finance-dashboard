# Paskal Finance Dashboard

Public GitHub Pages shell with **AES-256-GCM encrypted financial payloads**.

- Live: https://alexpaskal9.github.io/paskal-finance-dashboard/
- UI code is public.
- `business.enc` and `personal.enc` are encrypted ciphertext.
- The passphrase is not stored in this repository.
- Optional “remember this device” stores the passphrase for 30 days encrypted under a non-exportable AES key held in that browser's IndexedDB. `?forget=1` clears the remembered unlock.
- Raw invoices, statements, account identifiers, cards, and tax records belong only in the private accounting repository.
- Dashboard data is generated from private CSV ledgers and encrypted locally before each push.

Security details and recovery procedure are maintained in the private tax binder's `DASHBOARD-RUNBOOK.md`.
