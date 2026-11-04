# Platform sync, 28 Oct 2026

Attendees: Dev, Sari, Marcus

- Staging DB migration (#482) blocked on argon2 rollout; Marcus to pair with Dev Thursday.
- Stripe webhook retries: add idempotency key on `invoice.paid`, ship behind flag.
- CSV export: done, waiting on review.
- Reminder: rotate the shared S3 keys before the audit on 14 Nov.

Action items
- [ ] Dev: open PR for argon2 migration
- [ ] Sari: write runbook for failed webhook replay
- [x] Marcus: bump node to 22 on CI
