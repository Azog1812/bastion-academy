## What & why

## Security checklist
- [ ] New input is validated by a strict schema (unknown fields rejected)
- [ ] Every new query is parameterised and owner-scoped where relevant
- [ ] Authorization is enforced server-side for every new route
- [ ] No secret, token or personal data is logged or returned
- [ ] Tests cover the abuse case, not only the happy path
- [ ] Threat model / ASVS mapping updated if the attack surface changed
