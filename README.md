# Authorization Contract

> **License:** Copyright © 2026 Sifrious. All rights reserved. This is
> publicly viewable proprietary software, not open-source software. See
> [LICENSE.md](LICENSE.md).

Portable PHP 8.3 values describing who is acting, the explicit tenant/isolation scope, and a domain-owned authorization decision. The package carries context; it does not grant permissions or centralize domain policy.

Contexts contain durable references only. Session tokens, provider credentials, and other secrets are not fields in the contract.

## Verification

```sh
composer test
```

The command covers the MME-2072 human-runnable completion gate:

- same-tenant permitted context;
- cross/wrong-tenant denial independently of account identity;
- missing-actor fail-closed behavior;
- service acting-for-user JSON/queue round trip with no credential fields;
- authorization-decision round trip with policy, disclosure, and provenance intact;
- public identity resolution without disclosure of a cross-tenant private relation neighborhood; and
- missing-versus-forbidden disclosure without counts or candidate identities.
