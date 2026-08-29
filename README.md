# Authorization Contract

Portable PHP 8.3 values describing who is acting, the explicit tenant/isolation scope, and a domain-owned authorization decision. The package carries context; it does not grant permissions or centralize domain policy.

Contexts contain durable references only. Session tokens, provider credentials, and other secrets are not fields in the contract.

## Verification

```sh
composer test
```

The command covers same-tenant permission, cross/wrong-tenant denial, missing-actor fail-closed behavior, disclosure-safe denial, service acting-for-user, and JSON/queue round trips with no credential fields.
