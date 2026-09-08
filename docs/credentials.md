# Runner-local credentials

Provision protected target contexts locally, never through BADASS Cloud:

```sh
badass-runner cred set --target-ref TARGET_ID --context admin --auth-type bearer
badass-runner cred list
badass-runner cred remove --target-ref TARGET_ID --context admin
```

`cred set` reads a secret from a hidden prompt by default.  Automation may use
`--secret-stdin` or `--secret-env-file PATH`; there is intentionally no secret
command-line argument.  Values are stored only in the OS keyring.  The local
0600 JSON index has target/context references and auth metadata only.

For schema-3 Mode-2 enforcement jobs, BADASS Cloud sends only an opaque target
scope and opaque credential references. The runner binds those references to
the job target, resolves them from this local store, constructs request headers
in memory, and uploads only sanitized observations. Credential values never
enter the job wire or cloud persistence.

This boundary is covered by the R6 end-to-end planted-secret capstone: raw and
derived credential forms are asserted absent from the schema-3 wire, uploads,
cloud persistence, and runner/backend logs while the controlled target proves
receipt by digest. Missing references fail before target HTTP.

Runner onboarding is separate and token-only: use
`badass-runner start --token …` with an account-owned one-time registration
token. There is no pairing or browser-login path.