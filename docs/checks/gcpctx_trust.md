# Doctor check: `gcpctx_trust`

See [Doctor JSON contract](../doctor-contract.md) for exit codes and JSON shape.

Run `gcpctx doctor --strict --json` and inspect the check with `id` equal to `gcpctx_trust`.

This check compares the live gcpctx identity triple (resolved launcher, `sys.executable`, and package origin or dist RECORD hash) against the pins stored on a matching approval. A mismatch fails with exit code 6. Re-approve after moving or replacing the launcher, interpreter, or package.
