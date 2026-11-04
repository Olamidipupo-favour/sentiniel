# Safe infected fixture

This directory models the repository indicators without containing the real payload. The `.orc`
file is inert text, and Sentiniel must inspect it without executing it.

```sh
docker build -t sentiniel .
docker run --rm sentiniel scan --path /fixtures/infected --format json --fail-on high
```
