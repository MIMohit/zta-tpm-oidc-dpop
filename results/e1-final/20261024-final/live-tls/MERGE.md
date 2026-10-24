# Merged live E1 results

`attacks-merged.jsonl` = `attacks.jsonl` with 4 trials that failed to start (PEP health check failed
while the stack was starting, configuration -M5) replaced by a re-run of the same attack, variant and configuration
(`../live-tls-rerun/attacks.jsonl`, same code, same host). Replaced rows carry `rerunOf` = timestamp of the
original row. No other row differs.
