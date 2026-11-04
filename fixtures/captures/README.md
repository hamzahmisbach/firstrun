# Real captures

`basic/` is the raw output of one real run on the VM (Docker, gVisor `runsc`, sinkhole), with the exact
flags from `docs/ARCHITECTURE.md` 5.1 and 6.2. The credential in it is the fixed fake token
`FRCAPTUREFIXTURETOKEN234`, and the shim canary is `FRCAPTURESHIMTOKEN234567`.

- `trace.jsonl`: what `infra/gvisor-sink/gvisor-sink.py` wrote for the sandbox container.
- `events.jsonl`, `dns.log`, `tcp.jsonl`: what the sinkhole wrote.
- `stdout.txt`, `stderr.txt`, `run_id.txt`, `container_id.txt`: the rest of that run.

Use these as test input for the evidence code instead of hand-written records.
