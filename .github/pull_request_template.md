## What this changes

<!-- One or two sentences. Why, not just what. -->

## Checklist

- [ ] `python -m unittest discover -s tests` passes
- [ ] No third-party imports added (CI enforces this)
- [ ] No real hardware addresses, coordinates, network names, hostnames or
      user paths in the diff — documentation MACs are `00:00:5E:00:53:xx`
- [ ] Comments explain *why*, matching the surrounding style

## If this touches a wire protocol (`apple.py` / `msft.py`)

A broken request here does not raise — it returns fewer results, or a position
derived from the wrong thing. Regressions are silent.

- [ ] Added or updated an assertion in `tests/test_protocol.py`
- [ ] Verified against the live service — say how below

<!-- How you verified it: -->

## If this touches redaction, evidence or scoring

- [ ] `tests/test_redact.py` still passes and covers the new path
- [ ] A sealed package still verifies from a clean extract
