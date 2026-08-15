# Contributing

Thanks for considering it. This document is short, and most of it is about two
constraints that are unusual enough to be worth stating plainly before you write
any code.

---

## 1. There are no dependencies, and there will not be

The tool is written against the CPython standard library alone. The protobuf
codec, the PNG encoder, the PDF writer, the HTTP client, the map renderer and the
web server are all part of this project.

That is not minimalism for its own sake. The output of this tool is intended to
be evidential. A dependency is a third party who can change what your
evidence-generating code does between one run and the next — and findings may
already be in a report, a statement, or a court file. It also keeps the portable
build under 10 MB and lets it run on an air-gapped analysis host with nothing
installed.

CI enforces this: a job walks every import in `wifigeo/` and fails on anything
outside `sys.stdlib_module_names`.

If you are convinced a dependency is genuinely necessary, open an issue *before*
writing the code and make the case. The usual outcome is that we write the twenty
lines instead, and the usual reason is that twenty lines we can read beat fifty
thousand we cannot.

**Test tooling is the one exception in spirit but not in practice:** the suite is
plain `unittest` and runs on a bare interpreter. `pytest` works if you prefer it,
but nothing may *require* it.

---

## 2. Never commit real data

This is a tool whose input is somebody's hardware address and whose output is
somebody's front door. The repository must never contain either.

Before you commit, check that you have not included:

- a real BSSID or MAC address — use the range **RFC 7042 §2.1.2** reserves for
  documentation, `00:00:5E:00:53:00`–`FF`
- a real coordinate, Plus Code, MGRS, UTM or geohash — these are all lossless
  encodings of a position, and redacting the decimal pair while leaving the Plus
  Code publishes the location anyway
- a real SSID, street address, postcode or city tied to a person
- a hostname, username or home-directory path
- an evidence package, report, host artefact or network capture

`.gitignore` covers the obvious cases and CI fails the build on a MAC address
outside the documentation range, but neither is a substitute for looking.

If you need sample data, use the documentation range above. The protocol tests
in `tests/test_protocol.py` carry small sanitised request and response bodies
inline.

---

## Running the tests

```bash
python -m unittest discover -s tests -v
```

No installation, no network, no wireless radio required. On Linux and macOS use
`python3`.

```bash
python -m wifigeo --version          # smoke test
python -m wifigeo --help
```

---

## House style

The code is commented more heavily than most, and deliberately so — the comments
explain **why**, not what. Several of them record a specific wrong answer this
tool used to give, and what the wire actually does. Please match that:

- Explain the reasoning, not the mechanics. `# increment i` helps nobody.
- If you fixed a bug that produced a *plausible but wrong* result, say so in a
  comment. Those are the dangerous ones, and the next person needs to know the
  trap is there. Look at `msft.InferenceResult.ip_fallback` for the standard.
- British spelling in prose and comments (`normalise`, `behaviour`, `artefact`).
- Four-space indents, roughly 79 columns, no trailing whitespace.
- Type hints on public functions.

---

## Protocol changes

`wifigeo/apple.py` and `wifigeo/msft.py` implement undocumented, reverse
engineered wire formats. Both are fragile in a specific way: **a broken request
does not raise — it returns fewer results, or a position derived from the wrong
thing.** A regression here is silent.

If you change either:

1. Add a test to `tests/test_protocol.py` pinning the new behaviour.
2. Say in the commit message how you verified it against the live service.
3. Do not remove the existing byte-layout assertions. The four-byte big-endian
   length prefix in the Apple envelope is read as padding by every public
   implementation, and that mistake caps the response at one access point
   instead of four hundred.

---

## Reporting a bug

Please read `SECURITY.md` first if it involves a vulnerability rather than a
defect.

For an ordinary bug, the issue templates ask you to redact your data. Please
actually do it — an unredacted bug report is a disclosure of a real location,
and the issue tracker is public and indexed. `--redact` produces a report you
can attach safely.
