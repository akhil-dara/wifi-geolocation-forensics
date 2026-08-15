# Security and responsible use

## Reporting a vulnerability

Please report security issues privately, through GitHub's
[Private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
on this repository — **not** as a public issue.

Expect an acknowledgement within a few days. If a fix is warranted, we will agree
a disclosure timeline with you and credit you in the release notes unless you
would rather we did not.

**When reporting, redact your own data.** A proof of concept for this tool
naturally contains a real hardware address and a real position. Use the
documentation range `00:00:5E:00:53:00`–`FF` and a neutral coordinate, or attach
a `--redact` report.

### What counts as a vulnerability here

Ordinary categories apply — the local web interface, path handling, the ZIP
writer, XML parsing. Beyond those, this project treats the following as security
issues rather than bugs, because of what the tool is for:

- **Redaction failure.** Any input for which `--redact` leaves a full hardware
  address, a full-precision coordinate, a derived encoding of one (Plus Code,
  MGRS, UTM, geohash), a street address, or the examiner's identity or paths in
  the output.
- **Evidence integrity failure.** Any way to modify a sealed package without
  `verify_evidence.py` reporting it, or to make the manifest or root hash
  disagree with the files it covers.
- **Silent misattribution.** Any input that makes the tool position the wrong
  thing while still reporting confidently — an IP-derived answer accepted as a
  Wi-Fi fix, a client adapter geolocated as an access point, or a response
  attributed to a request it did not answer. A wrong answer that *looks* right
  is worse than a crash, because it reaches a report.

## What this tool sends, and to whom

Run it and you contact these services. There are no API keys and no accounts, but
that does not make the traffic invisible.

| Service | What it receives | When |
|---|---|---|
| `gs-loc.apple.com` | the access point addresses you are enquiring about | every run |
| `inference.location.live.net` | the same addresses, as a beacon fingerprint | unless `--no-microsoft` |
| `nominatim.openstreetmap.org` | the resolved coordinates | unless `--no-enrichment` |
| `overpass-api.de`, `photon.komoot.io` | the resolved coordinates | unless `--no-enrichment` |
| `tile.openstreetmap.org` | the resolved coordinates | unless `--no-tiles` |
| `api.mylnikov.org`, `wifidb.net` | the access point addresses | corroboration lookups |

Implications worth understanding before you run this on a live matter:

- **The enquiry itself is disclosed.** Apple and Microsoft learn which access
  point you are interested in, and when. If the subject of your investigation
  can see those logs, your enquiry is not covert.
- **Your own network is exposed by default in one specific way.** When Microsoft
  cannot position your beacons it returns a location derived from *your* IP
  address instead. The tool detects and discards that (see
  `msft.InferenceResult.ip_fallback`), but the request still happened from your
  connection.
- **`--send-device-profile` identifies your machine** to Microsoft. It is off by
  default for that reason.
- **Nothing is sent anywhere else.** No telemetry, no analytics, no crash
  reporting. The tool never phones home.

Use `--no-microsoft`, `--no-enrichment` and `--no-tiles` to narrow the footprint,
at the cost of corroboration and context.

## Responsible use

This tool locates physical places from hardware identifiers. That is a
legitimate and often necessary thing to do in incident response, threat
intelligence and criminal investigation — and it is also the mechanism of
stalking.

You are responsible for having lawful authority for what you look up. Wireless
positioning data is personal data in most jurisdictions, and the fact that Apple
and Microsoft answer without a credential is not authorisation.

Please do not use it to locate a person without a lawful basis. If someone has
asked you to look up "their own" access point and you cannot verify that, assume
the worst case.

`--host-artefacts` and `--import` recover a Windows host's history of every
network it has joined, with dates. On a subject machine that is a movement
history. Treat it with the care that implies.
