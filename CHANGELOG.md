# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries that change what a *result* means — the position, the verdict, the score,
or what is redacted — are marked **[result-affecting]**. If you have produced
reports with an earlier version, read those entries.

---

## [2.0.0] — 2026-08-10

First public release.

### Added

- Apple Location Services client. Hand-rolled protobuf codec; harvests up to
  **400** neighbouring access points per enquiry.
- Microsoft Location Inference client, as an independent second opinion:
  per-access-point cross-checks and replicated multilateration over disjoint
  groups.
- Cross-validation and a confidence score with an explicit rubric, weights
  renormalised over the checks that actually ran.
- Evidence packaging: every HTTP transaction preserved verbatim in both
  directions, SHA-256 per file, a manifest root hash, and a standalone
  `verify_evidence.py` that ships inside the package.
- Self-contained HTML and PDF reports; annotated map as PNG and SVG; CSV,
  GeoJSON and KML exports. No imaging or PDF library — both codecs are part of
  the project.
- Local web interface (`http.server`, loopback-only, token and CSRF protected).
- Address ingestion: saved `netsh` output and plain address lists,
  `netsh` output, and Kismet / WiGLE / SIEM CSV.
- `--redact` writes a distributable copy: vendor-prefix-only addresses,
  truncated coordinates, no street address, no map, no examiner or host details.
  It still quotes the evidence root hash so a recipient can tie it back.
- `--host-artefacts` recovers and locates the networks this machine has joined.
- Portable Windows distribution with an embedded CPython, published on the
  releases page.
- Test suite (159 tests) and CI across Linux and Windows on Python 3.9–3.14.
- Portable distribution bundles the current stable CPython (3.14.7 at release).

### Fixed

The following were found by testing against the live services, and each produced
a **plausible but wrong** answer rather than an error:

- **[result-affecting]** Neighbour harvesting was capped at one access point.
  Every public implementation copies a request fragment ending `\x18\x00\x20\x01`;
  that trailing field is the neighbour count. Omitting it returns 400.
- **[result-affecting]** Microsoft's IP fallback was being fused into the
  position. When Microsoft holds no record for the submitted beacons it silently
  answers with a location derived from the examiner's own internet connection,
  flagged only by `Source="IP"`. It looked like independent corroboration; it
  described the examiner. Now detected and discarded.
- **[result-affecting]** A verdict of `CORROBORATED` could be reported when no
  cross-check had actually run. Capped at `SINGLE-SOURCE`.
- **[result-affecting]** `netsh` import assigned the wrong network name: any
  `key : value` line was treated as the SSID, so an access point listed under
  `Authentication : WPA2-Personal` was recorded as being on a network of that
  name.
- **[result-affecting]** CSV import preferred whichever address appeared
  leftmost, so a SIEM export carrying `LocalMac` before `PeerMac` geolocated the
  examining host instead of the access point.
- **[result-affecting]** GUIDs in registry and event exports were parsed as MAC
  addresses, inventing access points that never existed.
- Geohash disagreed with every other implementation for coordinates lying
  exactly on a cell boundary (`>` where the convention is `>=`).
- Randomised-MAC collisions across unrelated devices are detected and excluded
  rather than averaged into the position.
- The redacted report is rendered after sealing, so it can quote the root hash;
  its filesystem paths, which carry the operator's account name, are dropped.

### Security

- The redacted copy rebuilds Plus Code, MGRS, UTM, geohash and DMS rather than
  pattern-matching them. Each is a lossless encoding of the position, so masking
  only the decimal pair published the location anyway.
- An installed copy no longer writes case evidence into `site-packages`, where a
  `pip` upgrade or uninstall would destroy it.

[2.0.0]: https://github.com/akhil-dara/wifi-geolocation-forensics/releases/tag/v2.0.0
