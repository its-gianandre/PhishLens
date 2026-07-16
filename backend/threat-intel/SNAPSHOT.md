# Bundled PhishTank snapshot

PhishLens uses a static PhishTank dataset snapshot because new PhishTank
account registration and application-key creation were unavailable when this
integration was prepared.

## Provenance

- Snapshot date: `2026-07-16`
- Source mirror: `https://github.com/ProKn1fe/phishtank-database`
- Source file: `online-valid.json`
- Source JSON SHA-256:
  `2B646286A2DD83EA88747C252D91E6D3D1BBD5190F4788EC2944FD118EC14E22`
- Bundled gzip SHA-256:
  `C5ACA527E61CC2A6B052D96FF2887A6F247F5AB6918EEEA5F7C51A1E5906C2A8`
- Raw records: `64,872`
- Accepted verified/online records: `64,872`
- Unique normalized URLs: `64,564`
- Unique hostnames: `32,554`

The source repository describes itself as a PhishTank database mirror updated
every 24 hours. It is not operated by PhishTank, Cisco, or PhishLens.

## Limitations

This snapshot is immutable and becomes less current over time. A match means
the URL appeared in the verified/online PhishTank snapshot on the snapshot
date. A missing match does not establish that a URL is safe. URLs in the
snapshot may subsequently go offline, be remediated, or change ownership.

The dataset is treated as untrusted input. PhishLens never visits any URL in
the snapshot.
