# CTI Data (Offline)

This project uses **MITRE ATT&CK Enterprise CTI** in **STIX 2.1** format (attack-stix-data).

Place the Enterprise ATT&CK STIX bundle here as:

- `backend/app/services/ttp_similarity/cti/enterprise-attack.json`

To fetch/update the file automatically, run from repo root:

- `./scripts/fetch_attack_cti.sh`

The backend TTP similarity module loads this file to build:

- `Intrusion Set -> Techniques` mapping
- `idf(t)` weights for TF-IDF + cosine similarity
