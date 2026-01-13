# CTI Data (Offline)

This project uses **MITRE ATT&CK Enterprise CTI** in **STIX 2.1** format (attack-stix-data).

Place the Enterprise ATT&CK STIX bundle here as:

- `data/cti/enterprise-attack.json`

The backend TTP similarity module loads this file to build:

- `Intrusion Set -> Techniques` mapping
- `idf(t)` weights for TF-IDF + cosine similarity

