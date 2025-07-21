# MITRE ATT&CK Threat Actor Navigator Tool

A command-line Python tool that allows you to search for threat actors tracked by [MITRE ATT&CK](https://attack.mitre.org/groups/), automatically fetches their ATT&CK Navigator layer, and displays their techniques grouped by tactic (e.g., Execution, Persistence, Lateral Movement).

## 🚀 Features

- 🔍 Search any known MITRE threat actor by name or alias (e.g., `FIN10`, `APT1`, `TA505`)
- 🧠 Automatically resolves and fetches the correct ATT&CK Group ID (e.g., `G0051`)
- 📎 Generates a Navigator link to visualize the threat actor’s techniques in the ATT&CK Navigator
- 🧰 Displays all techniques used by the actor, grouped by kill chain phase (tactic)
- 🧹 Optional filtering by tactic (e.g., only show `Execution` or `Persistence` TTPs)
- 🗂 Organized and readable console output
- ✅ Uses official MITRE STIX data from [github.com/mitre/cti](https://github.com/mitre/cti)

---

## 🛠 Requirements

- Python 3.7+
- [Requests](https://pypi.org/project/requests/)


### Install dependencies:
```bash
pip install requests
```

## Usage:
```bash
python attack_navigator_intel.py
```

## Example:
```bash
Enter a Threat Actor name (e.g., FIN10): fin10

✔ Found Group ID: G0051
📎 ATT&CK Navigator Link:
https://mitre-attack.github.io/attack-navigator//#layerURL=https://attack.mitre.org/groups/G0051/G0051-enterprise-layer.json

(Optional) Filter by tactic (e.g., Execution). Press Enter to show all:

📊 Techniques used by FIN10 (G0051):

=== Execution ===
🔹 T1059.001 - PowerShell
    📝 FIN10 uses PowerShell for execution and persistence via PowerShell Empire.

=== Persistence ===
🔹 T1547.001 - Registry Run Key
    📝 FIN10 has added registry Run keys to establish persistence.

...
```

## Data Sources:
This project pulls live data from:

* [MITRE ATT&CK STIX](https://github.com/mitre/cti/tree/master/enterprise-attack) (enterprise-attack.json)
* [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)

> Note: This project is open-source under the MIT License. MITRE ATT&CK data is used under the terms of their [license](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
