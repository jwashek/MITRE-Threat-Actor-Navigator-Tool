import requests
import json
from collections import defaultdict

MITRE_JSON_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
LAYER_TEMPLATE = "https://attack.mitre.org/groups/{group_id}/{group_id}-enterprise-layer.json"
NAVIGATOR_TEMPLATE = "https://mitre-attack.github.io/attack-navigator//#layerURL=" + LAYER_TEMPLATE

def get_mitre_dataset():
    r = requests.get(MITRE_JSON_URL)
    r.raise_for_status()
    return r.json()

def build_technique_tactic_map(dataset):
    """Returns a mapping of technique_id → {name, tactics[]}"""
    mapping = {}
    for obj in dataset["objects"]:
        if obj.get("type") in ["attack-pattern"]:
            tech_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("T"):
                    tech_id = ref["external_id"]
            if not tech_id:
                continue

            name = obj.get("name", "")
            tactics = [p["phase_name"].title() for p in obj.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"]
            mapping[tech_id] = {
                "name": name,
                "tactics": tactics or ["Unknown"]
            }
    return mapping

def get_group_id(threat_name, dataset):
    name = threat_name.lower()
    for obj in dataset["objects"]:
        if obj.get("type") == "intrusion-set":
            if any(name == alias.lower() for alias in obj.get("aliases", [])):
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack" and ref.get("external_id", "").startswith("G"):
                        return ref["external_id"]
    return None

def fetch_layer(group_id):
    url = LAYER_TEMPLATE.format(group_id=group_id)
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

def print_techniques_by_tactic(layer_json, technique_map, filter_tactic=None):
    tactic_buckets = defaultdict(list)

    for entry in layer_json["techniques"]:
        tid = entry["techniqueID"]
        comment = entry.get("comment", "").strip()

        # Some entries may not exist in map (very rare)
        if tid not in technique_map:
            tactic_buckets["Unknown"].append((tid, "Unknown", comment))
            continue

        info = technique_map[tid]
        for tactic in info["tactics"]:
            if filter_tactic and filter_tactic.lower() != tactic.lower():
                continue
            tactic_buckets[tactic].append((tid, info["name"], comment))

    if not tactic_buckets:
        print("❌ No techniques matched your filter.")
        return

    print(f"\n📊 Techniques used by {layer_json['name']}:\n")

    for tactic in sorted(tactic_buckets):
        print(f"=== {tactic} ===")
        for tid, name, comment in tactic_buckets[tactic]:
            print(f"🔹 {tid} - {name}")
            if comment:
                print(f"    📝 {comment}")
        print()

def main():
    threat_actor = input("Enter a Threat Actor name (e.g., FIN10): ").strip()
    mitre_data = get_mitre_dataset()
    technique_map = build_technique_tactic_map(mitre_data)

    group_id = get_group_id(threat_actor, mitre_data)
    if not group_id:
        print("❌ Group not found.")
        return

    print(f"\n✔ Found Group ID: {group_id}")
    print("📎 ATT&CK Navigator Link:")
    print(NAVIGATOR_TEMPLATE.format(group_id=group_id))

    layer_json = fetch_layer(group_id)
    if not layer_json:
        print("❌ Could not retrieve ATT&CK Navigator layer.")
        return

    filter_tactic = input("\n(Optional) Filter by tactic (e.g., Execution). Press Enter to show all: ").strip()
    print_techniques_by_tactic(layer_json, technique_map, filter_tactic if filter_tactic else None)

if __name__ == "__main__":
    main()
