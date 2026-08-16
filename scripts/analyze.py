#!/usr/bin/env python3
"""
Cloud Canary Guard - Script d'analyse de conformité Azure
Détecte : tags manquants, règles réseau trop ouvertes, coûts estimés élevés
Génère : un rapport JSON + un inventaire Ansible pour remédiation
"""

import json
import os
import subprocess
import sys
from datetime import datetime

from azure.identity import AzureCliCredential
from azure.mgmt.resource.resources import ResourceManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.compute import ComputeManagementClient

# --- Configuration ---
RESOURCE_GROUP = "canaryguard-rg"
REQUIRED_TAGS = ["owner", "environment"]
SENSITIVE_PORTS = ["22", "3389"]  # SSH, RDP
COST_THRESHOLD_USD_MONTH = 30  # seuil d'alerte coût

# Tarifs approximatifs USD/mois (région Europe, estimation simplifiée)
VM_PRICE_ESTIMATES = {
    "Standard_B1s": 7.6,
    "Standard_B1ms": 15.3,
    "Standard_B2s": 30.4,
    "Standard_B2s_v2": 31.0,
    "Standard_B2ms": 60.7,
    "Standard_D2s_v3": 70.0,
    "Standard_D4s_v3": 140.0,
}


def get_credentials():
    subscription_id = os.environ.get("ARM_SUBSCRIPTION_ID")
    if not subscription_id:
        print("Erreur: ARM_SUBSCRIPTION_ID n'est pas défini. Fais 'source .env' d'abord.")
        sys.exit(1)
    credential = AzureCliCredential()
    return credential, subscription_id


def check_tags(resource, required_tags):
    """Retourne la liste des tags manquants sur une ressource."""
    tags = resource.tags or {}
    return [t for t in required_tags if t not in tags]


def check_nsg_rules(network_client, resource_group):
    """Détecte les règles NSG trop permissives (source '*' sur ports sensibles)."""
    issues = []
    nsgs = network_client.network_security_groups.list(resource_group)
    for nsg in nsgs:
        for rule in nsg.security_rules:
            if (
                rule.direction == "Inbound"
                and rule.access == "Allow"
                and rule.source_address_prefix in ("*", "0.0.0.0/0", "Internet")
                and (rule.destination_port_range in SENSITIVE_PORTS
                     or rule.destination_port_range == "*")
            ):
                issues.append({
                    "nsg_name": nsg.name,
                    "rule_name": rule.name,
                    "port": rule.destination_port_range,
                    "source": rule.source_address_prefix,
                    "severity": "high",
                })
    return issues


def estimate_vm_cost(vm_size):
    """Estimation simplifiée du coût mensuel basée sur la taille de VM."""
    return VM_PRICE_ESTIMATES.get(vm_size, None)


def analyze():
    credential, subscription_id = get_credentials()

    resource_client = ResourceManagementClient(credential, subscription_id)
    network_client = NetworkManagementClient(credential, subscription_id)
    compute_client = ComputeManagementClient(credential, subscription_id)

    report = {
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "resource_group": RESOURCE_GROUP,
        "resources": [],
        "network_issues": [],
        "summary": {"compliant": 0, "non_compliant": 0},
    }

    # --- 1. Vérification des tags sur le Resource Group lui-même ---
    rg = resource_client.resource_groups.get(RESOURCE_GROUP)
    rg_missing_tags = check_tags(rg, REQUIRED_TAGS)
    if rg_missing_tags:
        report["resources"].append({
            "name": rg.name,
            "type": "ResourceGroup",
            "missing_tags": rg_missing_tags,
            "compliant": False,
        })
        report["summary"]["non_compliant"] += 1
    else:
        report["summary"]["compliant"] += 1

    # --- 2. Vérification des VMs : tags + coût ---
    vms = compute_client.virtual_machines.list(RESOURCE_GROUP)
    vm_hosts = []  # pour l'inventaire Ansible

    for vm in vms:
        missing_tags = check_tags(vm, REQUIRED_TAGS)
        vm_size = vm.hardware_profile.vm_size
        estimated_cost = estimate_vm_cost(vm_size)

        cost_issue = (
            estimated_cost is not None and estimated_cost > COST_THRESHOLD_USD_MONTH
        )

        vm_compliant = not missing_tags and not cost_issue

        vm_entry = {
            "name": vm.name,
            "type": "VirtualMachine",
            "size": vm_size,
            "missing_tags": missing_tags,
            "estimated_monthly_cost_usd": estimated_cost,
            "cost_alert": cost_issue,
            "compliant": vm_compliant,
        }
        report["resources"].append(vm_entry)

        if vm_compliant:
            report["summary"]["compliant"] += 1
        else:
            report["summary"]["non_compliant"] += 1
            vm_hosts.append(vm.name)

    # --- 3. Vérification des règles réseau ---
    network_issues = check_nsg_rules(network_client, RESOURCE_GROUP)
    report["network_issues"] = network_issues
    if network_issues:
        report["summary"]["non_compliant"] += len(network_issues)

    return report, vm_hosts


def save_report(report):
    os.makedirs("reports", exist_ok=True)
    filename = f"reports/report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)
    # Toujours garder une copie "latest" facile à retrouver
    with open("reports/latest_report.json", "w") as f:
        json.dump(report, f, indent=2)
    print(f"Rapport enregistré : {filename}")
    return filename


def generate_ansible_inventory(report, vm_public_ip, admin_user="azureadmin"):
    """Génère l'inventaire Ansible et les variables de remédiation."""
    os.makedirs("ansible/inventory", exist_ok=True)
    os.makedirs("ansible/group_vars", exist_ok=True)

    non_compliant_vms = [r for r in report["resources"] if r["type"] == "VirtualMachine" and not r["compliant"]]

    # Inventaire : toutes les VMs non conformes
    with open("ansible/inventory/hosts.ini", "w") as f:
        f.write("[non_compliant]\n")
        for vm in non_compliant_vms:
            f.write(f"{vm['name']} ansible_host={vm_public_ip} ansible_user={admin_user}\n")

    # Variables : détail des problèmes par groupe
    group_vars = {
        "network_issues": report["network_issues"],
        "vms_missing_tags": {
            vm["name"]: vm["missing_tags"] for vm in non_compliant_vms if vm["missing_tags"]
        },
        "vms_cost_alerts": {
            vm["name"]: vm["estimated_monthly_cost_usd"]
            for vm in non_compliant_vms if vm.get("cost_alert")
        },
    }
    with open("ansible/group_vars/all.yml", "w") as f:
        f.write("---\n")
        f.write(f"scan_date: \"{report['scan_date']}\"\n")
        f.write(f"network_issues: {json.dumps(group_vars['network_issues'])}\n")
        f.write(f"vms_missing_tags: {json.dumps(group_vars['vms_missing_tags'])}\n")
        f.write(f"vms_cost_alerts: {json.dumps(group_vars['vms_cost_alerts'])}\n")

    print(f"Inventaire Ansible généré : ansible/inventory/hosts.ini ({len(non_compliant_vms)} VM(s) non conforme(s))")
    return len(non_compliant_vms)


def trigger_ansible():
    """Déclenche ansible-playbook si le playbook existe, avec gestion d'erreurs claire."""
    playbook_path = "ansible/remediate.yml"
    if not os.path.exists(playbook_path):
        print("⚠ Playbook Ansible non trouvé (ansible/remediate.yml) — étape à venir.")
        return

    print("Déclenchement d'Ansible pour remédiation automatique...")
    result = subprocess.run(
        ["ansible-playbook", "-i", "ansible/inventory/hosts.ini", playbook_path],
        capture_output=True, text=True
    )
    print(result.stdout)

    if result.returncode == 0:
        print("✅ Remédiation Ansible appliquée avec succès.")
        return

    # --- Analyse du type d'échec pour un message clair ---
    output = result.stdout + result.stderr

    if "UNREACHABLE" in output or "Connection timed out" in output:
        print("⚠️  VM injoignable en SSH — remédiation interne (fail2ban, logs) impossible.")
        print("    → Vérifiez que la VM est allumée : az vm start --resource-group <RG> --name <VM>")
        print("    → Les corrections via Azure CLI (tags, règles réseau) restent possibles indépendamment du SSH.")
    elif "Permission denied" in output:
        print("⚠️  Échec d'authentification SSH — vérifiez la clé publique / l'utilisateur configuré.")
    else:
        print("⚠️  Échec Ansible pour une raison non identifiée :")
        print(result.stderr.strip() if result.stderr.strip() else "(aucun détail stderr disponible)")

    print("    → Le scan et le rapport restent valides ; seule la remédiation automatique a été impactée.")
def main():
    vm_public_ip = os.environ.get("VM_PUBLIC_IP", "4.223.129.11")

    print("=== Cloud Canary Guard — Scan de conformité ===")
    report, vm_hosts = analyze()
    save_report(report)

    print(f"\nRésumé : {report['summary']['compliant']} conforme(s), "
          f"{report['summary']['non_compliant']} non-conforme(s)")

    if report["network_issues"]:
        print("\n⚠ Règles réseau à risque détectées :")
        for issue in report["network_issues"]:
            print(f"  - {issue['nsg_name']} / {issue['rule_name']}: "
                  f"port {issue['port']} ouvert depuis {issue['source']}")

    non_compliant_count = generate_ansible_inventory(report, vm_public_ip)

    if non_compliant_count > 0 or report["network_issues"]:
        trigger_ansible()
    else:
        print("\n✅ Toutes les ressources sont conformes, aucune action nécessaire.")


if __name__ == "__main__":
    main()
