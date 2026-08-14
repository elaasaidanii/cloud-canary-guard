# ☁️ Cloud Canary Guard

Système sentinelle FinOps & Sécurité qui surveille automatiquement une infrastructure Azure, détecte les non-conformités (tags manquants, coûts excessifs, règles réseau ouvertes) et corrige les problèmes de sécurité sans intervention manuelle.

## 🎯 Pourquoi ce projet

En entreprise, deux problèmes reviennent sans cesse dans le cloud :
- **FinOps** : des ressources créées sans contrôle qui font exploser la facture
- **Sécurité** : des ressources sans tags (owner, environment) impossibles à auditer, ou des règles réseau trop permissives (ex: SSH ouvert à `0.0.0.0/0`)

Ce projet simule un mini système de gouvernance cloud automatisée, en combinant Infrastructure as Code, analyse programmatique et remédiation automatique.

## 🏗️ Architecture
1. **Terraform** provisionne l'infrastructure de test (Resource Group, réseau, VM) sur Azure
2. **Script Python** scanne les ressources via l'API Azure : tags manquants, coûts estimés, règles réseau à risque
3. **Ansible** applique automatiquement les correctifs : ajoute les tags, restreint les règles réseau trop ouvertes, renforce la sécurité SSH (fail2ban)
4. Le cycle peut être relancé pour vérifier que les corrections ont bien été appliquées

## 🛠️ Stack technique

| Outil | Rôle |
|---|---|
| Terraform | Provisioning de l'infrastructure Azure |
| Python (Azure SDK) | Détection des non-conformités |
| Ansible | Remédiation automatique |
| Azure CLI | Authentification et actions sur les ressources |
| Git / GitHub | Versioning du code |

## 📋 Prérequis

- Compte Azure (testé avec Azure for Students)
- Terraform >= 1.5
- Python 3.10+
- Ansible >= 2.14
- Azure CLI

## 🚀 Installation

```bash
git clone https://github.com/elaasaidanii/cloud-canary-guard.git
cd cloud-canary-guard

# Environnement Python
python3 -m venv venv
source venv/bin/activate
pip install azure-identity azure-mgmt-resource azure-mgmt-costmanagement azure-mgmt-network azure-mgmt-compute

# Authentification Azure
az login
```

## ▶️ Utilisation

### 1. Déployer l'infrastructure de test

```bash
cd terraform
terraform init
terraform apply -var="subscription_id=$(az account show --query id -o tsv)"
```

### 2. Scanner les ressources et déclencher la remédiation

```bash
cd ..
export VM_PUBLIC_IP=$(cd terraform && terraform output -raw vm_public_ip)
python3 scripts/analyze.py
```

Le script génère un rapport JSON dans `reports/`, un inventaire Ansible dans `ansible/inventory/`, et déclenche automatiquement la remédiation si des non-conformités sont détectées.

### 3. Détruire l'infrastructure (pour ne pas laisser tourner de coûts)

```bash
cd terraform
terraform destroy -var="subscription_id=$(az account show --query id -o tsv)"
```

## 🔍 Ce que le système détecte et corrige

| Problème détecté | Action de remédiation |
|---|---|
| Tags `owner` / `environment` manquants | Ajout automatique des tags sur le Resource Group et la VM |
| Règle NSG SSH ouverte à `*` | Restriction à l'IP du poste de contrôle |
| Coût VM estimé au-dessus du seuil | Alerte dans le rapport (décision manuelle) |

## 📁 Structure du projet
cloud-canary-guard/
├── terraform/ # Infrastructure as Code
│ ├── main.tf
│ ├── provider.tf
│ ├── variables.tf
│ └── outputs.tf
├── scripts/
│ └── analyze.py # Script de détection des non-conformités
├── ansible/
│ ├── remediate.yml # Remédiation sur la VM (logs, fail2ban)
│ ├── fix_network.yml # Correction de la règle NSG
│ ├── fix_tags.yml # Correction des tags manquants
│ └── inventory/
├── reports/ # Rapports JSON générés par les scans
└── README.md

## 🔐 Sécurité

- Aucun secret n'est versionné (voir `.gitignore`)
- Authentification via session Azure CLI (`az login`), pas de Service Principal stocké en clair
- Accès SSH restreint automatiquement à l'IP du poste de contrôle après remédiation

## 📄 Licence

Projet personnel à but éducatif.
