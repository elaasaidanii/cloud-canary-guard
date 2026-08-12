variable "subscription_id" {
  description = "ID de l'abonnement Azure"
  type        = string
}

variable "location" {
  description = "Région Azure"
  type        = string
  default     = "westeurope"
}

variable "project_name" {
  description = "Nom du projet, utilisé comme préfixe"
  type        = string
  default     = "canaryguard"
}

variable "admin_username" {
  description = "Nom d'utilisateur admin sur la VM"
  type        = string
  default     = "azureadmin"
}
