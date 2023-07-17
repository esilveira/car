variable "region" {
  description = "Region to create/access the resources"
  default     = "us-east-1"
  type        = string
}

variable "container_name" {
  description = ""
  type        = string
  default     = "backend_api_container"
}

variable "container_image" {
  description = "The container image"
  type        = string
}

variable "desired_instances_number" {
  description = "Number of instances of the task definition to place and keep running"
  type        = number
  default     = 1
}

variable "jwt_secret" {
  type        = string
  description = "JWT secret"
  sensitive   = true
}
