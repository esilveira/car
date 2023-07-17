provider "aws" {
  region = var.region
}

resource "aws_ssm_parameter" "jwt_secret" {
  name        = "jwt_secret"
  description = "JWT secret to be used as symetric key to issue and validate JWT tokens"
  type        = "SecureString"
  value       = var.jwt_secret
}

resource "aws_ecs_task_definition" "this" {
  family                   = "backend-api-task-definition"
  network_mode             = "awsvpc"
  task_role_arn            = data.terraform_remote_state.career-center-environment.outputs.ecs_task_execution_role_arn
  execution_role_arn       = data.terraform_remote_state.career-center-environment.outputs.ecs_task_execution_role_arn
  cpu                      = 1024
  memory                   = 2048
  requires_compatibilities = ["FARGATE"]

  container_definitions = jsonencode([
    {
      name      = var.container_name
      image     = var.container_image
      essential = true
      portMappings = [
        {
          protocol      = "tcp"
          containerPort = 8000
          hostPort      = 8000
        }
      ]

      cpu     = 1024
      memory  = 2048
      command = ["uvicorn", "--workers", "4", "app.main:create_app", "--host", "0.0.0.0"]

      healthCheck = {
        command     = ["CMD-SHELL", "curl -f http://localhost:8000/-/health || exit 1"]
        interval    = 10,
        timeout     = 5,
        retries     = 3,
        startPeriod = 60
      },

      environment = [
        {
          name  = "GITLAB_HOSTNAME"
          value = "http://gitlab.ecs/"
        },
        {
          name  = "REGISTER_ENABLED"
          value = "False"
        }
      ]

      secrets = [
        {
          name      = "GITLAB_ADMIN_PASSWORD"
          valueFrom = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/gitlab_admin_password"
        },
        {
          name      = "JWT_SECRET"
          valueFrom = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/jwt_secret"
        },
        {
          name  = "GITLAB_ADMIN_TOKEN"
          valueFrom = "arn:aws:ssm:${var.region}:${data.aws_caller_identity.current.account_id}:parameter/gitlab_root_token"
        }
      ]
    }
  ])

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

}

resource "aws_ecs_service" "this" {
  name                 = "backend-api"
  cluster              = data.terraform_remote_state.career-center-environment.outputs.ecs_cluster.cluster-id
  task_definition      = aws_ecs_task_definition.this.arn
  desired_count        = var.desired_instances_number
  launch_type          = "FARGATE"
  force_new_deployment = false

  network_configuration {
    subnets          = [data.terraform_remote_state.career-center-environment.outputs.private_subnet_id]
    security_groups  = [data.terraform_remote_state.career-center-environment.outputs.ecs_security_group_id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = data.terraform_remote_state.career-center-environment.outputs.lb_target_groups_arn["api-app"]
    container_name   = var.container_name
    container_port   = 8000
  }

  service_connect_configuration {
    enabled = true
  }
}
