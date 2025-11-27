resource "random_string" "lambda" {
  length  = 8
  special = false
  upper   = false

  lifecycle {
    ignore_changes = [
      special,
      upper,
    ]
  }
}

resource "random_string" "flask_secret_key" {
  length  = 32
  special = false
  upper   = false

  lifecycle {
    ignore_changes = [
      special,
      upper,
    ]
  }
}

locals {
  flask_secret_key = sensitive(random_string.flask_secret_key.result)
  name             = "saml2oauth-${random_string.lambda.result}"
  saml_secret_name = "saml-idp-keypair-${random_string.lambda.result}"
}

resource "aws_lambda_function" "lambda" {
  filename         = "${path.module}/dist/lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/dist/lambda.zip")

  function_name = local.name
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.13"

  role = aws_iam_role.lambda_role.arn

  memory_size = 384
  timeout     = 30

  environment {
    variables = {
      ENVIRONMENT = "prod"
      FLASK_SECRET_KEY = local.flask_secret_key
      SAML_KEYPAIR_SECRET_NAME = local.saml_secret_name
      OAUTH_CLIENT_ID = var.OAUTH_CLIENT_ID
      OAUTH_CLIENT_SECRET = sensitive(var.OAUTH_CLIENT_SECRET)
      SCIM_URL = var.SCIM_URL
      SCIM_ACCESS_TOKEN = sensitive(var.SCIM_ACCESS_TOKEN)
      SP_ACS_URL = var.SP_ACS_URL
      SP_ENTITY_ID = var.SP_ENTITY_ID
    }
  }
}

resource "aws_lambda_function_url" "lambda" {
  function_name = aws_lambda_function.lambda.function_name
  authorization_type = "NONE"
}
resource "aws_iam_role" "lambda_role" {
  name               = local.name
  assume_role_policy = data.aws_iam_policy_document.arpd.json
}

resource "aws_cloudwatch_log_group" "lambda_lg" {
  name              = "/aws/lambda/${local.name}"
  retention_in_days = var.LOG_RETENTION_DAYS
}

# See also the following AWS managed policy: AWSLambdaBasicExecutionRole
resource "aws_iam_policy" "lambda_policy" {
  name        = local.name
  path        = "/"
  description = "IAM policy for ${local.name}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "logs:CreateLogGroup",
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:logs:*:*:log-group:/aws/lambda/${local.name}:*"
      },
      {
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "secretsmanager:PutSecretValue",
          "secretsmanager:CreateSecret"
        ]
        Effect   = "Allow"
        Resource = "arn:aws:secretsmanager:*:*:secret:${local.saml_secret_name}*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_pa" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = aws_iam_policy.lambda_policy.arn
}

data "aws_iam_policy_document" "arpd" {
  statement {
    sid    = "AllowAwsToAssumeRole"
    effect = "Allow"

    actions = ["sts:AssumeRole"]

    principals {
      type = "Service"

      identifiers = [
        "lambda.amazonaws.com",
      ]
    }
  }
}
