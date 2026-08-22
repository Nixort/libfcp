# Copyright Nixort <https://github.com/Nixort> 2026.
#
# License: GNU General Public License v3.0 only.
# You can find the license file in the project root.
#
# Federated CFR Connect Protocol (FCP).

data "aws_iam_policy_document" "service_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "service" {
  name               = "${var.name_prefix}-service"
  assume_role_policy = data.aws_iam_policy_document.service_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.service.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "service_runtime" {
  statement {
    sid    = "ReadOnlyFabricRuntimeSecrets"
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
    ]
    resources = [
      aws_secretsmanager_secret.fabric_runtime.arn,
      aws_secretsmanager_secret.cloudflare_tunnel.arn,
      aws_db_instance.fabric.master_user_secret[0].secret_arn,
    ]
  }

  statement {
    sid    = "DecryptOnlyFabricSecrets"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
    ]
    resources = [aws_kms_key.secrets.arn]
  }

  statement {
    sid    = "UseTotpEnvelopeKeyWithBoundContext"
    effect = "Allow"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:GenerateDataKey",
    ]
    resources = [aws_kms_key.totp.arn]

    condition {
      test     = "StringEquals"
      variable = "kms:EncryptionContext:fcp-fabric-purpose"
      values   = ["totp-data-key/v1"]
    }
  }

  statement {
    sid       = "WriteStructuredServiceLogs"
    effect    = "Allow"
    actions   = ["logs:DescribeLogStreams", "logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.service.arn}:*"]
  }

  statement {
    sid       = "ReadDeploymentArtifacts"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = [
      "arn:aws:s3:::${split("/", trimprefix(var.service_artifact_s3_uri, "s3://"))[0]}/*",
      "arn:aws:s3:::${split("/", trimprefix(var.cloudflared_artifact_s3_uri, "s3://"))[0]}/*",
    ]
  }
}

resource "aws_iam_role_policy" "service_runtime" {
  name   = "${var.name_prefix}-runtime"
  role   = aws_iam_role.service.id
  policy = data.aws_iam_policy_document.service_runtime.json
}

resource "aws_iam_instance_profile" "service" {
  name = "${var.name_prefix}-service"
  role = aws_iam_role.service.name
}
