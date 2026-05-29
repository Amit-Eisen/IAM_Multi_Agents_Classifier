"""
Generate synthetic IAM policies for testing.
Creates a mix of secure, risky, and dangerous policies.
"""
import json
import random
from pathlib import Path


# Building blocks for generating policies
SAFE_ACTIONS = [
    "s3:GetObject",
    "s3:ListBucket",
    "ec2:DescribeInstances",
    "ec2:DescribeSecurityGroups",
    "cloudwatch:GetMetricData",
    "cloudwatch:ListMetrics",
    "logs:GetLogEvents",
    "logs:FilterLogEvents",
    "dynamodb:GetItem",
    "dynamodb:Query",
    "sns:ListTopics",
    "sqs:ReceiveMessage",
]

WRITE_ACTIONS = [
    "s3:PutObject",
    "s3:DeleteObject",
    "ec2:CreateSecurityGroup",
    "ec2:AuthorizeSecurityGroupIngress",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem",
    "sns:Publish",
    "sqs:SendMessage",
    "lambda:InvokeFunction",
]

DANGEROUS_ACTIONS = [
    "iam:CreateUser",
    "iam:CreateAccessKey",
    "iam:AttachUserPolicy",
    "iam:PutUserPolicy",
    "iam:CreateRole",
    "iam:AttachRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "ec2:RunInstances",
    "cloudformation:CreateStack",
    "kms:Decrypt",
    "secretsmanager:GetSecretValue",
]

WILDCARD_PATTERNS = [
    "*",
    "s3:*",
    "ec2:*",
    "iam:*",
    "dynamodb:*",
    "lambda:*",
]

SPECIFIC_RESOURCES = [
    "arn:aws:s3:::my-app-bucket/*",
    "arn:aws:s3:::my-app-bucket",
    "arn:aws:dynamodb:us-east-1:123456789012:table/users",
    "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
    "arn:aws:lambda:us-east-1:123456789012:function:my-function",
    "arn:aws:sqs:us-east-1:123456789012:my-queue",
]

MFA_CONDITION = {
    "Bool": {"aws:MultiFactorAuthPresent": "true"}
}

IP_CONDITION = {
    "IpAddress": {"aws:SourceIp": ["10.0.0.0/8", "192.168.0.0/16"]}
}


def generate_secure_policy():
    """Generate a well-scoped secure policy."""
    actions = random.sample(SAFE_ACTIONS, k=random.randint(2, 4))
    resources = random.sample(SPECIFIC_RESOURCES, k=random.randint(1, 2))
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "SecureReadAccess",
                "Effect": "Allow",
                "Action": actions,
                "Resource": resources,
            }
        ]
    }
    
    # Sometimes add conditions
    if random.random() > 0.5:
        policy["Statement"][0]["Condition"] = IP_CONDITION
    
    return policy


def generate_medium_risk_policy():
    """Generate a policy with some write access but scoped."""
    read_actions = random.sample(SAFE_ACTIONS, k=random.randint(2, 3))
    write_actions = random.sample(WRITE_ACTIONS, k=random.randint(1, 2))
    resources = random.sample(SPECIFIC_RESOURCES, k=random.randint(1, 2))
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ReadAccess",
                "Effect": "Allow",
                "Action": read_actions,
                "Resource": resources,
            },
            {
                "Sid": "WriteAccess", 
                "Effect": "Allow",
                "Action": write_actions,
                "Resource": resources,
            }
        ]
    }
    
    return policy


def generate_overly_permissive_policy():
    """Generate policy with wildcards but no privilege escalation."""
    wildcard = random.choice(["s3:*", "ec2:*", "dynamodb:*", "cloudwatch:*"])
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": wildcard,
                "Resource": "*",
            }
        ]
    }
    
    return policy


def generate_privilege_escalation_policy():
    """Generate a policy with privilege escalation paths."""
    dangerous = random.sample(DANGEROUS_ACTIONS, k=random.randint(2, 4))
    
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": dangerous,
                "Resource": "*",
            }
        ]
    }
    
    # Add passrole + lambda for escalation combo
    if random.random() > 0.5:
        policy["Statement"].append({
            "Effect": "Allow",
            "Action": ["iam:PassRole", "lambda:CreateFunction"],
            "Resource": "*",
        })
    
    return policy


def generate_data_exposure_policy():
    """Generate a policy with data exposure risks."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:PutBucketPolicy",
                    "s3:PutBucketAcl",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": [
                    "secretsmanager:GetSecretValue",
                    "ssm:GetParameter",
                    "ssm:GetParameters",
                ],
                "Resource": "*",
            }
        ]
    }
    
    return policy


def generate_admin_policy():
    """Generate a full admin policy (worst case)."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ]
    }
    
    return policy


def generate_mixed_policy():
    """Generate a realistic mixed policy."""
    statements = []
    
    # Some read access
    statements.append({
        "Sid": "ReadAccess",
        "Effect": "Allow",
        "Action": random.sample(SAFE_ACTIONS, k=3),
        "Resource": random.sample(SPECIFIC_RESOURCES, k=2),
    })
    
    # Some write access
    statements.append({
        "Sid": "WriteAccess",
        "Effect": "Allow", 
        "Action": random.sample(WRITE_ACTIONS, k=2),
        "Resource": random.choice(SPECIFIC_RESOURCES),
    })
    
    # Maybe a wildcard
    if random.random() > 0.6:
        statements.append({
            "Sid": "ServiceAccess",
            "Effect": "Allow",
            "Action": random.choice(["logs:*", "cloudwatch:*", "xray:*"]),
            "Resource": "*",
        })
    
    # Maybe a deny
    if random.random() > 0.7:
        statements.append({
            "Sid": "DenyDangerous",
            "Effect": "Deny",
            "Action": ["iam:*", "organizations:*"],
            "Resource": "*",
        })
    
    return {
        "Version": "2012-10-17",
        "Statement": statements,
    }


GENERATORS = [
    ("secure", generate_secure_policy, 5),
    ("medium_risk", generate_medium_risk_policy, 5),
    ("overly_permissive", generate_overly_permissive_policy, 4),
    ("priv_escalation", generate_privilege_escalation_policy, 4),
    ("data_exposure", generate_data_exposure_policy, 3),
    ("admin", generate_admin_policy, 2),
    ("mixed", generate_mixed_policy, 7),
]


def main():
    output_dir = Path("generated_policies")
    output_dir.mkdir(exist_ok=True)
    
    policy_num = 1
    
    for name, generator, count in GENERATORS:
        for i in range(count):
            policy = generator()
            filename = output_dir / f"gen_{name}_{i+1}.json"
            
            with open(filename, "w") as f:
                json.dump(policy, f, indent=2)
            
            print(f"Generated: {filename.name}")
            policy_num += 1
    
    print(f"\nTotal: {policy_num - 1} policies in {output_dir}/")
    print("\nTo analyze them:")
    print("  python main.py batch generated_policies")


if __name__ == "__main__":
    main()
