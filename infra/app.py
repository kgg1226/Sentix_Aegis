"""AEGIS CDK application entry point.

Deploy with:
    cdk deploy --all

Stacks:
    - AegisEventBusStack: EventBridge bus for signal routing
    - AegisDetectionStack: Lambda handlers for L1/L2 fast-path
    - AegisSandboxStack: ECS Fargate for Red/Blue arena isolation
    - AegisBedrock: Bedrock model access for L3/L4 analysis

Prerequisites:
    - pip install "aws-cdk-lib>=2.100"
    - AWS credentials configured
    - CDK bootstrapped in target account/region

Status: STUB — infrastructure definitions will be added in Phase 7.
"""

from __future__ import annotations


def main() -> None:
    try:
        import aws_cdk as cdk
    except ImportError:
        print(
            "aws-cdk-lib not installed. Install with:\n"
            "  pip install 'aws-cdk-lib>=2.100' 'constructs>=10.0'\n"
            "Then re-run: python infra/app.py"
        )
        return

    app = cdk.App()

    env = cdk.Environment(
        account=app.node.try_get_context("account"),
        region=app.node.try_get_context("region") or "ap-northeast-2",
    )

    # Stacks will be defined here in Phase 7:
    # AegisEventBusStack(app, "AegisEventBus", env=env)
    # AegisDetectionStack(app, "AegisDetection", env=env)
    # AegisSandboxStack(app, "AegisSandbox", env=env)

    app.synth()


if __name__ == "__main__":
    main()
