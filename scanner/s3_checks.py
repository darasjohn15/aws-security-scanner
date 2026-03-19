import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from scanner.models import Finding


ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTHENTICATED_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def scan_s3_buckets() -> list[Finding]:
    """
    Scan S3 buckets for public exposure risks.

    Flags:
    - ACL grants to AllUsers (HIGH)
    - ACL grants to AuthenticatedUsers (MEDIUM)
    - Missing or incomplete bucket public access block settings (MEDIUM)
    """
    findings: list[Finding] = []

    try:
        s3 = boto3.client("s3")
        response = s3.list_buckets()
        buckets = response.get("Buckets", [])
    except NoCredentialsError:
        raise RuntimeError(
            "AWS credentials not found. Run 'aws configure' or set environment credentials."
        )
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Failed to list S3 buckets: {exc}") from exc

    for bucket in buckets:
        bucket_name = bucket.get("Name")
        if not bucket_name:
            continue

        findings.extend(_check_bucket_acl(s3, bucket_name))
        findings.extend(_check_public_access_block(s3, bucket_name))

    return findings


def _check_bucket_acl(s3_client, bucket_name: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")
        findings.append(
            Finding(
                severity="MEDIUM",
                service="S3",
                resource_id=bucket_name,
                issue=f"Could not read bucket ACL. AWS returned: {error_code}.",
                recommendation="Verify the scanner has permission to read bucket ACL settings.",
            )
        )
        return findings

    grants = acl.get("Grants", [])

    for grant in grants:
        grantee = grant.get("Grantee", {})
        uri = grantee.get("URI")

        if uri == ALL_USERS_URI:
            findings.append(
                Finding(
                    severity="HIGH",
                    service="S3",
                    resource_id=bucket_name,
                    issue="Bucket ACL grants access to AllUsers, which can allow public access.",
                    recommendation="Remove public ACL grants unless this bucket is intentionally public.",
                )
            )

        elif uri == AUTHENTICATED_USERS_URI:
            findings.append(
                Finding(
                    severity="MEDIUM",
                    service="S3",
                    resource_id=bucket_name,
                    issue="Bucket ACL grants access to AuthenticatedUsers.",
                    recommendation="Review whether authenticated AWS users outside your account should have access.",
                )
            )

    return findings


def _check_public_access_block(s3_client, bucket_name: str) -> list[Finding]:
    findings: list[Finding] = []

    try:
        response = s3_client.get_public_access_block(Bucket=bucket_name)
        config = response.get("PublicAccessBlockConfiguration", {})
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "Unknown")

        # NoSuchPublicAccessBlockConfiguration means the bucket doesn't have
        # bucket-level public access block configured.
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            findings.append(
                Finding(
                    severity="MEDIUM",
                    service="S3",
                    resource_id=bucket_name,
                    issue="Bucket-level Public Access Block is not fully enabled. This does not necessarily mean the bucket is public, but it increases the risk of unintended public exposure.",
                    recommendation="Enable all four Public Access Block settings unless public access is explicitly required.",
                )
            )
            return findings

        findings.append(
            Finding(
                severity="MEDIUM",
                service="S3",
                resource_id=bucket_name,
                issue=f"Could not read Public Access Block settings. AWS returned: {error_code}.",
                recommendation="Verify the scanner has permission to read bucket public access block settings.",
            )
        )
        return findings

    required_flags = [
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    ]

    missing_or_disabled = [flag for flag in required_flags if config.get(flag) is not True]

    if missing_or_disabled:
        findings.append(
            Finding(
                severity="MEDIUM",
                service="S3",
                resource_id=bucket_name,
                issue=(
                    "Bucket Public Access Block is not fully enabled. "
                    f"Missing or disabled settings: {', '.join(missing_or_disabled)}."
                ),
                recommendation="Enable all four Public Access Block settings unless public access is explicitly required.",
            )
        )

    return findings