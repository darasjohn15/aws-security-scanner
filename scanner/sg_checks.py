import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
from scanner.models import Finding


HIGH_RISK_PORTS = {22, 3389}


def scan_security_groups() -> list[Finding]:
    """
    Scan AWS security groups for risky public inbound rules.

    Flags:
    - SSH (22) open to the world
    - RDP (3389) open to the world
    - All ports open to the world
    - Broad public port ranges
    """
    findings: list[Finding] = []

    try:
        ec2 = boto3.client("ec2")
        response = ec2.describe_security_groups()
        security_groups = response.get("SecurityGroups", [])
    except NoCredentialsError:
        raise RuntimeError(
            "AWS credentials not found. Run 'aws configure' or set environment credentials."
        )
    except (ClientError, BotoCoreError) as exc:
        raise RuntimeError(f"Failed to describe security groups: {exc}") from exc

    for sg in security_groups:
        group_id = sg.get("GroupId", "unknown-sg")
        group_name = sg.get("GroupName", "unknown-name")
        ip_permissions = sg.get("IpPermissions", [])

        for permission in ip_permissions:
            findings.extend(_analyze_permission(group_id, group_name, permission))

    return findings


def _analyze_permission(group_id: str, group_name: str, permission: dict) -> list[Finding]:
    findings: list[Finding] = []

    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    ip_protocol = permission.get("IpProtocol")

    ipv4_ranges = permission.get("IpRanges", [])
    ipv6_ranges = permission.get("Ipv6Ranges", [])

    for ip_range in ipv4_ranges:
        cidr = ip_range.get("CidrIp")
        if cidr == "0.0.0.0/0":
            finding = _build_finding_for_cidr(
                group_id=group_id,
                group_name=group_name,
                cidr=cidr,
                from_port=from_port,
                to_port=to_port,
                ip_protocol=ip_protocol,
            )
            if finding:
                findings.append(finding)

    for ip_range in ipv6_ranges:
        cidr = ip_range.get("CidrIpv6")
        if cidr == "::/0":
            finding = _build_finding_for_cidr(
                group_id=group_id,
                group_name=group_name,
                cidr=cidr,
                from_port=from_port,
                to_port=to_port,
                ip_protocol=ip_protocol,
            )
            if finding:
                findings.append(finding)

    return findings


def _build_finding_for_cidr(
    group_id: str,
    group_name: str,
    cidr: str,
    from_port,
    to_port,
    ip_protocol: str,
) -> Finding | None:
    """
    Convert a public inbound rule into a Finding if it matches our V1 risk rules.
    """

    # Case 1: all traffic allowed
    if ip_protocol == "-1":
        return Finding(
            severity="HIGH",
            service="EC2",
            resource_id=group_id,
            issue=f"Security group '{group_name}' allows all traffic from {cidr}.",
            recommendation="Restrict inbound access to only required ports and trusted IP ranges.",
        )

    # Case 2: ports missing or non-standard protocol
    if from_port is None or to_port is None:
        return Finding(
            severity="MEDIUM",
            service="EC2",
            resource_id=group_id,
            issue=f"Security group '{group_name}' allows public access from {cidr} with protocol '{ip_protocol}'.",
            recommendation="Review this rule and restrict access if it is broader than necessary.",
        )

    # Case 3: specific high-risk admin ports
    if from_port == to_port and from_port in HIGH_RISK_PORTS:
        port_name = "SSH" if from_port == 22 else "RDP"
        return Finding(
            severity="HIGH",
            service="EC2",
            resource_id=group_id,
            issue=f"Security group '{group_name}' exposes {port_name} port {from_port} to {cidr}.",
            recommendation=f"Restrict port {from_port} access to trusted IP ranges only.",
        )

    # Case 4: broad public range including sensitive ports
    if from_port <= 22 <= to_port or from_port <= 3389 <= to_port:
        return Finding(
            severity="HIGH",
            service="EC2",
            resource_id=group_id,
            issue=(
                f"Security group '{group_name}' exposes public port range "
                f"{from_port}-{to_port} to {cidr}, including sensitive admin ports."
            ),
            recommendation="Narrow the allowed port range and restrict access to trusted IP ranges.",
        )

    # Case 5: very broad public range
    if (to_port - from_port) >= 100:
        return Finding(
            severity="MEDIUM",
            service="EC2",
            resource_id=group_id,
            issue=f"Security group '{group_name}' exposes broad public port range {from_port}-{to_port} to {cidr}.",
            recommendation="Limit the rule to only the specific ports required.",
        )

    # Case 6: any other public port exposure
    return Finding(
        severity="MEDIUM",
        service="EC2",
        resource_id=group_id,
        issue=f"Security group '{group_name}' exposes port {from_port} to {cidr}.",
        recommendation="Confirm that public access is required and restrict it if possible.",
    )