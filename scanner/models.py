from dataclasses import dataclass, asdict

@dataclass
class Finding:
    severity: str
    service: str
    resource_id: str
    issue: str
    recommendation: str

    def to_dict(self):
        return asdict(self)