from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Finding(BaseModel):
    id: str
    title: str
    passed: bool
    severity: Severity
    detail: str = ""
    recommendation: str | None = None


class CheckResult(BaseModel):
    name: str
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None


class ScanResult(BaseModel):
    url: str
    final_url: str
    status_code: int
    score: int
    grade: str
    checks: list[CheckResult]
