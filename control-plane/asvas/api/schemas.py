from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from asvas.scope import Scope, TestingPolicy


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class AssessmentCreate(_In):
    name: str = Field(min_length=3, max_length=120)
    description: str = Field(default="", max_length=2000)
    scope: Scope
    testing_policy: TestingPolicy = TestingPolicy()


class AssessmentUpdate(_In):
    name: str | None = Field(default=None, min_length=3, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    scope: Scope | None = None
    testing_policy: TestingPolicy | None = None


class CancelRequest(_In):
    reason: str = Field(default="cancelled by user", min_length=3, max_length=500)


class ApprovalDecision(_In):
    decision: Literal["approve", "reject"]
    binding_hash: str = Field(pattern=r"^[0-9a-f]{64}$", description="The binding hash shown to the approver")
    reason: str | None = Field(default=None, max_length=500)


class EmergencyStop(_In):
    reason: str = Field(min_length=3, max_length=500)


class DevLogin(_In):
    email: str = Field(max_length=200)
