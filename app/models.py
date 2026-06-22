"""Ported from backend/src/pipeline/types.ts.

TS union types -> typing.Literal. Interfaces -> pydantic models.
String literals match the TS source exactly.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel

EmailStatus = Literal[
    "valid", "invalid", "reserved",
    "do_not_use", "duplicate",
]

Confidence = Literal["high", "medium", "low"]

SubStatus = Literal[
    "smtp_confirmed",
    "syntax_error", "invalid_tld", "dot_rule_violation",
    "length_exceeded", "no_mx_record", "no_dns_record",
    "mailbox_not_found", "domain_not_found",
    "mailbox_full", "mailbox_disabled", "mailbox_suspended",
    "accept_all",
    "disposable", "role_rejected", "spam_trap_keyword",
    "smtp_timeout", "smtp_connection_failed",
    "greylisted", "temp_error", "server_error",
    "role_flagged", "alias_address",
    "ip_reputation_block", "policy_rejection", "ambiguous_rejection",
]

Flag = Literal[
    "free_provider", "role_address", "disposable", "catch_all",
    "typo_suggestion", "alias_detected", "infrastructure_risk",
    "server_blacklisted", "possible_trap",
]

ProcessingStage = Literal[1, 2, 3, 4]

JobStatus = Literal[
    "pending", "stage1", "stage2",
    "stage3", "stage4", "complete", "failed",
]


class ScoreBreakdownItem(BaseModel):
    signal: str
    points: int


class ValidationResult(BaseModel):
    email: str
    normalised: str
    status: EmailStatus
    sub_status: SubStatus
    score: float
    confidence: Confidence
    flags: list[Flag]
    did_you_mean: Optional[str] = None
    mx_record: Optional[str] = None
    smtp_provider: Optional[str] = None
    smtp_response: Optional[str] = None
    smtp_response_code: Optional[int] = None
    is_free_provider: bool
    is_role_address: bool
    is_disposable: bool
    processing_stage: ProcessingStage
    score_breakdown: Optional[list[ScoreBreakdownItem]] = None
    promoted_from_reserved: Optional[bool] = None
    demoted_from_reserved: Optional[bool] = None
    # Phase C — enrichment metadata
    full_name: Optional[str] = None
    alphabetical_count: Optional[int] = None
    numerical_count: Optional[int] = None
    unicode_symbol_count: Optional[int] = None
    implicit_mx_record: Optional[bool] = None
    smtp_accessible: Optional[bool] = None
    is_no_reply: Optional[bool] = None
    whois_registrar: Optional[str] = None
    whois_country: Optional[str] = None
    whois_server: Optional[str] = None


class JobCounts(BaseModel):
    total: int
    processed: int
    valid: int
    invalid: int
    reserved: int
    do_not_use: int
    duplicate: int
    promoted_to_valid: int
    demoted_to_invalid: int


class StageCount(BaseModel):
    done: int
    total: int


class Stage1Count(StageCount):
    filtered: int
    passed: int


class PipelineProgress(BaseModel):
    stage1: Stage1Count
    stage2: StageCount
    stage3: StageCount
    stage4: StageCount


class JobState(BaseModel):
    id: str
    filename: str
    status: JobStatus
    results: list[ValidationResult]
    counts: JobCounts
    startedAt: datetime
    completedAt: Optional[datetime] = None
    error: Optional[str] = None
    progress: Optional[PipelineProgress] = None
