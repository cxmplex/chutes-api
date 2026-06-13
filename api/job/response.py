"""
Safer response class for user.
"""

from typing import Optional, Any
from pydantic import BaseModel
from datetime import datetime
from api.chute.response import MinimalChuteResponse
from api.instance.response import MinimalInstanceResponse


class JobResponse(BaseModel):
    job_id: str
    user_id: str
    chute_id: str
    version: str
    chutes_version: str
    method: str

    instance_id: Optional[str] = None
    active: bool
    verified: bool
    last_queried_at: Optional[datetime] = None
    created_at: datetime
    updated_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    job_args: dict
    result: Optional[dict] = None
    output_files: Optional[dict[str, Any]] = []

    host: Optional[str] = None
    port_mappings: Optional[list[dict[str, Any]]] = []
    # The attested CPU-TEE server the job's instance landed on. The owner passes this to
    # `chutes connect`/`chutes ssh` (GET /servers/cpu/{server_id}/connection) to attest + reach the
    # rental over the WireGuard overlay. None until the job is scheduled onto a server.
    server_id: Optional[str] = None

    chute: MinimalChuteResponse
    instance: Optional[MinimalInstanceResponse] = None

    output_storage_urls: Optional[dict[str, str]] = {}

    class Config:
        from_attributes = True
