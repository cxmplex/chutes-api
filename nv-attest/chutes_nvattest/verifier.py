import base64
import hashlib
from typing import Any, Dict

from nv_attestation_sdk.attestation import Attestation, Devices, Environment


class NvVerifier:
    def attest(
        self, nonce: str, evidence: list[Dict[str, str]]
    ) -> dict[str, Any] | None:
        _client = Attestation()
        _client.add_verifier(Devices.GPU, Environment.REMOTE, "", "")
        _client.set_nonce(nonce)
        result = _client.attest(evidence)
        if not result:
            return None
        devices = []
        for item in evidence:
            if set(item) != {"certificate", "evidence", "arch"}:
                raise ValueError("NVIDIA evidence item fields are not canonical")
            certificate = base64.b64decode(item["certificate"], validate=True)
            signed_evidence = base64.b64decode(item["evidence"], validate=True)
            if not certificate or not signed_evidence or not item["arch"]:
                raise ValueError("NVIDIA evidence item is incomplete")
            devices.append(
                {
                    "attestation_certificate_sha256": hashlib.sha256(
                        certificate
                    ).hexdigest(),
                    "evidence_sha256": hashlib.sha256(signed_evidence).hexdigest(),
                    "architecture": item["arch"],
                }
            )
        devices.sort(key=lambda item: item["attestation_certificate_sha256"])
        if len({item["attestation_certificate_sha256"] for item in devices}) != len(
            devices
        ):
            raise ValueError("NVIDIA evidence repeats a device certificate")
        return {
            "schema": "chutes.nvidia-verification-result",
            "version": 1,
            "nonce": nonce,
            "devices": devices,
        }
