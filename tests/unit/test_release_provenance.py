"""Canonical provenance parser and real cosign detached-signature integration."""

import copy
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from api.config import TeeMeasurementConfig
from api.releases import service as release_service
from api.releases.provenance import (
    ProvenanceError,
    canonical_provenance_bytes,
    load_canonical_provenance,
    verify_provenance_signature,
)
from api.releases.schemas import GuestRelease


_VCPU_SIZES = (1, 2, 4, 8)

# Exact hardened bare-metal TDX values captured from a verified runtime quote on the
# PhoenixNAP TDVF platform. The same observed capture is deliberately reused across the
# logical test classes; this regression tests complete class/value binding and is not a
# claim that 1/2/8-vCPU fleet captures have been taken.
_REAL_BAREMETAL_TDX_CAPTURE = {
    "mrtd": (
        "FDBEE8A3187E02B56827465C2811223712D0E5B9D77ADE35883D9A468B6448E"
        "02A3140A96DAFBB4E828ED14CF3906D51"
    ),
    "boot_rtmrs": {
        "RTMR0": (
            "F8A6B63099CAC6A5472B2EE9E0D2590472C0A102C758F80CAD95C9D6A860DB40"
            "09A96F7BEFD713D94CC7BE992454F957"
        ),
        "RTMR1": (
            "92354562DF8EC26FAA067E326B52F4D431485B1B9A146904AD2252F54022DF09"
            "203FBB35BE0D7DE1FF6C9A28AA062B67"
        ),
        "RTMR2": (
            "6B7A522EC51FB88EF932C0F8573A5CE837261CEB206871C2319C96CCB65424A3"
            "F026F1B1C498497B130C543C0A90031B"
        ),
        "RTMR3": "0" * 96,
    },
    "runtime_rtmrs": {
        "RTMR0": (
            "F8A6B63099CAC6A5472B2EE9E0D2590472C0A102C758F80CAD95C9D6A860DB40"
            "09A96F7BEFD713D94CC7BE992454F957"
        ),
        "RTMR1": (
            "92354562DF8EC26FAA067E326B52F4D431485B1B9A146904AD2252F54022DF09"
            "203FBB35BE0D7DE1FF6C9A28AA062B67"
        ),
        "RTMR2": (
            "6B7A522EC51FB88EF932C0F8573A5CE837261CEB206871C2319C96CCB65424A3"
            "F026F1B1C498497B130C543C0A90031B"
        ),
        "RTMR3": (
            "B73823F33F1BAB37A35224FAF07D5EE18B2822956A2420AB38E68E70C06BD01D"
            "254908F6EE5F24162674339EB7103AF8"
        ),
    },
}

# Real GCP N2D/Milan SNP + vTPM image-identity capture. These values come from
# the checked-in GCP attestation fixture and the signature-verified live report.
_REAL_GCP_SNP_CAPTURE = {
    "measurement": (
        "E1BCDADEF92887CB4512C079C485CF009100CF86D2276A27DA2B1E9D150DD11B0"
        "B5CC6D4B40BBC9FF0575B63F679DC23"
    ),
    "vtpm_pcrs": {
        "8": "18E48C268E9642CE8284BD5878CDDFC2F0AD22BE9CBF6AF1DC4AC0B9609AD780",
        "9": "05401E8744B13268D440BC2BAC1D503810E20146FF3EBDC28957965BB5A94D91",
    },
    "vtpm_security_flags": {
        "2": True,
        "3": False,
        "4": False,
        "5": False,
    },
}


def _document():
    return {
        "schema_version": 1,
        "image": {"filename": "1.7.0.qcow2", "sha256": "a" * 64},
        "tee_type": "sev-snp",
        "provider": "bare-metal",
        "role": "chute",
        "version": "1.7.0",
        "build_flags": {"debug_build": False, "debug_logging": False},
        "gpu_count": 0,
        "expected_gpus": [],
        "required_vcpu_sizes": [1, 2, 4, 8],
        "measurements": [
            {
                "name": f"cpu-baremetal-snp-genoa-1.7.0-{vcpus}vcpu",
                "vcpus": vcpus,
                "values": {"measurement": chr(ord("A") + index) * 96},
            }
            for index, vcpus in enumerate((1, 2, 4, 8))
        ],
    }


def test_canonical_provenance_rejects_reformatted_or_partial_payload():
    payload = canonical_provenance_bytes(_document()).decode()
    assert load_canonical_provenance(payload)["version"] == "1.7.0"
    with pytest.raises(ProvenanceError, match="not canonical"):
        load_canonical_provenance(payload.rstrip())

    document = _document()
    document["measurements"].pop()
    with pytest.raises(ProvenanceError, match="measurement order/classes"):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_gcp_provenance_requires_exact_boolean_security_flag_tags():
    document = _document()
    document["provider"] = "gcp"
    for measurement in document["measurements"]:
        measurement["name"] = measurement["name"].replace("baremetal", "gcp")
        measurement["values"]["vtpm_pcrs"] = {"8": "C" * 64, "9": "D" * 64}
        measurement["values"]["vtpm_security_flags"] = {
            "2": True,
            "3": False,
            "4": False,
            "5": False,
        }
    payload = canonical_provenance_bytes(document).decode()
    assert load_canonical_provenance(payload)["provider"] == "gcp"

    del document["measurements"][0]["values"]["vtpm_security_flags"]["5"]
    with pytest.raises(ProvenanceError, match="vtpm_security_flags"):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_api_image_and_chart_install_cosign_trust_root():
    root = Path(__file__).resolve().parents[2]
    dockerfile = (root / "Dockerfile").read_text()
    deployment = (root / "charts/templates/api-deployment.yaml").read_text()
    matches = list(
        re.finditer(
            r"^FROM\s+(?P<parent>\S+)\s+AS\s+(?P<name>[A-Za-z0-9_.-]+)\s*$",
            dockerfile,
            flags=re.MULTILINE,
        )
    )
    stages = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(dockerfile)
        stages[match.group("name")] = (
            match.group("parent"),
            dockerfile[match.end() : end],
        )

    assert stages["base"][0] == "ubuntu:24.04"
    assert stages["forge"][0] == "base"
    assert stages["api"][0] == "base"
    assert "ARG COSIGN_VERSION=2.5.3" in stages["base"][1]
    assert "cosign_${COSIGN_VERSION}_amd64.deb" in stages["base"][1]
    assert "cosign_${COSIGN_VERSION}_amd64.deb" not in stages["forge"][1]
    assert "RUN cosign verify-blob --help >/dev/null" in stages["api"][1]
    assert "TRUSTED_PROVENANCE_PUBLIC_KEY_PATH" in deployment
    assert "guest-provenance-public-key" in deployment


def _cosign_binary():
    return os.getenv("COSIGN_TEST_BINARY") or shutil.which("cosign")


def _generate_keys(cosign: str, prefix: Path) -> tuple[Path, Path]:
    environment = os.environ.copy()
    environment["COSIGN_PASSWORD"] = "test-provenance-password"
    process = subprocess.run(
        [
            cosign,
            "generate-key-pair",
            "--output-key-prefix",
            str(prefix),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert process.returncode == 0, process.stderr
    return Path(f"{prefix}.key"), Path(f"{prefix}.pub")


def _sign(cosign: str, key: Path, payload: Path, signature: Path) -> None:
    environment = os.environ.copy()
    environment["COSIGN_PASSWORD"] = "test-provenance-password"
    process = subprocess.run(
        [
            cosign,
            "sign-blob",
            "--yes",
            "--tlog-upload=false",
            "--key",
            str(key),
            "--output-signature",
            str(signature),
            str(payload),
        ],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
    )
    assert process.returncode == 0, process.stderr


def _sign_document(
    cosign: str,
    key: Path,
    tmp_path: Path,
    stem: str,
    document: dict,
) -> tuple[str, str]:
    payload = canonical_provenance_bytes(document)
    payload_path = tmp_path / f"{stem}.json"
    signature_path = tmp_path / f"{stem}.sig"
    payload_path.write_bytes(payload)
    _sign(cosign, key, payload_path, signature_path)
    return payload.decode(), signature_path.read_text()


def _production_tdx_fixture():
    version = "1.7.0"
    digest = hashlib.sha256(b"production TDX release activation regression").hexdigest()
    names = [f"cpu-baremetal-tdx-{version}-{vcpus}vcpu" for vcpus in _VCPU_SIZES]
    document = {
        "schema_version": 1,
        "image": {"filename": f"{version}.qcow2", "sha256": digest},
        "tee_type": "tdx",
        "provider": "bare-metal",
        "role": "chute",
        "version": version,
        "build_flags": {"debug_build": False, "debug_logging": False},
        "gpu_count": 0,
        "expected_gpus": [],
        "required_vcpu_sizes": list(_VCPU_SIZES),
        "measurements": [
            {
                "name": name,
                "vcpus": vcpus,
                "values": copy.deepcopy(_REAL_BAREMETAL_TDX_CAPTURE),
            }
            for name, vcpus in zip(names, _VCPU_SIZES, strict=True)
        ],
    }
    pins = [
        TeeMeasurementConfig(
            version=f"{version}-tdx-{vcpus}vcpu",
            name=name,
            tee_type="tdx",
            provider="bare-metal",
            mrtd=_REAL_BAREMETAL_TDX_CAPTURE["mrtd"],
            rtmr0=_REAL_BAREMETAL_TDX_CAPTURE["runtime_rtmrs"]["RTMR0"],
            rtmr1=_REAL_BAREMETAL_TDX_CAPTURE["runtime_rtmrs"]["RTMR1"],
            rtmr2=_REAL_BAREMETAL_TDX_CAPTURE["runtime_rtmrs"]["RTMR2"],
            runtime_rtmr3=_REAL_BAREMETAL_TDX_CAPTURE["runtime_rtmrs"]["RTMR3"],
            expected_gpus=[],
            gpu_count=0,
            debug=False,
            image_sha256=digest,
            image_measurement_names=list(names),
        )
        for name, vcpus in zip(names, _VCPU_SIZES, strict=True)
    ]
    image = {
        "url": f"https://artifacts.chutes.ai/releases/{version}.qcow2",
        "sha256": digest,
        "debug": False,
        "version": version,
        "measurement_names": names,
    }
    release = GuestRelease(
        release_id="production-tdx-regression",
        channel="release-test",
        tee_type="tdx",
        status="draft",
        images={"chute": image},
    )
    return release, image, document, pins


def _validate_production_image(
    release,
    image,
    pins,
    *,
    payload,
    signature,
    public_key,
    cosign,
):
    signed_image = {
        **image,
        "provenance_payload": payload,
        "provenance_signature": signature,
    }
    with (
        patch.object(
            release_service.settings,
            "trusted_provenance_public_key_path",
            public_key,
        ),
        patch.object(release_service.settings, "provenance_cosign_binary", cosign),
        patch.object(release_service.settings, "allow_debug_measurements", False),
        patch.object(release_service.settings, "skip_metagraph_check", False),
    ):
        release_service._validate_image_provenance(
            release,
            "chute",
            signed_image,
            {pin.name: pin for pin in pins},
        )


def test_generated_key_production_signed_tdx_activation_binds_real_capture(tmp_path):
    cosign = _cosign_binary()
    assert cosign, (
        "cosign is mandatory for release provenance tests; install it or set COSIGN_TEST_BINARY"
    )
    key, public_key = _generate_keys(cosign, tmp_path / "tdx-production")
    release, image, document, pins = _production_tdx_fixture()
    payload, signature = _sign_document(
        cosign,
        key,
        tmp_path,
        "tdx-production",
        document,
    )

    _validate_production_image(
        release,
        image,
        pins,
        payload=payload,
        signature=signature,
        public_key=public_key,
        cosign=cosign,
    )

    loaded = load_canonical_provenance(payload)
    assert loaded["provider"] == "bare-metal"
    assert loaded["tee_type"] == "tdx"
    assert loaded["role"] == "chute"
    assert loaded["version"] == image["version"]
    assert loaded["build_flags"] == {
        "debug_build": False,
        "debug_logging": False,
    }
    assert loaded["gpu_count"] == 0
    assert loaded["expected_gpus"] == []
    assert loaded["required_vcpu_sizes"] == list(_VCPU_SIZES)
    assert loaded["image"]["sha256"] == image["sha256"]
    assert [entry["name"] for entry in loaded["measurements"]] == image["measurement_names"]
    assert all(entry["values"] == _REAL_BAREMETAL_TDX_CAPTURE for entry in loaded["measurements"])


def test_production_signed_tdx_activation_rejects_tampered_measurement_and_signature(
    tmp_path,
):
    cosign = _cosign_binary()
    assert cosign, (
        "cosign is mandatory for release provenance tests; install it or set COSIGN_TEST_BINARY"
    )
    key, public_key = _generate_keys(cosign, tmp_path / "tdx-tamper")
    release, image, document, pins = _production_tdx_fixture()
    payload, signature = _sign_document(
        cosign,
        key,
        tmp_path,
        "tdx-original",
        document,
    )

    tampered_document = copy.deepcopy(document)
    tampered_document["measurements"][0]["values"]["runtime_rtmrs"]["RTMR3"] = "0" * 96
    tampered_payload, tampered_measurement_signature = _sign_document(
        cosign,
        key,
        tmp_path,
        "tdx-tampered-measurement",
        tampered_document,
    )
    with pytest.raises(release_service.ReleaseError, match="pin values do not match"):
        _validate_production_image(
            release,
            image,
            pins,
            payload=tampered_payload,
            signature=tampered_measurement_signature,
            public_key=public_key,
            cosign=cosign,
        )

    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    with pytest.raises(release_service.ReleaseError, match="untrusted provenance"):
        _validate_production_image(
            release,
            image,
            pins,
            payload=payload,
            signature=tampered_signature,
            public_key=public_key,
            cosign=cosign,
        )


def test_generated_key_production_signed_real_gcp_capture_round_trips_schema(tmp_path):
    """GCP uses the shared capture schema, while L0-managed activation remains bare-metal-only."""
    cosign = _cosign_binary()
    assert cosign, (
        "cosign is mandatory for release provenance tests; install it or set COSIGN_TEST_BINARY"
    )
    key, public_key = _generate_keys(cosign, tmp_path / "gcp-production")
    digest = hashlib.sha256(b"production GCP capture regression").hexdigest()
    document = {
        "schema_version": 1,
        "image": {"filename": "1.3.0.qcow2", "sha256": digest},
        "tee_type": "sev-snp",
        "provider": "gcp",
        "role": "chute",
        "version": "1.3.0",
        "build_flags": {"debug_build": False, "debug_logging": False},
        "gpu_count": 0,
        "expected_gpus": [],
        "required_vcpu_sizes": [4],
        "measurements": [
            {
                "name": "cpu-gcp-snp-milan-1.3.0-4vcpu",
                "vcpus": 4,
                "values": copy.deepcopy(_REAL_GCP_SNP_CAPTURE),
            }
        ],
    }
    payload, signature = _sign_document(
        cosign,
        key,
        tmp_path,
        "gcp-production",
        document,
    )

    verified = verify_provenance_signature(
        payload,
        signature,
        public_key,
        cosign_binary=cosign,
    )
    assert verified["provider"] == "gcp"
    assert verified["tee_type"] == "sev-snp"
    assert verified["build_flags"] == {
        "debug_build": False,
        "debug_logging": False,
    }
    assert verified["measurements"][0]["values"] == _REAL_GCP_SNP_CAPTURE

    tampered = copy.deepcopy(document)
    tampered["measurements"][0]["values"]["vtpm_pcrs"]["8"] = "0" * 64
    with pytest.raises(ProvenanceError, match="rejected provenance"):
        verify_provenance_signature(
            canonical_provenance_bytes(tampered).decode(),
            signature,
            public_key,
            cosign_binary=cosign,
        )


def test_cosign_verify_blob_rejects_wrong_signature_key_and_payload(tmp_path):
    cosign = _cosign_binary()
    assert cosign, (
        "cosign is mandatory for release provenance tests; install it or set COSIGN_TEST_BINARY"
    )
    key, public_key = _generate_keys(cosign, tmp_path / "trusted")
    _, wrong_public_key = _generate_keys(cosign, tmp_path / "wrong")
    payload = canonical_provenance_bytes(_document())
    payload_path = tmp_path / "provenance.json"
    signature_path = tmp_path / "provenance.sig"
    payload_path.write_bytes(payload)
    _sign(cosign, key, payload_path, signature_path)
    signature = signature_path.read_text()

    verified = verify_provenance_signature(
        payload.decode(), signature, public_key, cosign_binary=cosign
    )
    assert verified["image"]["sha256"] == "a" * 64

    with pytest.raises(ProvenanceError, match="rejected provenance"):
        verify_provenance_signature(
            payload.decode(), signature, wrong_public_key, cosign_binary=cosign
        )
    with pytest.raises(ProvenanceError, match="rejected provenance"):
        verify_provenance_signature(
            payload.decode(),
            ("A" if signature[0] != "A" else "B") + signature[1:],
            public_key,
            cosign_binary=cosign,
        )

    tampered = _document()
    tampered["image"]["sha256"] = "b" * 64
    with pytest.raises(ProvenanceError, match="rejected provenance"):
        verify_provenance_signature(
            canonical_provenance_bytes(tampered).decode(),
            signature,
            public_key,
            cosign_binary=cosign,
        )
