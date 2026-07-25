"""Canonical provenance parser and real cosign detached-signature integration."""

import copy
import base64
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from api.config import TeeMeasurementConfig
from api.releases import service as release_service
from api.releases.provenance import (
    ProvenanceError,
    canonical_provenance_bytes,
    gpu_measurement_fingerprint,
    gpu_profile_contract_fingerprint,
    load_canonical_provenance,
    select_direct_tdx_profile,
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


def _direct_document():
    profiles = [
        {
            "id": f"{vcpus}vcpu-{memory_mib // 1024}g",
            "vcpus": vcpus,
            "memory_mib": memory_mib,
        }
        for vcpus in (1, 2, 4, 8)
        for memory_mib in (8192, 16384, 32768, 65536)
    ]
    measurements = []
    for index, profile in enumerate(profiles):
        profile_digest = f"{index:X}" * 96
        rtmrs = {
            "RTMR0": profile_digest,
            "RTMR1": "B" * 96,
            "RTMR2": "C" * 96,
            "RTMR3": "D" * 96,
        }
        boot_rtmrs = {**rtmrs, "RTMR3": "0" * 96}
        measurements.append(
            {
                "name": f"cpu-baremetal-tdx-1.9.0-{profile['id']}",
                "profile_id": profile["id"],
                "vcpus": profile["vcpus"],
                "memory_mib": profile["memory_mib"],
                "values": {
                    "mrtd": "A" * 96,
                    "boot_rtmrs": boot_rtmrs,
                    "runtime_rtmrs": dict(rtmrs),
                },
            }
        )
    return {
        "schema_version": 2,
        "image": {"filename": "1.9.0.qcow2", "sha256": "a" * 64},
        "tee_type": "tdx",
        "provider": "bare-metal",
        "role": "chute",
        "version": "1.9.0",
        "build_flags": {"debug_build": False, "debug_logging": False},
        "gpu_count": 0,
        "expected_gpus": [],
        "required_profiles": profiles,
        "launch_contract": {
            "boot_mode": "direct",
            "sha256": "1" * 64,
            "qemu_binary_sha256": "2" * 64,
            "qemu_package_version": "1:10.1.0+ds-5ubuntu2.7",
            "machine_type": "pc-q35-10.1",
            "firmware_sha256": "3" * 64,
            "image_sha256": "a" * 64,
            "kernel_sha256": "4" * 64,
            "initrd_sha256": "5" * 64,
            "cmdline_sha256": "6" * 64,
            "verity_roothash": "7" * 64,
            "kernel_measurement_mode": "qemu-patched",
        },
        "measurements": measurements,
    }


def _gpu_document():
    profile = {
        "id": "b200-8gpu",
        "model": "B200",
        "pci_vendor_id": "10de",
        "pci_device_ids": ["2901"],
        "expected_gpu_identifiers": ["b200"],
        "gpu_count": 8,
        "vram_mib": 196608,
        "allocation": {
            "kind": "whole-fabric",
            "groups": 1,
            "devices_per_group": 8,
            "allow_partial": False,
        },
        "host": {
            "logical_cpus": 192,
            "sockets": 2,
            "reserved_logical_cpus": 16,
        },
        "guest": {
            "vcpus": 176,
            "memory_mib": 1990656,
            "smp": "176,sockets=2,cores=88,threads=1",
        },
        "qemu": {
            "distribution": "ubuntu:26.04",
            "upstream_version": "10.2.1",
            "binary": "qemu-system-x86_64",
            "package": "qemu-system-x86",
            "package_version": "1:10.2.1+ds-1ubuntu4",
            "machine_type": "pc-q35-10.2",
            "cpu": "host,-avx10",
            "predictor_cpu": "max,phys-bits=46",
        },
        "firmware": {"filename": "OVMF.inteltdx.fd"},
        "topology": {
            "kind": "numa-pxb",
            "host_numa_nodes": 2,
            "gpu_numa_nodes": [0, 0, 0, 0, 1, 1, 1, 1],
            "nvswitch_count": 0,
            "infiniband_count": 0,
            "nvlink_links_per_pair": 18,
        },
        "pci": {
            "root_port_start": 16,
            "root_slot_start": 8,
            "pxb_bus_start": 128,
            "pxb_bus_stride": 32,
            "pxb_root_slot_start": 24,
            "gpu_bar_mib": 262144,
            "use_gpu_bar_fw_cfg": True,
        },
        "smbios": [],
        "fw_cfg": [f"name=opt/ovmf/X-PciMmio64Mb{index},string=262144" for index in range(1, 9)],
        "option_roms": {"virtio_net": "", "vfio_gpu_romfile": None},
        "policy": {
            "cc_mode": "on",
            "ppcie_mode": "off",
            "passthrough_nvswitches": False,
            "passthrough_infiniband": False,
            "fabric_manager_required": True,
            "host_bridge_policy": "exclude-cx7-smdl-sw_mng",
            "reset_args": [
                "--reset-with-sbr",
                "--reset-after-cc-mode-switch",
            ],
        },
    }
    profile_contract = {
        "schema": "chutes.gpu-tdx-launch-profiles",
        "version": 1,
        "allocation_policy": "whole-fabric",
        "management_modes": ["platform", "miner"],
        "device_order": [
            "root",
            "network",
            "config",
            "scratch",
            "gpu-infra:miner-only",
            "vsock",
            "iommufd",
            "pxb:profile-order",
            "vfio:assigned-order",
            "fw_cfg:profile-order",
            "option-rom:profile",
        ],
        "profiles": [profile],
        "unsupported_profiles": [],
    }
    measurements = []
    for index, mode in enumerate(("platform", "miner")):
        runtime = {
            "RTMR0": chr(ord("B") + index) * 96,
            "RTMR1": "D" * 96,
            "RTMR2": chr(ord("E") + index) * 96,
            "RTMR3": ("A" if mode == "platform" else "F") * 96,
        }
        measurements.append(
            {
                "name": f"gpu-baremetal-tdx-1.11.0-b200-8gpu-{mode}",
                "profile_id": "b200-8gpu",
                "management_mode": mode,
                "values": {
                    "mrtd": "C" * 96,
                    "boot_rtmrs": {**runtime, "RTMR3": "0" * 96},
                    "runtime_rtmrs": runtime,
                },
            }
        )
    return {
        "schema_version": 3,
        "compute_type": "gpu",
        "role": "gpu",
        "tee_type": "tdx",
        "provider": "bare-metal",
        "version": "1.11.0",
        "image": {"filename": "1.11.0.qcow2", "sha256": "1" * 64},
        "build_flags": {"debug_build": False, "debug_logging": False},
        "source_manifest_sha256": "2" * 64,
        "build_inputs_sha256": "3" * 64,
        "launch_public_key_id": "4" * 64,
        "launch_public_key_epoch": 1,
        "supported_management_modes": ["platform", "miner"],
        "profile_contract": profile_contract,
        "profile_contract_sha256": gpu_profile_contract_fingerprint(profile_contract),
        "artifacts": {
            "boot_mode": "direct",
            "root_mode": "dm-verity",
            "image_sha256": "1" * 64,
            "kernel_sha256": "3" * 64,
            "initrd_sha256": "4" * 64,
            "cmdline_sha256": {"platform": "5" * 64, "miner": "6" * 64},
            "verity_roothash": "7" * 64,
            "kernel_measurement_mode": "efi-image-as-is",
        },
        "launch_environments": [
            {
                "profile_id": "b200-8gpu",
                "firmware_filename": "OVMF.inteltdx.fd",
                "firmware_sha256": "8" * 64,
                "qemu_binary": "qemu-system-x86_64",
                "qemu_binary_sha256": "9" * 64,
                "qemu_package": "qemu-system-x86",
                "qemu_package_version": "1:10.2.1+ds-1ubuntu4",
                "machine_type": "pc-q35-10.2",
                "cpu": "host,-avx10",
                "predictor_cpu": "max,phys-bits=46",
            }
        ],
        "measurements": measurements,
        "hardware_evidence": [
            {
                "measurement_name": measurement["name"],
                "quote_sha256": f"{index + 1:x}" * 64,
                "ccel_sha256": f"{index + 3:x}" * 64,
                "ccel_replay_sha256": f"{index + 5:x}" * 64,
            }
            for index, measurement in enumerate(measurements)
        ],
    }


def _gpu_l0_bootstrap(document):
    digest = "a" * 64

    def artifact(name):
        return {
            "url": f"https://artifacts.chutes.ai/l0/{name}",
            "size": 1,
            "sha256": digest,
        }

    environment = document["launch_environments"][0]
    return {
        "manifest": {
            "schema": "chutes.l0-bootstrap",
            "version": 2,
            "tee_type": "tdx",
            "compute_type": "gpu",
            "channel": "canary",
            "generation": 1,
            "key_id": "publisher",
            "key_epoch": 1,
            "l0_version": "1.11.0",
            "kernel": artifact("kernel"),
            "initrd": artifact("initrd"),
            "cmdline": artifact("cmdline"),
            "squashfs": artifact("squashfs"),
            "validator_ca_sha256": digest,
            "issued_at": "2026-07-24T00:00:00Z",
            "expires_at": "2026-07-25T00:00:00Z",
            "storage_closure": {
                "schema": "chutes.gpu-l0-storage-closure",
                "version": 1,
                "source_release_id": "cpu-storage-release",
                "image_version": "1.11.0",
                "image_sha256": digest,
                "kernel_sha256": digest,
                "initrd_sha256": digest,
                "cmdline_sha256": digest,
                "measurement_names": ["storage-tdx-1.11.0"],
                "launch_contract": {
                    "role": "storage",
                    "qemu_package": "qemu-system-x86",
                    "qemu_package_version": "1:10.2.0",
                    "qemu_binary": "qemu-system-x86_64",
                    "qemu_binary_sha256": digest,
                    "machine_type": "pc-q35-10.2",
                    "firmware_filename": "OVMF.inteltdx.fd",
                    "firmware_sha256": digest,
                },
            },
            "gpu_profile_id": environment["profile_id"],
            "gpu_qemu_sha256s": [environment["qemu_binary_sha256"]],
            "gpu_tdvf_sha256s": [environment["firmware_sha256"]],
            "gpu_launch_public_key_id": document["launch_public_key_id"],
            "gpu_launch_public_key_epoch": document["launch_public_key_epoch"],
            "gpu_build_inputs_sha256": document["build_inputs_sha256"],
        },
        "signature": base64.b64encode(b"\0" * 64).decode(),
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


def test_direct_tdx_provenance_selects_bounded_resource_profile():
    document = load_canonical_provenance(canonical_provenance_bytes(_direct_document()).decode())

    profile = select_direct_tdx_profile(
        document,
        requested_vcpus=2,
        requested_memory_mib=9000,
    )

    assert profile == {"id": "2vcpu-16g", "vcpus": 2, "memory_mib": 16384}


def test_direct_tdx_provenance_rejects_profile_measurement_drift():
    document = _direct_document()
    document["measurements"][0]["memory_mib"] = 16384

    with pytest.raises(ProvenanceError, match="does not match required profile"):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


@pytest.mark.parametrize(
    ("phase", "register", "value", "error"),
    [
        ("boot_rtmrs", "RTMR3", "F" * 96, "initial zero value"),
        ("runtime_rtmrs", "RTMR3", "0" * 96, "bind the runtime chain"),
        ("runtime_rtmrs", "RTMR0", "F" * 96, "RTMR0 cannot change"),
    ],
)
def test_direct_tdx_provenance_rejects_invalid_runtime_transition(phase, register, value, error):
    document = _direct_document()
    document["measurements"][0]["values"][phase][register] = value

    with pytest.raises(ProvenanceError, match=error):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_direct_tdx_provenance_rejects_duplicate_measurement_tuple():
    document = _direct_document()
    document["measurements"][1]["values"] = copy.deepcopy(document["measurements"][0]["values"])

    with pytest.raises(ProvenanceError, match="duplicates another profile"):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_gpu_provenance_requires_exact_keys_and_complete_dual_mode_matrix():
    document = _gpu_document()
    loaded = load_canonical_provenance(canonical_provenance_bytes(document).decode())
    assert [entry["management_mode"] for entry in loaded["measurements"]] == [
        "platform",
        "miner",
    ]

    missing = copy.deepcopy(document)
    del missing["profile_contract"]["profiles"][0]["option_roms"]
    with pytest.raises(ProvenanceError, match="missing=.*option_roms"):
        load_canonical_provenance(canonical_provenance_bytes(missing).decode())

    unknown = copy.deepcopy(document)
    unknown["artifacts"]["legacy_cmdline_sha256"] = "0" * 64
    with pytest.raises(ProvenanceError, match="unknown=.*legacy_cmdline"):
        load_canonical_provenance(canonical_provenance_bytes(unknown).decode())

    partial = copy.deepcopy(document)
    partial["measurements"].pop()
    with pytest.raises(ProvenanceError, match="complete ordered profile"):
        load_canonical_provenance(canonical_provenance_bytes(partial).decode())


@pytest.mark.parametrize(
    "path",
    [
        ("schema_version",),
        ("profile_contract", "version"),
        ("profile_contract", "profiles", 0, "allocation", "groups"),
        ("profile_contract", "profiles", 0, "allocation", "devices_per_group"),
        ("profile_contract", "profiles", 0, "host", "logical_cpus"),
        ("profile_contract", "profiles", 0, "gpu_count"),
    ],
)
def test_gpu_provenance_rejects_boolean_integer_fields(path):
    document = _gpu_document()
    target = document
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = True

    with pytest.raises(ProvenanceError):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_gpu_provenance_rejects_uncharacterized_b300_as_measurable():
    document = _gpu_document()
    profile = document["profile_contract"]["profiles"][0]
    profile["id"] = "b300-8gpu"
    profile["model"] = "B300"
    document["profile_contract_sha256"] = hashlib.sha256(
        canonical_provenance_bytes(document["profile_contract"])
    ).hexdigest()

    with pytest.raises(ProvenanceError, match="B300 is uncharacterized"):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_gpu_measurement_fingerprint_is_versioned_and_mode_bound():
    document = _gpu_document()
    platform, miner = document["measurements"]

    platform_fingerprint = gpu_measurement_fingerprint(document, platform)
    assert re.fullmatch(r"[0-9a-f]{64}", platform_fingerprint)
    assert platform_fingerprint != gpu_measurement_fingerprint(document, miner)

    changed = copy.deepcopy(document)
    changed["measurements"][0]["values"]["runtime_rtmrs"]["RTMR2"] = "F" * 96
    changed["measurements"][0]["values"]["boot_rtmrs"]["RTMR2"] = "F" * 96
    assert gpu_measurement_fingerprint(changed, changed["measurements"][0]) != platform_fingerprint


def test_gpu_release_validation_binds_exact_pins_and_dual_sidecars(monkeypatch):
    document = _gpu_document()
    monkeypatch.setattr(
        release_service,
        "_configured_gpu_launch_signer_identity",
        lambda: (
            document["launch_public_key_id"],
            document["launch_public_key_epoch"],
        ),
    )
    document["image"]["filename"] = "1.11.0-debug.qcow2"
    document["build_flags"] = {"debug_build": True, "debug_logging": False}
    names = [entry["name"] for entry in document["measurements"]]
    profile = document["profile_contract"]["profiles"][0]
    pins = []
    for entry in document["measurements"]:
        values = entry["values"]
        pins.append(
            TeeMeasurementConfig(
                version="1.11.0",
                name=entry["name"],
                tee_type="tdx",
                provider="bare-metal",
                debug=True,
                mrtd=values["mrtd"],
                rtmr0=values["runtime_rtmrs"]["RTMR0"],
                rtmr1=values["runtime_rtmrs"]["RTMR1"],
                rtmr2=values["runtime_rtmrs"]["RTMR2"],
                boot_rtmr3=values["boot_rtmrs"]["RTMR3"],
                runtime_rtmr3=values["runtime_rtmrs"]["RTMR3"],
                expected_gpus=profile["expected_gpu_identifiers"],
                gpu_count=profile["gpu_count"],
                image_sha256=document["image"]["sha256"],
                image_measurement_names=names,
                compute_type="gpu",
                role="gpu",
                management_mode=entry["management_mode"],
                gpu_profile_id=entry["profile_id"],
                gpu_profile_contract_sha256=document["profile_contract_sha256"],
                gpu_measurement_fingerprint=gpu_measurement_fingerprint(
                    document,
                    entry,
                ),
                gpu_fingerprint_version=1,
                provenance_schema_version=3,
            )
        )
    image = {
        "url": "https://artifacts.chutes.ai/releases/1.11.0-debug.qcow2",
        "sha256": document["image"]["sha256"],
        "debug": True,
        "version": "1.11.0",
        "measurement_names": names,
        "kernel_sha256": document["artifacts"]["kernel_sha256"],
        "initrd_sha256": document["artifacts"]["initrd_sha256"],
        "cmdline_sha256": document["artifacts"]["cmdline_sha256"],
        "provenance_payload": canonical_provenance_bytes(document).decode(),
        "provenance_signature": None,
    }
    release = GuestRelease(
        release_id="gpu-release",
        channel="canary",
        tee_type="tdx",
        compute_type="gpu",
        status="draft",
        images={"gpu": image, "l0": {"bootstrap": _gpu_l0_bootstrap(document)}},
    )
    old_allow_debug = release_service.settings.allow_debug_measurements
    old_skip_metagraph = release_service.settings.skip_metagraph_check
    try:
        release_service.settings.allow_debug_measurements = True
        release_service.settings.skip_metagraph_check = True
        release_service._validate_gpu_image_provenance(
            release,
            image,
            {pin.name: pin for pin in pins},
        )
        monkeypatch.setattr(
            release_service,
            "_configured_gpu_launch_signer_identity",
            lambda: ("f" * 64, document["launch_public_key_epoch"]),
        )
        with pytest.raises(
            release_service.ReleaseError,
            match="currently configured signer",
        ):
            release_service._validate_gpu_image_provenance(
                release,
                image,
                {pin.name: pin for pin in pins},
            )
        monkeypatch.setattr(
            release_service,
            "_configured_gpu_launch_signer_identity",
            lambda: (
                document["launch_public_key_id"],
                document["launch_public_key_epoch"],
            ),
        )
        release.images["l0"]["bootstrap"]["manifest"]["gpu_launch_public_key_epoch"] = 2
        with pytest.raises(
            release_service.ReleaseError,
            match="QEMU/TDVF/key/build closure",
        ):
            release_service._validate_gpu_image_provenance(
                release,
                image,
                {pin.name: pin for pin in pins},
            )
        release.images["l0"]["bootstrap"]["manifest"]["gpu_launch_public_key_epoch"] = 1
        pins[0].gpu_measurement_fingerprint = "0" * 64
        with pytest.raises(release_service.ReleaseError, match="Loaded GPU pin values"):
            release_service._validate_gpu_image_provenance(
                release,
                image,
                {pin.name: pin for pin in pins},
            )
    finally:
        release_service.settings.allow_debug_measurements = old_allow_debug
        release_service.settings.skip_metagraph_check = old_skip_metagraph


def test_gpu_activation_rejects_absent_signer_and_derives_current_identity(
    monkeypatch,
):
    historical = _gpu_document()
    assert (
        load_canonical_provenance(canonical_provenance_bytes(historical).decode())[
            "launch_public_key_id"
        ]
        == historical["launch_public_key_id"]
    )
    monkeypatch.setattr(
        release_service,
        "settings",
        SimpleNamespace(
            launch_config_private_key=None,
            gpu_launch_key_epoch=1,
        ),
    )
    with pytest.raises(release_service.ReleaseError, match="current configured P-256"):
        release_service._configured_gpu_launch_signer_identity()

    private_key = ec.generate_private_key(ec.SECP256R1())
    monkeypatch.setattr(
        release_service,
        "settings",
        SimpleNamespace(
            launch_config_private_key=private_key,
            gpu_launch_key_epoch=9,
        ),
    )
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    assert release_service._configured_gpu_launch_signer_identity() == (
        hashlib.sha256(public_der).hexdigest(),
        9,
    )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("mrtd", "F" * 96, "share one MRTD"),
        ("runtime_rtmr3", "E" * 96, "share one runtime RTMR3"),
    ],
)
def test_direct_tdx_provenance_requires_image_wide_measurements(field, value, error):
    document = _direct_document()
    if field == "mrtd":
        document["measurements"][1]["values"]["mrtd"] = value
    else:
        document["measurements"][1]["values"]["runtime_rtmrs"]["RTMR3"] = value

    with pytest.raises(ProvenanceError, match=error):
        load_canonical_provenance(canonical_provenance_bytes(document).decode())


def test_direct_tdx_release_accepts_complete_ram_qualified_matrix():
    document = _direct_document()
    names = [entry["name"] for entry in document["measurements"]]
    pins = []
    for entry in document["measurements"]:
        values = entry["values"]
        pins.append(
            TeeMeasurementConfig(
                version=f"1.9.0-tdx-{entry['profile_id']}",
                name=entry["name"],
                tee_type="tdx",
                provider="bare-metal",
                mrtd=values["mrtd"],
                rtmr0=values["runtime_rtmrs"]["RTMR0"],
                rtmr1=values["runtime_rtmrs"]["RTMR1"],
                rtmr2=values["runtime_rtmrs"]["RTMR2"],
                boot_rtmr3=values["boot_rtmrs"]["RTMR3"],
                runtime_rtmr3=values["runtime_rtmrs"]["RTMR3"],
                profile_id=entry["profile_id"],
                vcpus=entry["vcpus"],
                memory_mib=entry["memory_mib"],
                expected_gpus=[],
                gpu_count=0,
                image_sha256=document["image"]["sha256"],
                image_measurement_names=names,
            )
        )
    image = {
        "url": "https://artifacts.chutes.ai/releases/1.9.0.qcow2",
        "sha256": document["image"]["sha256"],
        "debug": False,
        "version": "1.9.0",
        "measurement_names": names,
        "provenance_payload": canonical_provenance_bytes(document).decode(),
        "provenance_signature": "verified-by-test",
    }
    release = GuestRelease(
        release_id="direct-tdx",
        channel="canary",
        tee_type="tdx",
        status="draft",
        images={"chute": image},
    )

    with patch.object(
        release_service,
        "verify_provenance_signature",
        return_value=document,
    ):
        release_service._validate_image_provenance(
            release,
            "chute",
            image,
            {pin.name: pin for pin in pins},
        )

    assert image["kernel_sha256"] == document["launch_contract"]["kernel_sha256"]
    assert image["initrd_sha256"] == document["launch_contract"]["initrd_sha256"]
    assert image["cmdline_sha256"] == document["launch_contract"]["cmdline_sha256"]

    mismatched_image = {**image, "kernel_sha256": "f" * 64}
    with patch.object(
        release_service,
        "verify_provenance_signature",
        return_value=document,
    ):
        with pytest.raises(release_service.ReleaseError, match="kernel_sha256"):
            release_service._validate_image_provenance(
                release,
                "chute",
                mismatched_image,
                {pin.name: pin for pin in pins},
            )

    pins[0].profile_id = "2vcpu-8g"
    with patch.object(
        release_service,
        "verify_provenance_signature",
        return_value=document,
    ):
        with pytest.raises(release_service.ReleaseError, match="loaded pin values"):
            release_service._validate_image_provenance(
                release,
                "chute",
                image,
                {pin.name: pin for pin in pins},
            )


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
    document = _direct_document()
    version = document["version"]
    digest = document["image"]["sha256"]
    names = [entry["name"] for entry in document["measurements"]]
    pins = [
        TeeMeasurementConfig(
            version=f"{version}-tdx-{entry['profile_id']}",
            name=entry["name"],
            tee_type="tdx",
            provider="bare-metal",
            mrtd=entry["values"]["mrtd"],
            rtmr0=entry["values"]["runtime_rtmrs"]["RTMR0"],
            rtmr1=entry["values"]["runtime_rtmrs"]["RTMR1"],
            rtmr2=entry["values"]["runtime_rtmrs"]["RTMR2"],
            boot_rtmr3=entry["values"]["boot_rtmrs"]["RTMR3"],
            runtime_rtmr3=entry["values"]["runtime_rtmrs"]["RTMR3"],
            profile_id=entry["profile_id"],
            vcpus=entry["vcpus"],
            memory_mib=entry["memory_mib"],
            expected_gpus=[],
            gpu_count=0,
            debug=False,
            image_sha256=digest,
            image_measurement_names=list(names),
        )
        for entry in document["measurements"]
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
    assert loaded["schema_version"] == 2
    assert loaded["required_profiles"] == document["required_profiles"]
    assert loaded["image"]["sha256"] == image["sha256"]
    assert [entry["name"] for entry in loaded["measurements"]] == image["measurement_names"]
    assert loaded["measurements"] == document["measurements"]


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
    for measurement in tampered_document["measurements"]:
        measurement["values"]["runtime_rtmrs"]["RTMR3"] = "E" * 96
    tampered_payload, tampered_measurement_signature = _sign_document(
        cosign,
        key,
        tmp_path,
        "tdx-tampered-measurement",
        tampered_document,
    )
    with pytest.raises(release_service.ReleaseError, match="loaded pin values"):
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


def test_shared_complete_gpu_provenance_fixture_has_canonical_digest():
    fixture = Path(__file__).resolve().parents[1] / "fixtures/gpu_provenance_v3_complete.json"
    document = load_canonical_provenance(fixture.read_text())
    assert len(document["profile_contract"]["profiles"]) == 3
    assert len(document["measurements"]) == 6
    assert (
        hashlib.sha256(fixture.read_bytes()).hexdigest()
        == "d472f52d5a0e0bb141d90504b02a0edd2114d67d02a9f5018f406c4143bbe12b"
    )


def test_offline_provenance_verification_explicitly_ignores_tlog():
    import inspect

    source = inspect.getsource(verify_provenance_signature)
    assert '"--key"' in source
    assert '"--signature"' in source
    assert '"--insecure-ignore-tlog"' in source


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
