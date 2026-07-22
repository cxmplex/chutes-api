"""Live podman/cosign acceptance against an attested-session Nginx registry proxy."""

import os
import shutil
import subprocess
import urllib.error
import urllib.request

import pytest


PROXY = os.getenv("REGISTRY_E2E_PROXY")
REFERENCE = os.getenv("REGISTRY_E2E_REFERENCE")
COSIGN_KEY = os.getenv("REGISTRY_E2E_COSIGN_KEY")
UNRELATED_BLOB = os.getenv("REGISTRY_E2E_UNRELATED_BLOB")

pytestmark = pytest.mark.skipif(
    not all((PROXY, REFERENCE, COSIGN_KEY, UNRELATED_BLOB)),
    reason=(
        "REGISTRY_E2E_PROXY, REGISTRY_E2E_REFERENCE, REGISTRY_E2E_COSIGN_KEY, "
        "and REGISTRY_E2E_UNRELATED_BLOB are required"
    ),
)


def _run(command):
    process = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert process.returncode == 0, process.stderr


def test_podman_cosign_probe_and_descriptor_denial_through_nginx():
    podman = shutil.which("podman")
    cosign = shutil.which("cosign")
    assert podman, "podman is required for live registry acceptance"
    assert cosign, "cosign is required for live registry acceptance"

    with urllib.request.urlopen(f"{PROXY.rstrip('/')}/v2/", timeout=30) as response:
        assert response.status == 200

    _run([podman, "pull", REFERENCE])
    _run(
        [
            cosign,
            "verify",
            "--key",
            COSIGN_KEY,
            REFERENCE,
        ]
    )

    with pytest.raises(urllib.error.HTTPError) as denied:
        urllib.request.urlopen(
            f"{PROXY.rstrip('/')}{UNRELATED_BLOB}",
            timeout=30,
        )
    assert denied.value.code in {401, 403}
