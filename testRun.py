from pathlib import Path
from pprint import pprint
import os
import time
import builtins
from typing import cast
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives import serialization

from Pixseal import SimpleImage


def _choose_backend():
    choice = (input(
        "Select SimpleImage backend "
        "(Enter=cython / 1=cython / 2=python fallback): ").strip().lower())
    backend = "python" if choice in {"2", "python"} else "cython"
    os.environ["PIXSEAL_SIMPLEIMAGE_BACKEND"] = backend
    print(f"[Init] SimpleImage backend set to: {backend}")


_choose_backend()

try:
    from line_profiler import LineProfiler  # type: ignore
except ImportError:  # pragma: no cover
    LineProfiler = None

from pip_package.Pixseal import signImage, validateImage

PRIVATE_KEY_PATH = "assets/RSA/private_key.pem"
PUBLIC_KEY_PATH = "assets/RSA/public_key.pem"
DEFAULT_PAYLOAD = "AutoTest123!"
INPUT_IMAGE = "assets/original.png"
OUTPUT_IMAGE = "assets/signed_original.png"

# Load privateKey
private_key_path = Path(PRIVATE_KEY_PATH)
if not private_key_path.is_file():
    raise FileNotFoundError(f"Private key file not found: {PRIVATE_KEY_PATH}")
private_pem_data = private_key_path.read_bytes()
if b"BEGIN PRIVATE KEY" not in private_pem_data:
    raise ValueError("Provided file does not contain a valid private key")

PRIVATE_KEY: RSAPrivateKey = cast(
    RSAPrivateKey,
    serialization.load_pem_private_key(private_pem_data, password=None))

# Load publicKey
public_key_path = Path(PUBLIC_KEY_PATH)
if not public_key_path.is_file():
    raise FileNotFoundError(f"Public key file not found: {PUBLIC_KEY_PATH}")
public_pem_data = public_key_path.read_bytes()
if b"BEGIN PUBLIC KEY" not in public_pem_data:
    raise ValueError("Provided file does not contain a valid public key")

PUBLIC_KEY: RSAPublicKey = cast(
    RSAPublicKey, serialization.load_pem_public_key(public_pem_data))


def sign_demo():
    signed: SimpleImage = signImage(INPUT_IMAGE, DEFAULT_PAYLOAD, PRIVATE_KEY)
    signed.save(str(OUTPUT_IMAGE))
    print(f"[Sign] saved -> {OUTPUT_IMAGE}")
    print(f"[Sign] signed with private key: {PRIVATE_KEY_PATH}")


def validate_demo():
    result = validateImage(OUTPUT_IMAGE, PUBLIC_KEY)
    print("\nValidation Report\n")
    pprint(result, sort_dicts=False)


def memory_roundtrip_demo():
    print("\n[Memory] Loading image bytes from disk...")
    image_bytes = Path(INPUT_IMAGE).read_bytes()

    print("[Memory] Signing using in-memory bytes...")
    signed_image = signImage(image_bytes, DEFAULT_PAYLOAD, PRIVATE_KEY)

    print("[Memory] Validating using in-memory bytes...")
    result = validateImage(signed_image, PUBLIC_KEY)

    pprint(result, sort_dicts=False)


def line_profile_demo():
    if LineProfiler is None:
        print("line_profiler is not installed. "
              "Please run `pip install line_profiler` and try again.")
        return

    builtin_profiler = getattr(builtins, "profile", None)
    is_kernprof = (builtin_profiler is not None and getattr(
        builtin_profiler, "__class__", object).__module__.split(".")[0]
                   == "line_profiler")

    if not is_kernprof:
        print(
            "Line profiling is only available when running via `kernprof -l testRun.py`."
        )
        print(
            "Please rerun this script with kernprof and select option 6 again."
        )
        return

    profiler = LineProfiler()
    profiled_sign = profiler(signImage)
    profiled_validate = profiler(validateImage)

    output = Path(OUTPUT_IMAGE)
    print("\n[Profiler] Using Auto Benchmark inputs.")
    print(
        f"image={INPUT_IMAGE}, payload='{DEFAULT_PAYLOAD}', public_key={PUBLIC_KEY_PATH}, "
        f"private_key={PRIVATE_KEY_PATH}")
    signed_image: SimpleImage = profiled_sign(INPUT_IMAGE, DEFAULT_PAYLOAD,
                                              PRIVATE_KEY)
    signed_image.save(str(output))
    print(f"[Profiler] Signed image saved -> {output}")

    print("[Profiler] Validating image...")
    result = profiled_validate(str(output), PUBLIC_KEY)
    pprint(result, sort_dicts=False)

    print("\n[Profiler] Line Profile Result")
    profiler.print_stats()

def main():
    choice = input(
        "1: Sign Image / 2: Validate Image / 3: Auto Benchmark / 4: Memory API Test / 5: Line Profiler >> "
    ).strip()

    if choice == "1":
        sign_demo()

    elif choice == "2":
        validate_demo()

    elif choice == "3":
        print("Encrypted " + DEFAULT_PAYLOAD + " will be injected\n")
        start = time.time()

        sign_demo()
        check1 = time.time()
        print(f"Signing time: {check1 - start:.6f} seconds\n")

        validate_demo()
        check2 = time.time()
        print(f"Validating time: {check2 - check1:.6f} seconds\n")

        print(f"Total time: {check2 - start:.6f} seconds\n")

    elif choice == "4":
        memory_roundtrip_demo()

    elif choice == "5":
        line_profile_demo()

    else:
        print("Invalid selection.")


if __name__ == "__main__":
    main()
