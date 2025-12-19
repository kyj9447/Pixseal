from pathlib import Path
from pprint import pprint
import os
import time
import builtins


def _choose_backend():
    choice = (
        input(
            "Select SimpleImage backend "
            "(Enter=cython / 1=cython / 2=python fallback): "
        )
        .strip()
        .lower()
    )
    backend = "python" if choice in {"2", "python"} else "cython"
    os.environ["PIXSEAL_SIMPLEIMAGE_BACKEND"] = backend
    print(f"[Init] SimpleImage backend set to: {backend}")


_choose_backend()

try:
    from line_profiler import LineProfiler  # type: ignore
except ImportError:  # pragma: no cover
    LineProfiler = None

from pip_package.Pixseal import signImage, validateImage

DEFAULT_PUBLIC_KEY = "assets/RSA/public_key.pem"
DEFAULT_PRIVATE_KEY = "assets/RSA/private_key.pem"


def shorten(seq, max_items=6):
    if len(seq) <= max_items:
        return seq
    head = seq[:2]
    tail = seq[-2:]
    return head + ["..."] + tail


def truncate_decrypted_entries(result):
    decrypted = result.get("decrypted", [])
    if not decrypted:
        return
    most_common = result.get("extractedString")
    if not most_common:
        return
    max_len = len(most_common)
    truncated = []
    for value in decrypted:
        if value in ("START-VALIDATION", "END-VALIDATION") or value == most_common:
            truncated.append(value)
            continue
        if len(value) > max_len:
            truncated.append(value[:max_len] + "...")
        else:
            truncated.append(value)
    result["decrypted"] = shorten(truncated)


def sign_demo(image="assets/original.png", payload=None, encrypt=False, pubkey=None):
    payload = payload or "!Validation:kyj9447@mailmail.com"
    output = Path("assets/signed_" + Path(image).name)
    selected_key = pubkey if encrypt else None
    if encrypt and not selected_key:
        selected_key = str(DEFAULT_PUBLIC_KEY)
    signed = signImage(image, payload, selected_key)
    signed.save(str(output))
    print(f"[Sign] saved -> {output}")
    if selected_key:
        print(f"[Sign] encrypted with public key: {selected_key}")
    else:
        print("[Sign] plain-text payload injected")


def validate_demo(image="assets/signed_original.png", decrypt=False, privkey=None):
    selected_key = privkey if decrypt else None
    if decrypt and not selected_key:
        selected_key = str(DEFAULT_PRIVATE_KEY)

    result = validateImage(image, selected_key)
    truncate_decrypted_entries(result)
    report = result["validationReport"]
    print("[Validate] verdict:", report["verdict"])
    print("[Validate] extracted string:", result.get("extractedString"))
    if selected_key:
        print(f"[Validate] decrypted with private key: {selected_key}")
    else:
        print("[Validate] used plain-text extraction")

    print("\nValidation Report\n")
    pprint(result)


def file_roundtrip_demo(
    image="assets/original.png",
    payload="!Validation:kyj9447@mailmail.com",
    public_key=DEFAULT_PUBLIC_KEY,
    private_key=DEFAULT_PRIVATE_KEY,
):
    output = Path("assets/signed_original.png")
    print("\n[PathTest] Signing using file path input...")
    signed_from_path = signImage(image, payload, str(public_key))
    signed_from_path.save(str(output))
    print(f"[PathTest] Saved path-based signed image -> {output}")

    print("[PathTest] Validating using file path input...")
    path_result = validateImage(str(output), str(private_key))
    truncate_decrypted_entries(path_result)
    path_report = path_result["validationReport"]
    print("[PathTest] verdict:", path_report["verdict"])
    print("[PathTest] extracted:", path_result.get("extractedString"))
    pprint(path_result)


def memory_roundtrip_demo(
    image="assets/original.png",
    payload="!Validation:kyj9447@mailmail.com",
    public_key=DEFAULT_PUBLIC_KEY,
    private_key=DEFAULT_PRIVATE_KEY,
):
    bytes_output = Path("assets/signed_original.png")
    # ============ Test with File Stream Input ========
    print("\n[Memory] Loading image bytes from disk...")
    image_bytes = Path(image).read_bytes()

    print("[Memory] Signing using in-memory bytes...")
    signed_image = signImage(image_bytes, payload, str(public_key))
    signed_image.save(str(bytes_output))
    print(f"[Memory] Saved signed image -> {bytes_output}")

    print("[Memory] Validating using in-memory bytes...")
    signed_bytes = bytes_output.read_bytes()
    result = validateImage(signed_bytes, str(private_key))
    truncate_decrypted_entries(result)
    report = result["validationReport"]

    print("[Memory] (bytes) verdict:", report["verdict"])
    print("[Memory] (bytes) extracted string:", result.get("extractedString"))
    pprint(result)


def line_profile_demo():
    if LineProfiler is None:
        print(
            "line_profiler is not installed. "
            "Please run `pip install line_profiler` and try again."
        )
        return

    builtin_profiler = getattr(builtins, "profile", None)
    is_kernprof = (
        builtin_profiler is not None
        and getattr(builtin_profiler, "__class__", object).__module__.split(".")[0]
        == "line_profiler"
    )

    if not is_kernprof:
        print(
            "Line profiling is only available when running via `kernprof -l testRun.py`."
        )
        print("Please rerun this script with kernprof and select option 6 again.")
        return

    image = "assets/original.png"
    payload = "AutoTest123!"
    pubkey = str(DEFAULT_PUBLIC_KEY)
    privkey = str(DEFAULT_PRIVATE_KEY)

    profiler = LineProfiler()
    profiled_sign = profiler(signImage)
    profiled_validate = profiler(validateImage)

    output = Path("assets/signed_original.png")
    print("\n[Profiler] Using Auto Benchmark inputs.")
    print(
        f"image={image}, payload='{payload}', public_key={pubkey}, "
        f"private_key={privkey}"
    )
    signed_image = profiled_sign(image, payload, pubkey)
    signed_image.save(str(output))
    print(f"[Profiler] Signed image saved -> {output}")

    print("[Profiler] Validating image...")
    result = profiled_validate(str(output), privkey)
    truncate_decrypted_entries(result)
    pprint(result)

    print("\n[Profiler] Line Profile Result")
    profiler.print_stats()


def _prompt_bool(message, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    choice = input(message + suffix).strip().lower()
    if not choice:
        return default
    return choice in ("y", "yes")


def main():
    choice = input(
        "1: Sign Image / 2: Validate Image / 3: Auto Benchmark / 4: File Path Test / 5: Memory API Test / 6: Line Profiler >> "
    ).strip()

    if choice == "1":
        image = (
            input("Image file (default assets/original.png): ").strip()
            or "assets/original.png"
        )
        msg = input("Payload to inject (Enter=default): ")
        encrypt = _prompt_bool("Encrypt with RSA public key?", default=True)
        pubkey = None
        if encrypt:
            pubkey_input = input(
                f"Public key path (default {DEFAULT_PUBLIC_KEY}): "
            ).strip()
            pubkey = pubkey_input or None
        sign_demo(image, msg or None, encrypt, pubkey)

    elif choice == "2":
        image = (
            input("Image to validate (default assets/signed_original.png): ").strip()
            or "assets/signed_original.png"
        )
        decrypt = _prompt_bool("Decrypt with RSA private key?", default=True)
        privkey = None
        if decrypt:
            privkey_input = input(
                f"Private key path (default {DEFAULT_PRIVATE_KEY}): "
            ).strip()
            privkey = privkey_input or None
        validate_demo(image, decrypt, privkey)

    elif choice == "3":
        print("Encrypted 'AutoTest123!' will be injected\n")

        start = time.time()

        image = "assets/original.png"
        msg = "AutoTest123!"
        encrypt = True
        sign_demo(image, msg, encrypt)

        check1 = time.time()
        print(f"Signing time: {check1 - start:.6f} seconds\n")

        image2 = "assets/signed_original.png"
        decrypt = True
        validate_demo(image2, decrypt)

        check2 = time.time()
        print(f"Validating time: {check2 - check1:.6f} seconds\n")
        print(f"Total time: {check2 - start:.6f} seconds\n")

    elif choice == "4":
        file_roundtrip_demo()

    elif choice == "5":
        memory_roundtrip_demo()

    elif choice == "6":
        line_profile_demo()

    else:
        print("Invalid selection.")


if __name__ == "__main__":
    main()
