from pathlib import Path
from pprint import pprint
import os
import time
import builtins

from Pixseal import SimpleImage


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

PUBLIC_KEY = "assets/RSA/public_key.pem"
PRIVATE_KEY = "assets/RSA/private_key.pem"
DEFAULT_PAYLOAD = "AutoTest123!"
INPUT_IMAGE = "assets/original.png"
OUTPUT_IMAGE = "assets/signed_original.png"


# Helper to shorten long lists for display
def shorten(seq, max_items=6):
    if len(seq) <= max_items:
        return seq
    head = seq[:2]
    tail = seq[-2:]
    return head + ["..."] + tail


# Helper to truncate long decrypted entries for display
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


def sign_demo():
    signed: SimpleImage = signImage(INPUT_IMAGE, DEFAULT_PAYLOAD, PRIVATE_KEY)
    signed.save(str(OUTPUT_IMAGE))
    print(f"[Sign] saved -> {OUTPUT_IMAGE}")
    if PRIVATE_KEY:
        print(f"[Sign] signed with private key: {PRIVATE_KEY}")
    else:
        print("[Sign] plain-text payload injected")


def validate_demo():

    result = validateImage(OUTPUT_IMAGE)
    truncate_decrypted_entries(result)
    report = result["validationReport"]
    print("[Validate] verdict:", report["verdict"])
    print("[Validate] extracted string:", result.get("extractedString"))

    print("\nValidation Report\n")
    pprint(result)


def file_roundtrip_demo():
    print("\n[PathTest] Signing using file path input...")
    signed_from_path = signImage(INPUT_IMAGE, DEFAULT_PAYLOAD, str(PUBLIC_KEY))
    signed_from_path.save(str(OUTPUT_IMAGE))
    print(f"[PathTest] Saved path-based signed image -> {OUTPUT_IMAGE}")

    print("[PathTest] Validating using file path input...")
    path_result = validateImage(str(OUTPUT_IMAGE))
    truncate_decrypted_entries(path_result)
    path_report = path_result["validationReport"]
    print("[PathTest] verdict:", path_report["verdict"])
    print("[PathTest] extracted:", path_result.get("extractedString"))
    pprint(path_result)


def memory_roundtrip_demo():
    bytes_output = Path(OUTPUT_IMAGE)
    # ============ Test with File Stream Input ========
    print("\n[Memory] Loading image bytes from disk...")
    image_bytes = Path(INPUT_IMAGE).read_bytes()
    print("[Memory] Signing using in-memory bytes...")
    signed_image = signImage(image_bytes, DEFAULT_PAYLOAD, str(PUBLIC_KEY))
    signed_image.save(str(bytes_output))
    print(f"[Memory] Saved signed image -> {bytes_output}")

    print("[Memory] Validating using in-memory bytes...")
    signed_bytes = bytes_output.read_bytes()
    result = validateImage(signed_bytes)
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

    profiler = LineProfiler()
    profiled_sign = profiler(signImage)
    profiled_validate = profiler(validateImage)

    output = Path(OUTPUT_IMAGE)
    print("\n[Profiler] Using Auto Benchmark inputs.")
    print(
        f"image={INPUT_IMAGE}, payload='{DEFAULT_PAYLOAD}', public_key={PUBLIC_KEY}, "
        f"private_key={PRIVATE_KEY}"
    )
    signed_image: SimpleImage = profiled_sign(INPUT_IMAGE, DEFAULT_PAYLOAD, PUBLIC_KEY)
    signed_image.save(str(output))
    print(f"[Profiler] Signed image saved -> {output}")

    print("[Profiler] Validating image...")
    result = profiled_validate(str(output), PRIVATE_KEY)
    truncate_decrypted_entries(result)
    pprint(result)

    print("\n[Profiler] Line Profile Result")
    profiler.print_stats()


# def _prompt_bool(message, default=False):
#     suffix = " [Y/n]: " if default else " [y/N]: "
#     choice = input(message + suffix).strip().lower()
#     if not choice:
#         return default
#     return choice in ("y", "yes")


def main():
    choice = input(
        "1: Sign Image / 2: Validate Image / 3: Auto Benchmark / 4: File Path Test / 5: Memory API Test / 6: Line Profiler >> "
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
        file_roundtrip_demo()

    elif choice == "5":
        memory_roundtrip_demo()

    elif choice == "6":
        line_profile_demo()

    else:
        print("Invalid selection.")


if __name__ == "__main__":
    main()
