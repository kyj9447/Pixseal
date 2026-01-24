from pathlib import Path
from pprint import pprint
import os
import time
import builtins
from Pixseal import SimpleImage

from pip_package.Pixseal.keyInput import resolve_private_key, resolve_public_key
from pip_package.Pixseal import signImage, validateImage


def _choose_backend():
    choice = (input("Select SimpleImage backend (Enter=cython / 1=cython / 2=python fallback): ").strip().lower())
    backend = "python" if choice in {"2", "python"} else "cython"
    os.environ["PIXSEAL_SIMPLEIMAGE_BACKEND"] = backend
    print(f"[Init] SimpleImage backend set to: {backend}")


_choose_backend()

try:
    from line_profiler import LineProfiler  # type: ignore
except ImportError:  # pragma: no cover
    LineProfiler = None

PRIVATE_KEY_PATH = "assets/CA/pixseal-dev-root.key"
CERT_PATH = "assets/CA/pixseal-dev-root.crt"
DEFAULT_PAYLOAD = "AutoTest123!"
INPUT_IMAGE = "assets/original.png"
CURRUPTED_IMAGE = "assets/currupted_signed_original.png"
OUTPUT_IMAGE = "signed_original.png"

PRIVATE_KEY = resolve_private_key(PRIVATE_KEY_PATH)
PUBLIC_KEY = resolve_public_key(CERT_PATH)


def sign_demo(keyless: bool = False):
    signed: SimpleImage = signImage(INPUT_IMAGE, DEFAULT_PAYLOAD, PRIVATE_KEY, keyless)
    signed.save(str(OUTPUT_IMAGE))
    print(f"[Sign] saved -> {OUTPUT_IMAGE}")
    print(f"[Sign] signed with private key: {PRIVATE_KEY_PATH}")


def validate_demo(keyless: bool = False):
    result = validateImage(OUTPUT_IMAGE, PUBLIC_KEY, keyless)
    print("\nValidation Report\n")
    pprint(result, sort_dicts=False)


def validate_fail_demo(keyless: bool = False):
    result = validateImage(CURRUPTED_IMAGE, PUBLIC_KEY, keyless)
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
    is_kernprof = (builtin_profiler is not None
                   and getattr(builtin_profiler, "__class__", object).__module__.split(".")[0] == "line_profiler")

    if not is_kernprof:
        print("Line profiling is only available when running via `kernprof -l testRun.py`.")
        print("Please rerun this script with kernprof and select option 7 again.")
        return

    profiler = LineProfiler()
    profiled_sign = profiler(signImage)
    profiled_validate = profiler(validateImage)

    output = Path(OUTPUT_IMAGE)
    print("\n[Profiler] Using Auto Benchmark inputs.")
    print(f"image={INPUT_IMAGE}, payload='{DEFAULT_PAYLOAD}', cert={CERT_PATH}, "
          f"private_key={PRIVATE_KEY_PATH}")
    signed_image: SimpleImage = profiled_sign(INPUT_IMAGE, DEFAULT_PAYLOAD, PRIVATE_KEY)
    signed_image.save(str(output))
    print(f"[Profiler] Signed image saved -> {output}")

    print("[Profiler] Validating image...")
    result = profiled_validate(str(output), PUBLIC_KEY)
    pprint(result, sort_dicts=False)

    print("\n[Profiler] Line Profile Result")
    profiler.print_stats()


def multi_pass_test(passes: int = 3):
    if passes <= 0:
        print("[MultiPass] passes must be >= 1.")
        return

    print(f"\n[MultiPass] passes={passes}")
    image_input = INPUT_IMAGE
    all_ok = True

    for idx in range(1, passes + 1):
        signed_image = signImage(image_input, DEFAULT_PAYLOAD, PRIVATE_KEY)
        result = validateImage(signed_image, PUBLIC_KEY)
        hash_ok = bool(result.get("imageHashCompareCheck", {}).get("result"))
        verdict_ok = bool(result.get("verdict"))
        pass_ok = hash_ok and verdict_ok
        all_ok = all_ok and pass_ok
        print(f"[MultiPass] pass {idx}: hash_ok={hash_ok}, verdict={verdict_ok}")
        image_input = signed_image

    print(f"[MultiPass] overall={all_ok}")


def main():
    choice = input("""
1: Sign Image
2: Validate Image
3: Validate Image (Fail Test)
4: Auto Benchmark
5: Auto Benchmark (Key Less)
6: Memory API Test
7: Line Profiler
8: Validation Multi Pass Test
>> 
""").strip()

    if choice == "1":
        sign_demo()

    elif choice == "2":
        validate_demo()

    elif choice == "3":
        validate_fail_demo()

    elif choice == "4":
        print("Payload " + DEFAULT_PAYLOAD + " will be injected\n")
        start = time.time()

        sign_demo()
        check1 = time.time()
        print(f"Signing time: {check1 - start:.6f} seconds\n")

        validate_demo()
        check2 = time.time()
        print(f"Validating time: {check2 - check1:.6f} seconds\n")

        print(f"Total time: {check2 - start:.6f} seconds\n")

    elif choice == "5":
        print("Payload " + DEFAULT_PAYLOAD + " will be injected/ without Key based Channel Selector\n")
        start = time.time()

        sign_demo(True)
        check1 = time.time()
        print(f"Signing time: {check1 - start:.6f} seconds\n")

        validate_demo(True)
        check2 = time.time()
        print(f"Validating time: {check2 - check1:.6f} seconds\n")

        print(f"Total time: {check2 - start:.6f} seconds\n")

    elif choice == "6":
        memory_roundtrip_demo()

    elif choice == "7":
        line_profile_demo()

    elif choice == "8":
        multi_pass_test(passes=3)

    else:
        print("Invalid selection.")


if __name__ == "__main__":
    main()
