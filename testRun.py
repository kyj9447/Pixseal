from pathlib import Path
from pprint import pprint
import time

from pip_package.Pixseal import signImage, validateImage

DEFAULT_PUBLIC_KEY = "SSL/public_key.pem"
DEFAULT_PRIVATE_KEY = "SSL/private_key.pem"

def sign_demo(image="original.png", payload=None, encrypt=False, pubkey=None):
    payload = payload or "!Validation:kyj9447@mailmail.com"
    output = Path("signed_" + Path(image).name)
    selected_key = pubkey if encrypt else None
    if encrypt and not selected_key:
        selected_key = str(DEFAULT_PUBLIC_KEY)
    signed = signImage(image, payload, selected_key)
    signed.save(output)
    print(f"[Sign] saved -> {output}")
    if selected_key:
        print(f"[Sign] encrypted with public key: {selected_key}")
    else:
        print("[Sign] plain-text payload injected")

def validate_demo(image="signed_original.png", decrypt=False, privkey=None):
    selected_key = privkey if decrypt else None
    if decrypt and not selected_key:
        selected_key = str(DEFAULT_PRIVATE_KEY)

    result = validateImage(image, selected_key)
    report = result["validationReport"]
    extracted = result.get("extractedString1", "")
    print("[Validate] verdict:", report["verdict"])
    print("[Validate] extracted string:", extracted)
    if selected_key:
        print(f"[Validate] decrypted with private key: {selected_key}")
    else:
        print("[Validate] used plain-text extraction")

    print("\nValidation Report\n")
    pprint(result)

def file_roundtrip_demo(
    image="original.png",
    payload="!Validation:kyj9447@mailmail.com",
    public_key=DEFAULT_PUBLIC_KEY,
    private_key=DEFAULT_PRIVATE_KEY,
):
    output = Path("signed_path_test.png")
    print("\n[PathTest] Signing using file path input...")
    signed_from_path = signImage(image, payload, str(public_key))
    signed_from_path.save(output)
    print(f"[PathTest] Saved path-based signed image -> {output}")

    print("[PathTest] Validating using file path input...")
    path_result = validateImage(str(output), str(private_key))
    path_report = path_result["validationReport"]
    path_payload = path_result.get("extractedString1")
    print("[PathTest] verdict:", path_report["verdict"])
    print("[PathTest] extracted:", path_payload)
    pprint(path_result)

def memory_roundtrip_demo(
    image="original.png",
    payload="!Validation:kyj9447@mailmail.com",
    public_key=DEFAULT_PUBLIC_KEY,
    private_key=DEFAULT_PRIVATE_KEY,
):
    bytes_output = Path("signed_bytes_test.png")
    # ============ Test with File Stream Input ========
    print("\n[Memory] Loading image bytes from disk...")
    image_bytes = Path(image).read_bytes()

    print("[Memory] Signing using in-memory bytes...")
    signed_image = signImage(image_bytes, payload, str(public_key))
    signed_image.save(bytes_output)
    print(f"[Memory] Saved signed image -> {bytes_output}")

    print("[Memory] Validating using in-memory bytes...")
    signed_bytes = bytes_output.read_bytes()
    result = validateImage(signed_bytes, str(private_key))
    report = result["validationReport"]
    extracted = result.get("extractedString1")

    print("[Memory] (bytes) verdict:", report["verdict"])
    print("[Memory] (bytes) extracted string:", extracted)
    pprint(result)

def _prompt_bool(message, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    choice = input(message + suffix).strip().lower()
    if not choice:
        return default
    return choice in ("y", "yes")

def main():
    choice = input("1: Sign Image / 2: Validate Image / 3: Auto Benchmark / 4: File Path Test / 5: Memory API Test >> ").strip()
    
    if choice == "1":
        image = input("Image file (default original.png): ").strip() or "original.png"
        msg = input("Payload to inject (Enter=default): ")
        encrypt = _prompt_bool("Encrypt with RSA public key?", default=True)
        pubkey = None
        if encrypt:
            pubkey_input = input(f"Public key path (default {DEFAULT_PUBLIC_KEY}): ").strip()
            pubkey = pubkey_input or None
        sign_demo(image, msg or None, encrypt, pubkey)
    
    elif choice == "2":
        image = input("Image to validate (default signed_original.png): ").strip() or "signed_original.png"
        decrypt = _prompt_bool("Decrypt with RSA private key?", default=True)
        privkey = None
        if decrypt:
            privkey_input = input(f"Private key path (default {DEFAULT_PRIVATE_KEY}): ").strip()
            privkey = privkey_input or None
        validate_demo(image, decrypt, privkey)
    
    elif choice == "3":
        print("Encrypted 'AutoTest123!' will be injected\n")

        start = time.time()

        image = "original.png"
        msg = "AutoTest123!"
        encrypt = True
        sign_demo(image, msg, encrypt)

        check1 = time.time()
        print(f"Signing time: {check1 - start:.6f} seconds\n")

        image2 = "signed_original.png"
        decrypt = True
        validate_demo(image2, decrypt)

        check2 = time.time()
        print(f"Validating time: {check2 - check1:.6f} seconds\n")
        print(f"Total time: {check2 - start:.6f} seconds\n")

    elif choice == "4":
        file_roundtrip_demo()

    elif choice == "5":
        memory_roundtrip_demo()
        
    else:
        print("Invalid selection.")

if __name__ == "__main__":
    main()
