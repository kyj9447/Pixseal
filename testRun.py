from pathlib import Path

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
    extracted = result.get("extractedString", "")
    print("[Validate] verdict:", report["verdict"])
    print("[Validate] extracted string:", extracted)
    if selected_key:
        print(f"[Validate] decrypted with private key: {selected_key}")
    else:
        print("[Validate] used plain-text extraction")

def _prompt_bool(message, default=False):
    suffix = " [Y/n]: " if default else " [y/N]: "
    choice = input(message + suffix).strip().lower()
    if not choice:
        return default
    return choice in ("y", "yes")

def main():
    choice = input("1: Sign Image / 2: Validate Image >> ").strip()
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
    else:
        print("Invalid selection.")

if __name__ == "__main__":
    main()
