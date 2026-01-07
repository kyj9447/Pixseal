import base64
import hashlib
import json
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .imageSigner import BinaryProvider, addHiddenBit

# profiler check
try:
    from line_profiler import profile
except ImportError:

    def profile(func):
        return func


# Dynamic typing
from .simpleImage import (
    ImageInput as _RuntimeImageInput,
    SimpleImage as _RuntimeSimpleImage,
)

if TYPE_CHECKING:
    from .simpleImage_py import ImageInput, SimpleImage
else:
    ImageInput = _RuntimeImageInput
    SimpleImage = _RuntimeSimpleImage


PAYLOAD_FIELD = "payload"
PUBLIC_KEY_FIELD = "publicKey"
HASH_FIELD = "imageHash"


def _build_payload_json(payload_cipher: str, public_key_text: str, image_hash: str) -> str:
    payload_obj = {
        PAYLOAD_FIELD: payload_cipher,
        PUBLIC_KEY_FIELD: public_key_text,
        HASH_FIELD: image_hash,
    }
    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=True)


def _is_json_like(value: str) -> bool:
    return value.lstrip().startswith("{")


def _extract_payload_json(deduplicated):
    for value in deduplicated:
        if not _is_json_like(value):
            continue
        if not value.rstrip().endswith("}"):
            continue
        try:
            payload_obj = json.loads(value)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload_obj, dict):
            continue
        if not all(
            key in payload_obj for key in (PAYLOAD_FIELD, PUBLIC_KEY_FIELD, HASH_FIELD)
        ):
            continue
        return value, payload_obj
    return None, None


def _load_private_key(privKeyPath):
    with open(privKeyPath, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )


def _decrypt_ciphertext(cipher_text: str, private_key) -> str:
    cipher_bytes = base64.b64decode(cipher_text)
    plain_bytes = private_key.decrypt(
        cipher_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plain_bytes.decode("utf-8")


def binaryToString(binaryCode):
    string = []
    for i in range(0, len(binaryCode), 8):
        byte = binaryCode[i : i + 8]
        decimal = int(byte, 2)
        character = chr(decimal)
        string.append(character)
    return "".join(string)


@profile
def readHiddenBit(imageInput: ImageInput):
    img = SimpleImage.open(imageInput)
    width, height = img.size
    pixels = img._pixels  # direct buffer access for performance
    total = width * height
    bits = []
    append_bit = bits.append

    for idx in range(total):
        base = idx * 3
        r = pixels[base]
        g = pixels[base + 1]
        b = pixels[base + 2]

        diffR = r - 127
        if diffR < 0:
            diffR = -diffR
        diffG = g - 127
        if diffG < 0:
            diffG = -diffG
        diffB = b - 127
        if diffB < 0:
            diffB = -diffB

        maxDiff = diffR
        if diffG > maxDiff:
            maxDiff = diffG
        if diffB > maxDiff:
            maxDiff = diffB

        append_bit("1" if maxDiff % 2 == 0 else "0")

    return "".join(bits)


def deduplicate(arr):
    deduplicated = []
    freq = {}
    most_common = None
    most_count = 0

    for i, value in enumerate(arr):
        freq[value] = freq.get(value, 0) + 1
        if freq[value] > most_count:
            most_count = freq[value]
            most_common = value

        if i == 0 or value != arr[i - 1]:
            deduplicated.append(value)

    return deduplicated, most_common


def tailCheck(arr: list[str]):
    if len(arr) != 4:
        return None  # Not required

    full_cipher = arr[1]  # complete ciphertext
    truncated_cipher = arr[2]  # incomplete ciphertext

    return full_cipher.startswith(truncated_cipher)


def buildValidationReport(
    decrypted, tailCheck: bool, skipPlain: bool = False, hashCheck=None
):
    # Length after deduplication/decryption
    arrayLength = len(decrypted)

    # 1. Check that the deduplicated sequence length is valid
    lengthCheck = arrayLength in (3, 4)

    # 2. Validate start/end markers
    startCheck = decrypted[0] == "START-VALIDATION" if decrypted else False
    endCheck = decrypted[-1] == "END-VALIDATION" if decrypted else False

    # 4. Determine whether payload was successfully decrypted
    decryptedPayload = decrypted[1] if len(decrypted) > 1 else ""
    isDecrypted = bool(decryptedPayload) and not decryptedPayload.endswith("==")

    checkList = [lengthCheck, startCheck, endCheck, isDecrypted]
    # 5. Parse tailCheck result
    if tailCheck is None:
        tailCheckResult = "Not Required"
    else:
        tailCheckResult = tailCheck
        checkList.append(tailCheckResult)

    if hashCheck is None:
        hashCheckResult = "Not Checked"
    else:
        hashCheckResult = hashCheck
        checkList.append(hashCheckResult)

    # Overall verdict requires every check to pass
    verdict = all(checkList)

    result = {
        "arrayLength": arrayLength,
        "lengthCheck": lengthCheck,
        "startCheck": startCheck,
        "endCheck": endCheck,
        "isDecrypted": isDecrypted,
        "tailCheckResult": tailCheckResult,
        "hashCheckResult": hashCheckResult,
        "verdict": verdict,
    }

    if skipPlain:
        result["decryptSkipMessage"] = (
            "Skip decrypt: payload was plain or corrupted text despite decrypt request."
        )

    return result


def decrypt_array(deduplicated, private_key):
    decrypted = []
    decryptError = False
    for item in deduplicated:
        if not item or _is_json_like(item):
            decrypted.append(item)
            continue
        try:
            decrypted.append(_decrypt_ciphertext(item, private_key))
        except Exception as exc:
            print(exc)
            decryptError = True
            decrypted.append(item)

    skippedPlain = decryptError

    return decrypted, skippedPlain


def _compute_placeholder_hash(
    imageInput,
    start_marker: str,
    end_marker: str,
    payload_cipher: str,
    public_key_text: str,
    hash_placeholder: str,
) -> str:
    payload_placeholder = _build_payload_json(
        payload_cipher, public_key_text, hash_placeholder
    )
    hiddenBinary = BinaryProvider(
        hiddenString=payload_placeholder + "\n",
        startString=start_marker + "\n",
        endString="\n" + end_marker,
    )
    placeholder_image = addHiddenBit(imageInput, hiddenBinary)
    return hashlib.sha256(placeholder_image._pixels).hexdigest()


# main
def validateImage(imageInput: ImageInput, privKeyPath=None):
    """
    Extract the embedded payload from an image and optionally decrypt it.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        privKeyPath: Optional path to a PEM-encoded RSA private key used to
            decrypt the extracted ciphertext.

    Returns:
        Dict with the most common extracted string, decrypted sequence, and
        a validation report describing the sentinel checks and verdict.
    """
    resultBinary = readHiddenBit(imageInput)
    resultString = binaryToString(resultBinary)
    splited = resultString.split("\n")
    deduplicated, most_common = deduplicate(splited)

    payload_line, payload_obj = _extract_payload_json(deduplicated)
    private_key = _load_private_key(privKeyPath) if privKeyPath else None

    if private_key:
        decrypted, skippedPlain = decrypt_array(deduplicated, private_key)
    else:
        decrypted = deduplicated
        skippedPlain = False

    payload_plain = None
    hash_plain = None
    public_key_text = None
    computed_hash = None
    hash_check = None

    if payload_obj:
        payload_cipher = payload_obj.get(PAYLOAD_FIELD)
        public_key_text = payload_obj.get(PUBLIC_KEY_FIELD)
        hash_cipher = payload_obj.get(HASH_FIELD)

        if (
            isinstance(payload_cipher, str)
            and isinstance(public_key_text, str)
            and isinstance(hash_cipher, str)
            and hash_cipher
            and deduplicated
        ):
            hash_placeholder = "0" * len(hash_cipher)
            start_marker = deduplicated[0]
            end_marker = deduplicated[-1]
            computed_hash = _compute_placeholder_hash(
                imageInput,
                start_marker,
                end_marker,
                payload_cipher,
                public_key_text,
                hash_placeholder,
            )
            if private_key:
                try:
                    hash_plain = _decrypt_ciphertext(hash_cipher, private_key).strip()
                except Exception as exc:
                    print(exc)
            if hash_plain:
                hash_check = hash_plain.lower() == computed_hash

        if private_key and isinstance(payload_cipher, str):
            try:
                payload_plain = _decrypt_ciphertext(payload_cipher, private_key)
            except Exception as exc:
                print(exc)

        if payload_line and payload_plain is not None and payload_line in deduplicated:
            payload_index = deduplicated.index(payload_line)
            decrypted[payload_index] = payload_plain

    extracted_string = payload_line or most_common

    report = buildValidationReport(
        decrypted=decrypted,
        tailCheck=tailCheck(deduplicated),
        skipPlain=skippedPlain,
        hashCheck=hash_check,
    )

    return {
        "extractedString": extracted_string,
        "decrypted": decrypted,
        "payload": payload_plain,
        "publicKey": public_key_text,
        "imageHash": hash_plain,
        "computedImageHash": computed_hash,
        "validationReport": report,
    }
