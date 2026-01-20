import base64
import hashlib
import json
from pprint import pprint
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

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

# JSON field names
PAYLOAD_FIELD = "payload"
PAYLOAD_SIG_FIELD = "payloadSig"
IMAGE_HASH_FIELD = "imageHash"
IMAGE_HASH_SIG_FIELD = "imageHashSig"


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
            key in payload_obj
            for key in (
                PAYLOAD_FIELD,
                PAYLOAD_SIG_FIELD,
                IMAGE_HASH_FIELD,
                IMAGE_HASH_SIG_FIELD,
            )
        ):
            continue
        return value, payload_obj
    return None, None


def _load_decrypt_key(key_text: str):
    if not isinstance(key_text, str):
        return None
    if "BEGIN PUBLIC KEY" not in key_text and "BEGIN RSA PUBLIC KEY" not in key_text:
        return None
    try:
        return serialization.load_pem_public_key(
            key_text.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return None


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
    is_placeholder_pixel = [False] * total

    byte_bits = []
    byte_indices = []
    chars = []
    placeholder_pattern = 'placeholder":"'
    in_placeholder = False

    for idx in range(total):

        # Progress Check
        print("readHiddenBit Current : ", idx, "/", total)

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

        bit = "1" if maxDiff % 2 == 0 else "0"
        append_bit(bit)
        byte_bits.append(bit)
        byte_indices.append(idx)

        # parse 8bits to byte
        if len(byte_bits) == 8:
            decimal = int("".join(byte_bits), 2)
            char = chr(decimal)
            chars.append(char)

            # Mark place holder index
            if in_placeholder and char != '"':
                for bit_idx in byte_indices:
                    is_placeholder_pixel[bit_idx] = True

            # Check placeholder pattern
            if "".join(chars).endswith(placeholder_pattern):
                in_placeholder = True

            # Check placeholder ends
            if in_placeholder and char == '"':
                in_placeholder = False
                chars = []

            byte_bits = []
            byte_indices = []

    # Erase place holder index for end sentinel
    end_marker_len_bits = len("END-VALIDATION") * 8
    if end_marker_len_bits > 0:
        tail_start = max(total - end_marker_len_bits, 0)
        for idx in range(tail_start, total):
            is_placeholder_pixel[idx] = False

    return "".join(bits), is_placeholder_pixel


def compute_image_hash_with_placeholder_mask(
    imageInput: ImageInput, placeholder_mask: list[bool]
) -> str:
    img = SimpleImage.open(imageInput)
    width, height = img.size
    total = width * height
    if len(placeholder_mask) != total:
        raise ValueError("Placeholder mask size mismatch")

    pattern_bits = [int(bit) for bit in format(ord("0"), "08b")]
    placeholder_bit_index = 0
    pixels = bytearray(img._pixels)
    for idx in range(total):
        print("compute_image_hash Current : ", idx, "/", total)
        if not placeholder_mask[idx]:
            continue
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

        if maxDiff == diffR:
            targetColorValue = r
        elif maxDiff == diffG:
            targetColorValue = g
        else:
            targetColorValue = b

        addDirection = 1 if targetColorValue < 127 else -1
        expected_bit = pattern_bits[placeholder_bit_index % 8]
        placeholder_bit_index += 1
        current_bit = 1 if maxDiff % 2 == 0 else 0

        if current_bit != expected_bit:
            if maxDiff == diffR:
                r += addDirection
            if maxDiff == diffG:
                g += addDirection
            if maxDiff == diffB:
                b += addDirection

        pixels[base] = r
        pixels[base + 1] = g
        pixels[base + 2] = b

    return hashlib.sha256(pixels).hexdigest()


def deduplicate(arr):
    deduplicated = []
    freq = {}
    most_common = ""
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


# main
def validateImage(imageInput: ImageInput):
    """
    Extract the embedded payload from an image and optionally decrypt it.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        privKeyPath: Optional path to a PEM-encoded RSA public key used to
            decrypt the extracted ciphertext.

    Returns:
        Dict with the most common extracted string, decrypted sequence, and
        a validation report describing the sentinel checks and verdict.
    """
    resultBinary, placeholderMask = readHiddenBit(imageInput)
    imageHash = compute_image_hash_with_placeholder_mask(imageInput, placeholderMask)
    resultString = binaryToString(resultBinary)
    deduplicated, most_common = deduplicate(resultString.split("\n"))
    resultJSON = json.loads(most_common)

    print("imageHash\n", imageHash)
    print("resultJSON\n", resultJSON["imageHash"])

    # pprint(resultString)

    return {}
