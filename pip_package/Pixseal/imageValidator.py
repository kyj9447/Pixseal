import hashlib
import json
from typing import Any, Sequence
import base64
import binascii

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from line_profiler import profile

from .imageSigner import (
    BinaryProvider,
    build_channel_key_array,
    addHiddenBit,
    build_payload_json,
    make_channel_key,
)
from .keyInput import PublicKeyInput, resolve_public_key
from .simpleImage import ImageInput, SimpleImage

# JSON field names
PAYLOAD_FIELD: str = "payload"
PAYLOAD_SIG_FIELD: str = "payloadSig"
IMAGE_HASH_FIELD: str = "imageHash"
IMAGE_HASH_SIG_FIELD: str = "imageHashSig"

# Sentinel
START_SENTINEL: str = "START-VALIDATION"
END_SENTINEL: str = "END-VALIDATION"

# Report print option
TAIL_HEAD_LEN: int = 20
TAIL_SUFFIX_LEN: int = 10
FULL_TAIL_EXTRA_LEN: int = 20


@profile
def _is_json_like(value: str) -> bool:
    return value.lstrip().startswith("{")


@profile
def _extract_payload_json(deduplicated: list[str]) -> dict[str, Any]:
    for value in deduplicated:
        if not _is_json_like(value):
            continue
        if not value.rstrip().endswith("}"):
            continue
        try:
            payload_obj: dict[str, Any] = json.loads(value)
        except json.JSONDecodeError:
            continue
        if not all(key in payload_obj for key in (
                PAYLOAD_FIELD,
                PAYLOAD_SIG_FIELD,
                IMAGE_HASH_FIELD,
                IMAGE_HASH_SIG_FIELD,
        )):
            continue
        return payload_obj
    return {}


@profile
def binaryToString(bits: list[int]) -> str:
    ba = bytearray()
    acc = 0
    count = 0

    for bit in bits:
        acc = (acc << 1) | bit
        count += 1
        if count == 8:
            ba.append(acc)
            acc = 0
            count = 0

    return ba.decode("utf-8", errors="ignore")


@profile
def readHiddenBit(
    imageInput: ImageInput,
    channel_key: bytes,
    keyless: bool,
) -> list[int]:
    img = (imageInput if isinstance(imageInput, SimpleImage) else SimpleImage.open(imageInput))
    width, height = img.size
    pixels: bytearray = img.pixels  # direct buffer access for performance
    total = width * height
    bits: list[int] = []
    append_bit = bits.append

    if keyless:
        for idx in range(total):
            # Progress Check

            base = idx * 3
            r = pixels[base]
            g = pixels[base + 1]
            b = pixels[base + 2]

            r_sel = r & 0xFE
            g_sel = g & 0xFE
            b_sel = b & 0xFE
            diffR = r_sel - 127
            if diffR < 0:
                diffR = -diffR
            diffG = g_sel - 127
            if diffG < 0:
                diffG = -diffG
            diffB = b_sel - 127
            if diffB < 0:
                diffB = -diffB

            maxDiff = diffR
            if diffG > maxDiff:
                maxDiff = diffG
            if diffB > maxDiff:
                maxDiff = diffB

            if maxDiff == diffR:
                bit = r & 1
            elif maxDiff == diffG:
                bit = g & 1
            else:
                bit = b & 1
            append_bit(bit)
    else:
        channel_key_arr: bytes = build_channel_key_array(total, channel_key)

        for idx in range(total):
            base = idx * 3
            # channel = _choose_channel(idx, channel_key)
            channel: int = channel_key_arr[idx]
            bit: int = pixels[base + channel] & 1
            append_bit(bit)

    return bits


@profile
def deduplicate(arr: Sequence[str]) -> tuple[list[str], str]:
    deduplicated: list[str] = []
    freq: dict[str, int] = {}
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


# Check functions
def lengthCheck(arr: list[str]) -> bool:
    return len(arr) in (3, 4)


def tailCheck(arr: list[str]) -> bool | None:
    if len(arr) != 4:
        return None  # Not required

    full_cipher = arr[1]  # complete ciphertext
    truncated_cipher = arr[2]  # incomplete ciphertext

    return full_cipher.startswith(truncated_cipher)


@profile
def verifySigniture(original: str, sig: str, publicKey: RSAPublicKey) -> bool:
    try:
        publicKey.verify(
            data=original.encode("utf-8"),
            signature=base64.b64decode(sig, validate=True),
            padding=padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            algorithm=hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, binascii.Error):
        return False
    return True


# def buildValidationReport(
#     decrypted, tailCheck: bool, skipPlain: bool = False, hashCheck=None
# ):
#     # Length after deduplication/decryption
#     arrayLength = len(decrypted)

#     # 1. Check that the deduplicated sequence length is valid
#     lengthCheck = arrayLength in (3, 4)

#     # 2. Validate start/end markers
#     startCheck = decrypted[0] == "START-VALIDATION" if decrypted else False
#     endCheck = decrypted[-1] == "END-VALIDATION" if decrypted else False

#     # 4. Determine whether payload was successfully decrypted
#     decryptedPayload = decrypted[1] if len(decrypted) > 1 else ""
#     isDecrypted = bool(decryptedPayload) and not decryptedPayload.endswith("==")

#     checkList = [lengthCheck, startCheck, endCheck, isDecrypted]
#     # 5. Parse tailCheck result
#     if tailCheck is None:
#         tailCheckResult = "Not Required"
#     else:
#         tailCheckResult = tailCheck
#         checkList.append(tailCheckResult)

#     if hashCheck is None:
#         hashCheckResult = "Not Checked"
#     else:
#         hashCheckResult = hashCheck
#         checkList.append(hashCheckResult)

#     # Overall verdict requires every check to pass
#     verdict = all(checkList)

#     result = {
#         "arrayLength": arrayLength,
#         "lengthCheck": lengthCheck,
#         "startCheck": startCheck,
#         "endCheck": endCheck,
#         "isDecrypted": isDecrypted,
#         "tailCheckResult": tailCheckResult,
#         "hashCheckResult": hashCheckResult,
#         "verdict": verdict,
#     }

#     if skipPlain:
#         result["decryptSkipMessage"] = (
#             "Skip decrypt: payload was plain or corrupted text despite decrypt request."
#         )

#     return result


# main
@profile
def validateImage(
    imageInput: ImageInput,
    publicKey: PublicKeyInput,
    keyless: bool = False,
) -> dict[str, Any]:
    """
    Extract the embedded payload from an image and optionally decrypt it.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        publicKey: RSA public key or certificate (object, bytes, or path).

    Returns:
        Dict with the most common extracted string, decrypted sequence, and
        a validation report describing the sentinel checks and verdict.
    """

    publicKey = resolve_public_key(publicKey)
    channel_key = make_channel_key(publicKey)
    resultBinary = readHiddenBit(
        imageInput,
        channel_key,
        keyless,
    )
    resultString = binaryToString(resultBinary)
    splitted = resultString.split("\n")

    deduplicated, most_common = deduplicate(splitted)
    if not deduplicated or most_common == "":
        # raise ValueError("Deduplication failed!")
        return {
            "status": "Failed",
            "error": "Deduplication failed",
            "verdict": False,
        }

    lengthCheckResult = lengthCheck(deduplicated)
    tailCheckResult = tailCheck(deduplicated)

    payload_obj = _extract_payload_json(deduplicated)
    if not payload_obj:
        # raise ValueError("json extraction from payload failed!")
        return {
            "status": "Failed",
            "error": "JSON extraction from payload failed!",
            "verdict": False,
        }
    payload_text = payload_obj[PAYLOAD_FIELD]
    payload_sig = payload_obj[PAYLOAD_SIG_FIELD]
    image_hash = payload_obj[IMAGE_HASH_FIELD]
    image_hash_sig = payload_obj[IMAGE_HASH_SIG_FIELD]
    if (not isinstance(payload_text, str) or not isinstance(payload_sig, str) or not isinstance(image_hash, str)
            or not isinstance(image_hash_sig, str)):
        # raise TypeError("Essenstial value missing!")
        return {
            "status": "Failed",
            "error": "Essenstial values in JSON are missing",
            "verdict": False,
        }
    imageHashVerifyResult = verifySigniture(original=image_hash, sig=image_hash_sig, publicKey=publicKey)
    payloadVerifyResult = verifySigniture(original=payload_text, sig=payload_sig, publicKey=publicKey)
    start_sig = deduplicated[0]
    end_sig = deduplicated[-1]
    startVerifyResult = verifySigniture(original=START_SENTINEL, sig=start_sig, publicKey=publicKey)
    endVerifyResult = verifySigniture(original=END_SENTINEL, sig=end_sig, publicKey=publicKey)

    image_hash_placeholder = "0" * len(image_hash)
    image_hash_sig_placeholder = "0" * len(image_hash_sig)

    payload_placeholder = build_payload_json(
        payload_text,
        payload_sig,
        image_hash_placeholder,
        image_hash_sig_placeholder,
    )

    hiddenBinary = BinaryProvider(
        payload=payload_placeholder + "\n",
        startString=start_sig + "\n",
        endString="\n" + end_sig,
    )

    placeholder_image = addHiddenBit(
        imageInput,
        hiddenBinary,
        channel_key,
        keyless,
    )
    computed_hash = hashlib.sha256(placeholder_image.pixels).hexdigest()
    imageHashCompareCheckResult = image_hash == computed_hash

    verdict = all([
        lengthCheckResult,
        tailCheckResult,
        startVerifyResult,
        endVerifyResult,
        payloadVerifyResult,
        imageHashVerifyResult,
        imageHashCompareCheckResult,
    ])

    length_report: dict[str, int | bool] = {
        "length": len(deduplicated),
        "result": lengthCheckResult,
    }

    if len(deduplicated) == 4:
        full_value = deduplicated[1]
        tail_value = deduplicated[2]
        tail_min_len = TAIL_HEAD_LEN + TAIL_SUFFIX_LEN + 3
        if len(tail_value) > tail_min_len:
            tail_display = (tail_value[:TAIL_HEAD_LEN] + "..." + tail_value[-TAIL_SUFFIX_LEN:])
        else:
            tail_display = tail_value
        if len(full_value) > tail_min_len:
            start = len(tail_value) - TAIL_SUFFIX_LEN
            if start < 0:
                start = 0
            end = len(tail_value) + FULL_TAIL_EXTRA_LEN
            if end > len(full_value):
                end = len(full_value)
            snippet = full_value[start:end]
            if end < len(full_value):
                snippet = snippet + "..."
            full_display = full_value[:TAIL_HEAD_LEN] + "..." + snippet
        else:
            full_display = full_value
        tail_report: dict[str, str | bool | None] = {
            "full": full_display,
            "tail": tail_display,
            "result": tailCheckResult,
        }
    else:
        tail_report = {"result": "Not Required"}
    hash_report: dict[str, str | bool] = {
        "extractedHash": image_hash,
        "computedHash": computed_hash,
        "result": imageHashCompareCheckResult,
    }

    report: dict[str, Any] = {
        "lengthCheck": length_report,
        "tailCheck": tail_report,
        "startVerify": startVerifyResult,
        "endtVerify": endVerifyResult,
        "payloadVerify": payloadVerifyResult,
        "imageHashVerify": imageHashVerifyResult,
        "imageHashCompareCheck": hash_report,
        "verdict": verdict,
    }

    return report
