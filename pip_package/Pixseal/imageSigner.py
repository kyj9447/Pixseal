from pathlib import Path
import base64
import hashlib
import json
from pprint import pprint
from typing import TYPE_CHECKING, cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

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


class BinaryProvider:

    # Constructor
    def __init__(
        self,
        payload,
        startString="START-VALIDATION\n",
        endString="\nEND-VALIDATION",
    ):
        self.hiddenBits = self._stringToBits(payload)
        self.startBits = self._stringToBits(startString)
        self.endBits = self._stringToBits(endString)

    # Convert string to contiguous binary digits
    def _stringToBits(self, string):
        bits = []
        for char in string:
            binary = format(ord(char), "08b")
            bits.extend(int(bit) for bit in binary)
        return bits

    def _expandPayload(self, count: int):
        if count <= 0:
            return []
        payloadLen = len(self.hiddenBits)
        if payloadLen == 0:
            raise ValueError("Hidden payload is empty")
        repeats, remainder = divmod(count, payloadLen)
        return (self.hiddenBits * repeats) + self.hiddenBits[:remainder]

    def buildBitArray(self, pixelCount: int):
        startLen = len(self.startBits)
        endLen = len(self.endBits)
        if pixelCount < startLen + endLen:
            raise ValueError("Image is too small to fit start/end sentinels")

        bits = [0] * pixelCount

        # 1. Place START-VALIDATION bits first
        bits[:startLen] = self.startBits

        # 2. Fill the remaining slots by repeating the payload bits
        payloadSlots = pixelCount - startLen
        payloadBits = self._expandPayload(payloadSlots)
        bits[startLen:] = payloadBits[:payloadSlots]

        # 3. Overwrite the tail with END-VALIDATION bits
        tailStart = pixelCount - endLen
        bits[tailStart:] = self.endBits

        return bits


@profile
def addHiddenBit(imageInput: ImageInput, hiddenBinary: BinaryProvider):
    img = SimpleImage.open(imageInput)
    width, height = img.size
    pixels = img._pixels  # direct buffer access for performance
    total = width * height
    payloadBits = hiddenBinary.buildBitArray(total)

    # Iterate over every pixel and inject one bit
    for idx in range(total):
        base = idx * 3
        # Read the pixel
        r = pixels[base]
        g = pixels[base + 1]
        b = pixels[base + 2]

        # Calculate the distance from 127
        diffR = r - 127
        if diffR < 0:
            diffR = -diffR
        diffG = g - 127
        if diffG < 0:
            diffG = -diffG
        diffB = b - 127
        if diffB < 0:
            diffB = -diffB

        # Pick the component farthest from 127
        maxDiff = diffR
        if diffG > maxDiff:
            maxDiff = diffG
        if diffB > maxDiff:
            maxDiff = diffB

        # Actual value of that channel
        if maxDiff == diffR:
            targetColorValue = r
        elif maxDiff == diffG:
            targetColorValue = g
        else:
            targetColorValue = b

        # Channels >=127 are decremented, <127 incremented
        addDirection = 1 if targetColorValue < 127 else -1

        # Pull next bit from provider
        bit = payloadBits[idx]

        # Force the selected channel parity to match the bit
        if maxDiff == diffR:
            if r % 2 != bit:
                r += addDirection
        if maxDiff == diffG:
            if g % 2 != bit:
                g += addDirection
        if maxDiff == diffB:
            if b % 2 != bit:
                b += addDirection

        # Write the updated pixel
        pixels[base] = r
        pixels[base + 1] = g
        pixels[base + 2] = b

    # Return the modified image
    return img


# Helper function to encrypt a string with RSA private key
def stringSigner(plaintext: str, private_key: RSAPrivateKey) -> str:
    signature = private_key.sign(
        plaintext.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode("ascii")


# Helper function to calculate signature placeholder
def make_image_hash_placeholder() -> str:
    """
    Generate a placeholder string for the SHA256 image hash (hex length).
    """
    hash_hex_len = len(hashlib.sha256().hexdigest())
    print("hash_hex_len = ", hash_hex_len)
    return "0" * hash_hex_len


def make_hash_signature_placeholder(private_key) -> str:
    """
    Generate a placeholder string for the signature of the image hash.
    """
    key_bytes = (private_key.key_size + 7) // 8
    signature_b64_len = len(base64.b64encode(b"\x00" * key_bytes))
    print("signature_b64_len = ", signature_b64_len)
    return "0" * signature_b64_len


# JSON field names
PAYLOAD_FIELD = "payload"
PAYLOAD_SIG_FIELD = "payloadSig"
IMAGE_HASH_FIELD = "imageHash"
IMAGE_HASH_SIG_FIELD = "imageHashSig"


# Helper function for building the JSON payload
def _build_payload_json(
    payload: str | None,
    payload_sig: str,
    image_hash: str,
    image_hash_sig: str,
) -> str:
    payload_obj = {
        PAYLOAD_FIELD: payload,
        PAYLOAD_SIG_FIELD: payload_sig,
        IMAGE_HASH_FIELD: image_hash,
        IMAGE_HASH_SIG_FIELD: image_hash_sig,
    }

    return json.dumps(payload_obj, separators=(",", ":"), ensure_ascii=True)


# main
# Image input (path or bytes) + payload string => returns image with embedded payload
def signImage(imageInput: ImageInput, payload: str, privateKeyPath: str):
    """
    Embed a payload into an image using the parity-based steganography scheme.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        payload: Text payload that should be signed (and optionally embedded).
        privateKeyPath: Optional path to a PEM-encoded RSA private key used to
            sign the payload hash, image hash, and sentinel markers.
        includePlaintext: When True, embed the payload text alongside signatures.

    Returns:
        SimpleImage instance whose pixels include the signed payload.

    Raises:
        FileNotFoundError: If a private key path is provided but the file is missing.
        ValueError: If the file is not a valid PEM private key.
    """
    if not isinstance(payload, str) or not payload:
        raise TypeError("payload must be a non-empty string")
    if privateKeyPath and not isinstance(privateKeyPath, (str, Path)):
        raise TypeError("privateKeyPath must be a path string or Path")

    key_path = Path(privateKeyPath)
    if not key_path.is_file():
        raise FileNotFoundError(f"Private key file not found: {privateKeyPath}")

    pem_data = key_path.read_bytes()
    if b"BEGIN PRIVATE KEY" not in pem_data:
        raise ValueError("Provided file does not contain a valid private key")

    private_key: RSAPrivateKey = cast(
        RSAPrivateKey, serialization.load_pem_private_key(pem_data, password=None)
    )

    payload_text = payload
    payload_sig = stringSigner(payload_text, private_key)
    image_hash_placeholder = make_image_hash_placeholder()
    image_hash_sig_placeholder = make_hash_signature_placeholder(private_key)

    payload_with_placeholder = _build_payload_json(
        payload_text,
        payload_sig,
        image_hash_placeholder,
        image_hash_sig_placeholder,  # Placeholder for image hash signature
    )
    print("payload #1")
    pprint(payload_with_placeholder)

    # Sign the start/end markers
    start_marker_sig = stringSigner("START-VALIDATION", private_key)
    end_marker_sig = stringSigner("END-VALIDATION", private_key)
    start_string = start_marker_sig + "\n"
    end_string = "\n" + end_marker_sig

    # 1st injection: payload with placeholder
    placeholder_binary = BinaryProvider(
        payload=payload_with_placeholder + "\n",
        startString=start_string,
        endString=end_string,
    )
    image_with_placeholder = addHiddenBit(imageInput, placeholder_binary)

    # Calculate the image hash and sign it
    image_hash = hashlib.sha256(image_with_placeholder._pixels).hexdigest()
    if len(image_hash) != len(image_hash_placeholder):
        raise ValueError(
            "Signed hash length mismatch with placeholder"
            + "\nhash len: "
            + str(len(image_hash))
            + "\nplaceholder len: "
            + str(len(image_hash_placeholder))
        )

    # Sign the calculated hash
    image_hash_sig = stringSigner(image_hash, private_key)
    if len(image_hash_sig) != len(image_hash_sig_placeholder):
        raise ValueError(
            "Signed hash length mismatch with placeholder"
            + "\nhash signiture len: "
            + str(len(image_hash_sig))
            + "\nplaceholder len: "
            + str(len(image_hash_sig_placeholder))
        )

    # Prepare the final payload with the calculated hash
    payload_final = _build_payload_json(
        payload_text,
        payload_sig,
        image_hash,
        image_hash_sig,
    )
    print("payload #2")
    pprint(payload_final)

    hiddenBinary = BinaryProvider(
        payload=payload_final + "\n",
        startString=start_string,
        endString=end_string,
    )

    # Final injection: final payload
    signedImage = addHiddenBit(imageInput, hiddenBinary)

    return signedImage
