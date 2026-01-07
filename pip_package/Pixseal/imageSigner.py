from pathlib import Path
import base64
import hashlib
import json
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

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
        hiddenString,
        startString="START-VALIDATION\n",
        endString="\nEND-VALIDATION",
    ):
        self.hiddenBits = self._stringToBits(hiddenString)
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


def stringCryptor(plaintext: str, public_key) -> str:

    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return base64.b64encode(ciphertext).decode("ascii")


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


def _encrypted_placeholder_length(public_key) -> int:
    key_bytes = (public_key.key_size + 7) // 8
    return len(base64.b64encode(b"\x00" * key_bytes))


# main
# Image input (path or bytes) + payload string => returns image with embedded payload
def signImage(imageInput: ImageInput, hiddenString, publicKeyPath=None):
    """
    Embed a payload into an image using the parity-based steganography scheme.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        hiddenString: Text payload that should be written into the image.
        publicKeyPath: Optional path to a PEM-encoded RSA public key used to
            encrypt the payload and sentinel markers before embedding.

    Returns:
        SimpleImage instance whose pixels include the signed payload.

    Raises:
        FileNotFoundError: If a public key path is provided but the file is missing.
        ValueError: If the file is not a valid PEM public key.
    """

    if publicKeyPath:  # When encryption key is supplied
        key_path = Path(publicKeyPath)
        if not key_path.is_file():
            raise FileNotFoundError(f"Public key file not found: {publicKeyPath}")

        pem_data = key_path.read_bytes()
        if b"BEGIN PUBLIC KEY" not in pem_data:
            raise ValueError("Provided file does not contain a valid public key")

        public_key = serialization.load_pem_public_key(pem_data)

        public_key_text = pem_data.decode("ascii").strip()
        payload_cipher = stringCryptor(hiddenString, public_key)
        hash_placeholder = "0" * _encrypted_placeholder_length(public_key)
        payload_placeholder = _build_payload_json(
            payload_cipher, public_key_text, hash_placeholder
        )
        start_marker = stringCryptor("START-VALIDATION", public_key)
        end_marker = stringCryptor("END-VALIDATION", public_key)
        start_string = start_marker + "\n"
        end_string = "\n" + end_marker

        placeholder_binary = BinaryProvider(
            hiddenString=payload_placeholder + "\n",
            startString=start_string,
            endString=end_string,
        )
        placeholder_image = addHiddenBit(imageInput, placeholder_binary)
        image_hash = hashlib.sha256(placeholder_image._pixels).hexdigest()
        hash_cipher = stringCryptor(image_hash, public_key)
        if len(hash_cipher) != len(hash_placeholder):
            raise ValueError("Encrypted hash length mismatch with placeholder")

        payload_final = _build_payload_json(payload_cipher, public_key_text, hash_cipher)
        hiddenBinary = BinaryProvider(
            hiddenString=payload_final + "\n",
            startString=start_string,
            endString=end_string,
        )

    else:  # Plain-text payload
        hiddenBinary = BinaryProvider(hiddenString + "\n")

    signedImage = addHiddenBit(imageInput, hiddenBinary)
    return signedImage
