import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from line_profiler import profile

from .keyInput import PrivateKeyInput, resolve_private_key
from .simpleImage import ImageInput, SimpleImage


class BinaryProvider:
    hiddenBits: list[int]
    startBits: list[int]
    endBits: list[int]

    # Constructor
    def __init__(
        self,
        payload: str,
        startString: str = "START-VALIDATION\n",
        endString: str = "\nEND-VALIDATION",
    ) -> None:
        self.hiddenBits = self._stringToBits(payload)
        self.startBits = self._stringToBits(startString)
        self.endBits = self._stringToBits(endString)

    # Convert string to contiguous binary digits
    def _stringToBits(self, string: str) -> list[int]:
        bits: list[int] = []
        for char in string:
            binary = format(ord(char), "08b")
            bits.extend(int(bit) for bit in binary)
        return bits

    def _expandPayload(self, count: int) -> list[int]:
        if count <= 0:
            return []
        payloadLen = len(self.hiddenBits)
        if payloadLen == 0:
            raise ValueError("Hidden payload is empty")
        repeats, remainder = divmod(count, payloadLen)
        return (self.hiddenBits * repeats) + self.hiddenBits[:remainder]

    def buildBitArray(self, pixelCount: int) -> list[int]:
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
def make_channel_key(public_key: RSAPublicKey) -> bytes:
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_bytes


@profile
def build_channel_key_array(total: int, channel_key: bytes) -> bytes:
    if not channel_key:
        raise ValueError("channel_key must not be empty")
    if total <= 0:
        return b""
    key_mod3 = bytes(b % 3 for b in channel_key)
    repeats, remainder = divmod(total, len(key_mod3))
    return (key_mod3 * repeats) + key_mod3[:remainder]


# @profile
# def _choose_channel(index: int, channel_key: bytes) -> int:
#     if not channel_key:
#         raise ValueError("channel_key must not be empty")
#     return channel_key[index % len(channel_key)] % 3


@profile
def addHiddenBit(
    imageInput: ImageInput,
    hiddenBinary: BinaryProvider,
    channel_key: bytes,
    keyless: bool,
) -> SimpleImage:
    img = SimpleImage.open(imageInput)
    width, height = img.size
    pixels = img.pixels  # direct buffer access for performance
    total = width * height
    payloadBits = hiddenBinary.buildBitArray(total)

    if keyless:
        # Iterate over every pixel and inject one bit
        for idx in range(total):
            base = idx * 3
            # Read the pixel
            r = pixels[base]
            g = pixels[base + 1]
            b = pixels[base + 2]

            # Calculate the distance from 127 (ignore LSB for stability)
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

            # Pick the component farthest from 127
            maxDiff = diffR
            if diffG > maxDiff:
                maxDiff = diffG
            if diffB > maxDiff:
                maxDiff = diffB

            # Pull next bit from provider
            bit = payloadBits[idx] & 1

            # Force the selected channel parity to match the bit (LSB overwrite)
            if maxDiff == diffR:
                r = (r & 0xFE) | bit
            if maxDiff == diffG:
                g = (g & 0xFE) | bit
            if maxDiff == diffB:
                b = (b & 0xFE) | bit

            # Write the updated pixel
            pixels[base] = r
            pixels[base + 1] = g
            pixels[base + 2] = b
    else:
        # Keyed channel selection with explicit LSB overwrite.
        channel_key_arr = build_channel_key_array(total, channel_key)

        for idx in range(total):
            base = idx * 3
            bit = payloadBits[idx] & 1
            # channel = _choose_channel(idx, channel_key)
            channel = channel_key_arr[idx]
            offset = base + channel
            pixels[offset] = (pixels[offset] & 0xFE) | bit

    # Return the modified image
    return img


# Helper function to encrypt a string with RSA private key
@profile
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
@profile
def make_image_hash_placeholder() -> str:
    """
    Generate a placeholder string for the SHA256 image hash (hex length).
    """
    hash_hex_len = len(hashlib.sha256().hexdigest())
    # print("hash_hex_len = ", hash_hex_len)
    return "0" * hash_hex_len


@profile
def make_hash_signature_placeholder(private_key: RSAPrivateKey) -> str:
    """
    Generate a placeholder string for the signature of the image hash.
    """
    key_bytes = (private_key.key_size + 7) // 8
    signature_b64_len = len(base64.b64encode(b"\x00" * key_bytes))
    # print("signature_b64_len = ", signature_b64_len)
    return "0" * signature_b64_len


# JSON field names
PAYLOAD_FIELD: str = "payload"
PAYLOAD_SIG_FIELD: str = "payloadSig"
IMAGE_HASH_FIELD: str = "imageHash"
IMAGE_HASH_SIG_FIELD: str = "imageHashSig"


# Helper function for building the JSON payload
@profile
def build_payload_json(
    payload: str,
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
@profile
def signImage(
    imageInput: ImageInput,
    payload: str,
    private_key: PrivateKeyInput,
    keyless: bool = False,
) -> SimpleImage:
    """
    Embed a payload into an image using the parity-based steganography scheme.

    Args:
        imageInput: File path, bytes, or file-like object accepted by SimpleImage.
        payload: Text payload that should be signed (and optionally embedded).
        private_key: RSA private key or PEM/DER-encoded key bytes/path used to
            sign the payload hash, image hash, and sentinel markers.
        includePlaintext: When True, embed the payload text alongside signatures.

    Returns:
        SimpleImage instance whose pixels include the signed payload.

    Raises:
        FileNotFoundError: If a private key path is provided but the file is missing.
        ValueError: If the file is not a valid PEM private key.
    """
    if not payload:
        raise TypeError("payload must be a non-empty string")

    private_key = resolve_private_key(private_key)
    payload_text = payload
    payload_sig = stringSigner(payload_text, private_key)
    image_hash_placeholder = make_image_hash_placeholder()
    image_hash_sig_placeholder = make_hash_signature_placeholder(private_key)

    payload_with_placeholder = build_payload_json(
        payload_text,
        payload_sig,
        image_hash_placeholder,
        image_hash_sig_placeholder,  # Placeholder for image hash signature
    )

    # Sign the start/end markers
    start_marker_sig = stringSigner("START-VALIDATION", private_key)
    end_marker_sig = stringSigner("END-VALIDATION", private_key)
    start_string = start_marker_sig + "\n"
    end_string = "\n" + end_marker_sig
    channel_key = make_channel_key(private_key.public_key())

    # 1st injection: payload with placeholder
    placeholder_binary = BinaryProvider(
        payload=payload_with_placeholder + "\n",
        startString=start_string,
        endString=end_string,
    )
    image_with_placeholder = addHiddenBit(
        imageInput,
        placeholder_binary,
        channel_key,
        keyless,
    )

    # Calculate the image hash and sign it
    image_hash = hashlib.sha256(image_with_placeholder.pixels).hexdigest()
    if len(image_hash) != len(image_hash_placeholder):
        raise ValueError(
            "Signed hash length mismatch with placeholder",
            "\nhash len: " + str(len(image_hash)),
            "\nplaceholder len: " + str(len(image_hash_placeholder)),
        )

    # Sign the calculated hash
    image_hash_sig = stringSigner(image_hash, private_key)
    if len(image_hash_sig) != len(image_hash_sig_placeholder):
        raise ValueError(
            "Signed hash length mismatch with placeholder",
            "\nhash signiture len: " + str(len(image_hash_sig)),
            "\nplaceholder len: " + str(len(image_hash_sig_placeholder)),
        )

    # Prepare the final payload with the calculated hash
    payload_final = build_payload_json(
        payload_text,
        payload_sig,
        image_hash,
        image_hash_sig,
    )

    hiddenBinary = BinaryProvider(
        payload=payload_final + "\n",
        startString=start_string,
        endString=end_string,
    )

    # Final injection: final payload
    signedImage = addHiddenBit(
        imageInput,
        hiddenBinary,
        channel_key,
        keyless,
    )

    return signedImage
