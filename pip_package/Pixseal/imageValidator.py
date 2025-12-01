import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .simpleImage import SimpleImage

def binaryToString(binaryCode):
    string = ""
    for i in range(0, len(binaryCode), 8):
        byte = binaryCode[i:i+8]
        decimal = int(byte, 2)
        character = chr(decimal)
        string += character
    return string

def readHiddenBit(imagePath):
    # Accumulates decoded bits
    hiddenBinary = ""

    # Open the image
    img = SimpleImage.open(imagePath)

    # Dimensions
    width, height = img.size

    # Visit every pixel to rebuild the bitstream
    for y in range(height):
        for x in range(width):
            # Load pixel
            r, g, b = img.getPixel((x, y))

            # Distance from 127
            diffR = abs(r - 127)
            diffG = abs(g - 127)
            diffB = abs(b - 127)

            # Pick the channel farthest from 127
            maxDiff = max(diffR, diffG, diffB)

            # Even => 1, odd => 0
            if maxDiff % 2 == 0:
                hiddenBinary += "1"
            else:
                hiddenBinary += "0"
    
    return hiddenBinary

def deduplicate(arr):
    deduplicated = []
    for i in range(len(arr)):
        if i == 0 or arr[i] != arr[i-1]:
            deduplicated.append(arr[i])
    return deduplicated

def buildValidationReport(decrypted, skipPlain=False):
    # Length after deduplication/decryption
    arrayLength = len(decrypted)

    # 1. Check that the deduplicated sequence length is valid
    lengthCheck = True if arrayLength == 3 or arrayLength == 4 else False

    # 2. Validate start/end markers
    startCheck = decrypted[0] == "START-VALIDATION" if decrypted else False
    endCheck = decrypted[-1] == "END-VALIDATION" if decrypted else False

    # 4. Determine whether payload was successfully decrypted
    decryptedPayload = decrypted[1] if len(decrypted) > 1 else ""
    isDecrypted = bool(decryptedPayload) and not decryptedPayload.endswith("==")

    # Overall verdict requires every check to pass
    verdict = all([lengthCheck, startCheck, endCheck, isDecrypted])

    result = {
        "arrayLength": arrayLength,
        "lengthCheck": lengthCheck,
        "startCheck": startCheck,
        "endCheck": endCheck,
        "isDecrypted": isDecrypted,
        "verdict": verdict
    }
    if skipPlain:
        result["decryptSkipMessage"] = "Skip decrypt: payload was plain text despite decrypt request."
    return result

def decrypt_array(deduplicated, privKeyPath):
    # Load PEM private key
    with open(privKeyPath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    decrypted = []
    skipped_plain = False
    for item in deduplicated:
        if item.endswith("=="):
            try:
                cipher_bytes = base64.b64decode(item)
                plain_bytes = private_key.decrypt(
                    cipher_bytes,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                )
                decrypted.append(plain_bytes.decode("utf-8"))
            except Exception as exc:
                print(exc)
                skipped_plain = True
                decrypted.append(item)
        else:
            skipped_plain = True
            decrypted.append(item)

    return decrypted, skipped_plain

# main
def validateImage(imagePath, privKeyPath = None):
    resultBinary = readHiddenBit(imagePath)
    resultString = binaryToString(resultBinary)
    splited = resultString.split("\n")
    deduplicated = deduplicate(splited)

    if privKeyPath:
        decrypted, skipped_plain = decrypt_array(deduplicated,privKeyPath)
    else :
        decrypted = deduplicated
        skipped_plain = False

    report = buildValidationReport(decrypted, skipped_plain)
    return {
        "extractedString": decrypted[1],
        "validationReport": report
    }
