import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from .simpleImage import ImageInput, SimpleImage

def binaryToString(binaryCode):
    string = ""
    for i in range(0, len(binaryCode), 8):
        byte = binaryCode[i:i+8]
        decimal = int(byte, 2)
        character = chr(decimal)
        string += character
    return string

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
        return None # Not required

    full_cipher = arr[1]       # complete ciphertext
    truncated_cipher = arr[2]  # incomplete ciphertext

    return full_cipher.startswith(truncated_cipher)

def buildValidationReport(decrypted, tailCheck: bool, skipPlain: bool = False):
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
        tailCheckResult = 'Not Required'
    else :
        tailCheckResult = tailCheck
        checkList.append(tailCheckResult)

    # Overall verdict requires every check to pass
    verdict = all(checkList)

    result = {
        "arrayLength": arrayLength,
        "lengthCheck": lengthCheck,
        "startCheck": startCheck,
        "endCheck": endCheck,
        "isDecrypted": isDecrypted,
        "tailCheckResult": tailCheckResult,
        "verdict": verdict
    }

    if skipPlain:
        result["decryptSkipMessage"] = "Skip decrypt: payload was plain or corrupted text despite decrypt request."

    return result

def decrypt_array(deduplicated, privKeyPath):
    # Load PEM private key
    with open(privKeyPath, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    decrypted = []
    skippedPlainCount = 0
    decryptError = False
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
                decryptError = True
                decrypted.append(item)
        else:
            skippedPlainCount += 1
            decrypted.append(item)

    expectedPlainCount = 0
    if len(deduplicated) == 4:
        expectedPlainCount = 1

    skippedPlain = decryptError or skippedPlainCount != expectedPlainCount

    return decrypted, skippedPlain

# main
def validateImage(imageInput: ImageInput, privKeyPath = None):
    resultBinary = readHiddenBit(imageInput)
    resultString = binaryToString(resultBinary)
    splited = resultString.split("\n")
    deduplicated, most_common = deduplicate(splited)

    if privKeyPath:
        decrypted, skippedPlain = decrypt_array(deduplicated,privKeyPath)
    else :
        decrypted = deduplicated
        skippedPlain = False

    report = buildValidationReport(decrypted=decrypted, tailCheck=tailCheck(deduplicated), skipPlain=skippedPlain )
    
    return {
        "extractedString":decrypt_array({most_common},privKeyPath)[0][0],
        "decrypted": decrypted,
        "validationReport": report
    }
