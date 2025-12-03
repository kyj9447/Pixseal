import base64
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .simpleImage import ImageInput, SimpleImage

class BinaryProvider:

    # Constructor
    def __init__(self, hiddenString, startString = "START-VALIDATION\n", endString="\nEND-VALIDATION"):
        self.hiddenBinary = self.strToBinary(hiddenString)
        self.hiddenBinaryIndex = 0
        self.hiddenBinaryIndexMax = len(self.hiddenBinary)

        # Start sentinel
        self.startBinary = self.strToBinary(startString)
        self.startBinaryIndex = 0
        self.startBinaryIndexMax = len(self.startBinary)

        # End sentinel
        self.endBinary = self.strToBinary(endString)
        # End bits are written in reverse from the tail
        self.endBinaryIndex = len(self.endBinary)-1
        self.endBinaryIndexMin = 0

    # Convert string to contiguous binary digits
    def strToBinary(self, string):
        # Prepare an empty list for characters
        binaries = []
        
        # Iterate over each character
        for char in string:
            # Convert character to 8-bit binary and append
            binaries.append(bin(ord(char))[2:].zfill(8))
            
        # Join into a single string
        return ''.join(binaries)

    # Retrieve the next bit, emitting the start sentinel before payload
    def nextBit(self):

        # After the start sentinel, consume payload bits
        if self.startBinaryIndex == self.startBinaryIndexMax:    
            # Loop payload bits when the end is reached
            if self.hiddenBinaryIndex >= self.hiddenBinaryIndexMax:
                self.hiddenBinaryIndex = 0

            # Read the payload bit at the current index
            bit = self.hiddenBinary[self.hiddenBinaryIndex]

            # Advance payload index
            self.hiddenBinaryIndex += 1

        # Otherwise continue to emit start sentinel bits
        else:
            # Pull the bit from the start sentinel
            bit = self.startBinary[self.startBinaryIndex]

            # Advance start sentinel index
            self.startBinaryIndex += 1

        return int(bit)
    
    # Retrieve the next end sentinel bit in reverse order
    def nextEnd(self):
        # End sentinel complete when we reach the lower bound
        if self.endBinaryIndex == self.endBinaryIndexMin:
            return None

        # Grab the bit at the current index
        bit = self.endBinary[self.endBinaryIndex]

        # Move backwards
        self.endBinaryIndex -= 1

        return int(bit)

def addHiddenBit(imageInput: ImageInput, hiddenBinary):
    # Open the image
    img = SimpleImage.open(imageInput)

    # Retrieve dimensions
    width, height = img.size

    # Iterate over every pixel and inject one bit
    for y in range(height):
        for x in range(width):
            # Read the pixel
            r, g, b = img.getPixel((x, y))

            # Calculate the distance from 127
            diffR = abs(r - 127)
            diffG = abs(g - 127)
            diffB = abs(b - 127)

            # Pick the component farthest from 127
            maxDiff = max(diffR, diffG, diffB)

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
            bit = hiddenBinary.nextBit()

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
            img.putPixel((x,y), (r, g, b))

    # Append the end sentinel starting from the last pixel
    for y in reversed(range(height)):
        for x in reversed(range(width)):
            # Read the pixel
            r, g, b = img.getPixel((x, y))

            # Distance from 127
            diffR = abs(r - 127)
            diffG = abs(g - 127)
            diffB = abs(b - 127)

            # Select the farthest channel
            maxDiff = max(diffR, diffG, diffB)

            # Actual value of that channel
            if maxDiff == diffR: 
                targetColorValue = r
            elif maxDiff == diffG:
                targetColorValue = g
            else:
                targetColorValue = b 
            
            # Direction to adjust
            addDirection = 1 if targetColorValue < 127 else -1

            # End-bit provider
            bit = hiddenBinary.nextEnd()
            if bit is None:
                break

            # Apply the parity tweak
            if maxDiff == diffR:
                if r % 2 != bit:
                    r += addDirection
            if maxDiff == diffG:
                if g % 2 != bit:
                    g += addDirection
            if maxDiff == diffB:
                if b % 2 != bit:
                    b += addDirection

            # Persist the adjustment
            img.putPixel((x,y), (r, g, b))

        if bit is None:
            break

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

# main
# Image input (path or bytes) + payload string => returns image with embedded payload
def signImage(imageInput: ImageInput, hiddenString, publicKeyPath = None) :

    if publicKeyPath : # When encryption key is supplied
        key_path = Path(publicKeyPath)
        if not key_path.is_file():
            raise FileNotFoundError(f"Public key file not found: {publicKeyPath}")

        pem_data = key_path.read_bytes()
        if b"BEGIN PUBLIC KEY" not in pem_data:
            raise ValueError("Provided file does not contain a valid public key")

        public_key = serialization.load_pem_public_key(pem_data)
            
        hiddenBinary = BinaryProvider(
            hiddenString = stringCryptor(hiddenString,public_key)+"\n", 
            startString = stringCryptor("START-VALIDATION",public_key)+"\n", 
            endString="\n"+stringCryptor("END-VALIDATION",public_key)
            )
        
    else : # Plain-text payload
        hiddenBinary = BinaryProvider(hiddenString + "\n")

    signedImage = addHiddenBit(imageInput, hiddenBinary)
    return signedImage
