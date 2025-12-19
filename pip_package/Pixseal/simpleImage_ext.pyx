# cython: language_level=3, boundscheck=False, wraparound=False
import struct
import zlib
from io import BytesIO
from pathlib import Path
from typing import List, Sequence, Tuple, Union

cimport cython
from libc.stdint cimport uint8_t

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

ImageInput = Union[str, Path, bytes, bytearray]


@cython.cfunc
cdef int _paethPredictor(int a, int b, int c) nogil:
    cdef int p = a + b - c
    cdef int pa = p - a
    if pa < 0:
        pa = -pa
    cdef int pb = p - b
    if pb < 0:
        pb = -pb
    cdef int pc = p - c
    if pc < 0:
        pc = -pc
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


@cython.cfunc
cdef void _applyPngFilter(
    int filterType,
    uint8_t[:] rowData,
    uint8_t[:] prevRow,
    int bytesPerPixel,
    uint8_t[:] recon,
) nogil:
    cdef Py_ssize_t length = rowData.shape[0]
    cdef Py_ssize_t i
    cdef int left, up, upLeft
    for i in range(length):
        left = recon[i - bytesPerPixel] if i >= bytesPerPixel else 0
        up = prevRow[i] if prevRow.shape[0] else 0
        upLeft = prevRow[i - bytesPerPixel] if (prevRow.shape[0] and i >= bytesPerPixel) else 0

        if filterType == 0:
            recon[i] = rowData[i]
        elif filterType == 1:
            recon[i] = (rowData[i] + left) & 0xFF
        elif filterType == 2:
            recon[i] = (rowData[i] + up) & 0xFF
        elif filterType == 3:
            recon[i] = (rowData[i] + ((left + up) >> 1)) & 0xFF
        elif filterType == 4:
            recon[i] = (rowData[i] + _paethPredictor(left, up, upLeft)) & 0xFF
        else:
            with gil:
                raise ValueError(f"Unsupported PNG filter: {filterType}")


@cython.cfunc
cdef tuple _loadPng(object stream):
    signature = stream.read(8)
    if signature != PNG_SIGNATURE:
        raise ValueError("Unsupported PNG signature")

    cdef int width = -1
    cdef int height = -1
    cdef int bitDepth = -1
    cdef int colorType = -1
    cdef int compression = -1
    cdef int filterMethod = -1
    cdef int interlace = -1
    idatChunks: List[bytes] = []

    while True:
        chunkType, data = _readChunk(stream)
        if chunkType == b"":
            break
        if chunkType == b"IHDR":
            (
                width,
                height,
                bitDepth,
                colorType,
                compression,
                filterMethod,
                interlace,
            ) = struct.unpack(">IIBBBBB", data)
        elif chunkType == b"IDAT":
            idatChunks.append(data)
        elif chunkType == b"IEND":
            break

    if -1 in (width, height, bitDepth, colorType, compression, filterMethod, interlace):
        raise ValueError("Incomplete PNG header information")
    if bitDepth != 8:
        raise ValueError("Only 8-bit PNG images are supported")
    if colorType not in (2, 6):
        raise ValueError("Only RGB/RGBA PNG images are supported")
    if compression != 0 or filterMethod != 0 or interlace != 0:
        raise ValueError("Unsupported PNG configuration (compression/filter/interlace)")

    rawImage = zlib.decompress(b"".join(idatChunks))
    cdef int bytesPerPixel = 3 if colorType == 2 else 4
    cdef int rowLength = width * bytesPerPixel
    cdef int expected = height * (rowLength + 1)
    if len(rawImage) != expected:
        raise ValueError("Malformed PNG image data")

    pixels = bytearray(width * height * 3)
    prevRow = bytearray(rowLength)
    cdef uint8_t[:] prev_view = prevRow
    cdef uint8_t[:] pix_view = pixels
    cdef uint8_t[:] row_view
    cdef uint8_t[:] recon_view
    cdef bytearray rowBytes
    cdef bytearray recon
    cdef Py_ssize_t offset = 0
    cdef int y, x
    cdef int filterType
    cdef int srcIndex, destIndex

    for y in range(height):
        filterType = rawImage[offset]
        offset += 1
        rowBytes = bytearray(rawImage[offset : offset + rowLength])
        offset += rowLength
        row_view = rowBytes
        recon = bytearray(rowLength)
        recon_view = recon
        _applyPngFilter(filterType, row_view, prev_view, bytesPerPixel, recon_view)
        for x in range(width):
            srcIndex = x * bytesPerPixel
            destIndex = (y * width + x) * 3
            pix_view[destIndex] = recon_view[srcIndex]
            pix_view[destIndex + 1] = recon_view[srcIndex + 1]
            pix_view[destIndex + 2] = recon_view[srcIndex + 2]
        prevRow = recon
        prev_view = recon_view
    return width, height, pixels


def _readChunk(stream) -> Tuple[bytes, bytes]:
    lengthBytes = stream.read(4)
    if len(lengthBytes) == 0:
        return b"", b""
    if len(lengthBytes) != 4:
        raise ValueError("Unexpected EOF while reading chunk length")
    length = struct.unpack(">I", lengthBytes)[0]
    chunkType = stream.read(4)
    if len(chunkType) != 4:
        raise ValueError("Unexpected EOF while reading chunk type")
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Unexpected EOF while reading chunk data")
    crc = stream.read(4)
    if len(crc) != 4:
        raise ValueError("Unexpected EOF while reading chunk CRC")
    expectedCrc = zlib.crc32(chunkType)
    expectedCrc = zlib.crc32(data, expectedCrc) & 0xFFFFFFFF
    actualCrc = struct.unpack(">I", crc)[0]
    if actualCrc != expectedCrc:
        raise ValueError("Corrupted PNG chunk detected")
    return chunkType, data


@cython.cfunc
cdef tuple _loadBmp(object stream):
    header = stream.read(14)
    if len(header) != 14 or header[:2] != b"BM":
        raise ValueError("Unsupported BMP header")
    fileSize, _, _, pixelOffset = struct.unpack("<IHHI", header[2:])
    dibHeaderSizeBytes = stream.read(4)
    if len(dibHeaderSizeBytes) != 4:
        raise ValueError("Corrupted BMP DIB header")
    dibHeaderSize = struct.unpack("<I", dibHeaderSizeBytes)[0]
    if dibHeaderSize != 40:
        raise ValueError("Only BITMAPINFOHEADER BMP files are supported")
    dibData = stream.read(36)
    (
        width,
        height,
        planes,
        bitCount,
        compression,
        imageSize,
        xPpm,
        yPpm,
        clrUsed,
        clrImportant,
    ) = struct.unpack("<iiHHIIiiII", dibData)
    if planes != 1 or bitCount != 24 or compression != 0:
        raise ValueError("Only uncompressed 24-bit BMP files are supported")
    absHeight = abs(height)
    rowStride = ((width * 3 + 3) // 4) * 4
    pixels = bytearray(width * absHeight * 3)
    stream.seek(pixelOffset)
    cdef uint8_t[:] pix_view = pixels
    cdef int row
    cdef int targetRow
    cdef int baseIndex
    cdef int x
    cdef int idx
    cdef bytes rowData
    cdef int rowPad = rowStride - width * 3
    for row in range(absHeight):
        rowData = stream.read(rowStride)
        if len(rowData) != rowStride:
            raise ValueError("Incomplete BMP pixel data")
        targetRow = absHeight - 1 - row if height > 0 else row
        baseIndex = targetRow * width * 3
        for x in range(width):
            idx = baseIndex + x * 3
            pix_view[idx] = rowData[x * 3 + 2] & 0xFF
            pix_view[idx + 1] = rowData[x * 3 + 1] & 0xFF
            pix_view[idx + 2] = rowData[x * 3] & 0xFF
    return width, absHeight, pixels


def _makeChunk(chunkType: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crcValue = zlib.crc32(chunkType)
    crcValue = zlib.crc32(data, crcValue) & 0xFFFFFFFF
    crc = struct.pack(">I", crcValue)
    return length + chunkType + data + crc


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void _write_png_bytes(int width, int height, uint8_t[:] pixels, bytearray raw):
    cdef int rowStride = width * 3
    cdef int y, start
    raw.clear()
    for y in range(height):
        raw.append(0)
        start = y * rowStride
        raw.extend(pixels[start : start + rowStride])


def _writePng(path, int width, int height, object pixels) -> None:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw = bytearray()
    if isinstance(pixels, bytearray):
        pix_view = pixels
    else:
        pix_view = bytearray(pixels)
    _write_png_bytes(width, height, pix_view, raw)
    compressed = zlib.compress(bytes(raw))
    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        output.write(_makeChunk(b"IHDR", ihdr))
        output.write(_makeChunk(b"IDAT", compressed))
        output.write(_makeChunk(b"IEND", b""))


def _writeBmp(path, int width, int height, object pixels) -> None:
    rowStride = ((width * 3 + 3) // 4) * 4
    pixelArraySize = rowStride * height
    fileSize = 14 + 40 + pixelArraySize
    if isinstance(pixels, bytearray):
        pix_buf = pixels
    else:
        pix_buf = bytearray(pixels)
    with open(path, "wb") as output:
        output.write(b"BM")
        output.write(struct.pack("<IHHI", fileSize, 0, 0, 54))
        output.write(
            struct.pack(
                "<IIIHHIIIIII",
                40,
                width,
                height,
                1,
                24,
                0,
                pixelArraySize,
                2835,
                2835,
                0,
                0,
            )
        )
        rowPad = rowStride - width * 3
        padBytes = b"\x00" * rowPad
        for y in range(height - 1, -1, -1):
            start = y * width * 3
            for x in range(width):
                idx = start + x * 3
                r = pix_buf[idx]
                g = pix_buf[idx + 1]
                b = pix_buf[idx + 2]
                output.write(bytes((b & 0xFF, g & 0xFF, r & 0xFF)))
            if rowPad:
                output.write(padBytes)


cdef class SimpleImage:
    """Minimal RGB image helper implemented in Cython."""

    cdef public int width
    cdef public int height
    cdef public bytearray _pixels

    def __cinit__(self, int width, int height, object pixels):
        cdef Py_ssize_t expected = width * height * 3
        if len(pixels) != expected:
            raise ValueError("Pixel data length does not match image dimensions")
        self.width = width
        self.height = height
        if isinstance(pixels, bytearray):
            self._pixels = bytearray(pixels)
        else:
            self._pixels = bytearray(pixels)

    @property
    def size(self) -> Tuple[int, int]:
        return self.width, self.height

    @staticmethod
    def _streamToImage(stream):
        signature = stream.read(8)
        stream.seek(0)
        if signature.startswith(PNG_SIGNATURE):
            return _loadPng(stream)
        if signature[:2] == b"BM":
            return _loadBmp(stream)
        raise ValueError("Unsupported image format")

    @classmethod
    def open(cls, source: ImageInput) -> "SimpleImage":
        if isinstance(source, (str, Path)):
            with open(source, "rb") as stream:
                width, height, pixels = cls._streamToImage(stream)
        elif isinstance(source, (bytes, bytearray)):
            stream = BytesIO(source)
            width, height, pixels = cls._streamToImage(stream)
        else:
            raise TypeError("source must be a file path or raw bytes")
        return cls(width, height, pixels)

    def getPixel(self, coords: Tuple[int, int]) -> Tuple[int, int, int]:
        x, y = coords
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise ValueError("Pixel coordinate out of bounds")
        index = (y * self.width + x) * 3
        return (
            self._pixels[index],
            self._pixels[index + 1],
            self._pixels[index + 2],
        )

    def putPixel(self, coords: Tuple[int, int], value: Sequence[int]) -> None:
        x, y = coords
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise ValueError("Pixel coordinate out of bounds")
        index = (y * self.width + x) * 3
        r, g, b = value
        self._pixels[index] = int(r) & 0xFF
        self._pixels[index + 1] = int(g) & 0xFF
        self._pixels[index + 2] = int(b) & 0xFF

    def copy(self) -> "SimpleImage":
        return SimpleImage(self.width, self.height, self._pixels[:])

    def save(self, path: str) -> None:
        _writePng(path, self.width, self.height, self._pixels)

    def saveBmp(self, path: str) -> None:
        _writeBmp(path, self.width, self.height, self._pixels)
