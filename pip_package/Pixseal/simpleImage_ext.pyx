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
    chunk_records = []

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
        if chunkType == b"IDAT":
            idatChunks.append(data)
            chunk_records.append((chunkType, None, len(data)))
        else:
            chunk_records.append((chunkType, data, len(data)))

        if chunkType == b"IEND":
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
    alpha = bytearray(width * height) if bytesPerPixel == 4 else None
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
            if alpha is not None:
                alpha[y * width + x] = recon_view[srcIndex + 3]
        prevRow = recon
        prev_view = recon_view
    return width, height, pixels, bytesPerPixel, alpha, chunk_records, None


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
    metadata = {
        "xppm": xPpm,
        "yppm": yPpm,
        "clrUsed": clrUsed,
        "clrImportant": clrImportant,
    }
    return width, absHeight, pixels, 3, None, None, metadata


def _makeChunk(chunkType: bytes, data: bytes) -> bytes:
    length = struct.pack(">I", len(data))
    crcValue = zlib.crc32(chunkType)
    crcValue = zlib.crc32(data, crcValue) & 0xFFFFFFFF
    crc = struct.pack(">I", crcValue)
    return length + chunkType + data + crc


@cython.boundscheck(False)
@cython.wraparound(False)
cdef void _write_png_bytes(
    int width,
    int height,
    uint8_t[:] pixels,
    object alpha_obj,
    bytearray raw,
):
    cdef bint has_alpha = alpha_obj is not None
    cdef uint8_t[:] alpha_view
    cdef int y, x, start, idx
    raw.clear()
    if has_alpha:
        alpha_view = alpha_obj
    for y in range(height):
        raw.append(0)
        start = y * width * 3
        for x in range(width):
            idx = start + x * 3
            raw.append(pixels[idx])
            raw.append(pixels[idx + 1])
            raw.append(pixels[idx + 2])
            if has_alpha:
                raw.append(alpha_view[y * width + x])


def _writePng(path, int width, int height, object pixels, object alpha=None) -> None:
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6 if alpha is not None else 2, 0, 0, 0)
    raw = bytearray()
    if isinstance(pixels, bytearray):
        pix_buf = pixels
    else:
        pix_buf = bytearray(pixels)
    _write_png_bytes(width, height, pix_buf, alpha, raw)
    compressed = zlib.compress(bytes(raw))
    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        output.write(_makeChunk(b"IHDR", ihdr))
        output.write(_makeChunk(b"IDAT", compressed))
        output.write(_makeChunk(b"IEND", b""))


def _split_idat_payload(bytes data, list lengths):
    parts = []
    offset = 0
    total = len(data)
    count = len(lengths)
    cdef Py_ssize_t idx
    for idx in range(count):
        length = lengths[idx]
        if offset >= total:
            break
        if length <= 0:
            continue
        if idx == count - 1:
            take = total - offset
        else:
            take = length if length < total - offset else total - offset
        if take <= 0:
            continue
        parts.append(data[offset : offset + take])
        offset += take
    if offset < total:
        parts.append(data[offset:])
    if not parts and total:
        parts.append(data)
    return parts


def _writePngWithChunks(path, int width, int height, object pixels, object alpha, object chunks):
    if not chunks:
        _writePng(path, width, height, pixels, alpha)
        return
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")
    raw = bytearray()
    if isinstance(pixels, bytearray):
        pix_buf = pixels
    else:
        pix_buf = bytearray(pixels)
    _write_png_bytes(width, height, pix_buf, alpha, raw)
    compressed = zlib.compress(bytes(raw))
    lengths = [length for chunkType, _, length in chunks if chunkType == b"IDAT"]
    parts = _split_idat_payload(compressed, lengths)
    if not parts:
        parts = [compressed]

    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        idat_written = False
        for chunkType, data, _ in chunks:
            if chunkType == b"IDAT":
                if not idat_written:
                    for part in parts:
                        output.write(len(part).to_bytes(4, "big"))
                        output.write(b"IDAT")
                        output.write(part)
                        crc = zlib.crc32(b"IDAT")
                        crc = zlib.crc32(part, crc) & 0xFFFFFFFF
                        output.write(struct.pack(">I", crc))
                    idat_written = True
                continue
            payload = data if data is not None else b""
            output.write(len(payload).to_bytes(4, "big"))
            output.write(chunkType)
            output.write(payload)
            crc = zlib.crc32(chunkType)
            crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
            output.write(struct.pack(">I", crc))
        if not idat_written:
            for part in parts:
                output.write(len(part).to_bytes(4, "big"))
                output.write(b"IDAT")
                output.write(part)
                crc = zlib.crc32(b"IDAT")
                crc = zlib.crc32(part, crc) & 0xFFFFFFFF
                output.write(struct.pack(">I", crc))


def _writeBmp(path, int width, int height, object pixels, object meta=None) -> None:
    rowStride = ((width * 3 + 3) // 4) * 4
    pixelArraySize = rowStride * height
    fileSize = 14 + 40 + pixelArraySize
    if meta is not None:
        xppm = int(meta.get("xppm", 2835))
        yppm = int(meta.get("yppm", 2835))
        clrUsed = int(meta.get("clrUsed", 0))
        clrImportant = int(meta.get("clrImportant", 0))
    else:
        xppm = yppm = 2835
        clrUsed = clrImportant = 0
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
                xppm,
                yppm,
                clrUsed,
                clrImportant,
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
    cdef public object _alpha
    cdef public object _png_chunks
    cdef public object _bmp_header

    def __cinit__(
        self,
        int width,
        int height,
        object pixels,
        object alpha=None,
        object png_chunks=None,
        object bmp_header=None,
    ):
        cdef Py_ssize_t expected = width * height * 3
        if len(pixels) != expected:
            raise ValueError("Pixel data length does not match image dimensions")
        self.width = width
        self.height = height
        if isinstance(pixels, bytearray):
            self._pixels = bytearray(pixels)
        else:
            self._pixels = bytearray(pixels)
        if alpha is not None:
            if len(alpha) != width * height:
                raise ValueError("Alpha channel length does not match image dimensions")
            if isinstance(alpha, bytearray):
                self._alpha = bytearray(alpha)
            else:
                self._alpha = bytearray(alpha)
        else:
            self._alpha = None
        if png_chunks is not None:
            self._png_chunks = list(png_chunks)
        else:
            self._png_chunks = None
        if bmp_header is not None:
            self._bmp_header = dict(bmp_header)
        else:
            self._bmp_header = None

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
                (
                    width,
                    height,
                    pixels,
                    channels,
                    alpha,
                    chunks,
                    bmp_meta,
                ) = cls._streamToImage(stream)
        elif isinstance(source, (bytes, bytearray)):
            stream = BytesIO(source)
            (
                width,
                height,
                pixels,
                channels,
                alpha,
                chunks,
                bmp_meta,
            ) = cls._streamToImage(stream)
        else:
            raise TypeError("source must be a file path or raw bytes")
        image = cls(width, height, pixels, alpha, chunks, bmp_meta)
        print(f"[SimpleImage] Opened image: {width}x{height}, channels={channels}")
        return image

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
        cdef object alpha_copy
        cdef object chunk_copy
        if self._alpha is None:
            alpha_copy = None
        else:
            alpha_copy = self._alpha[:]
        if self._png_chunks is None:
            chunk_copy = None
        else:
            chunk_copy = self._png_chunks[:]
        if self._bmp_header is None:
            bmp_copy = None
        else:
            bmp_copy = dict(self._bmp_header)
        return SimpleImage(self.width, self.height, self._pixels[:], alpha_copy, chunk_copy, bmp_copy)

    def save(self, path: str) -> None:
        if self._png_chunks is not None:
            _writePngWithChunks(
                path,
                self.width,
                self.height,
                self._pixels,
                self._alpha,
                self._png_chunks,
            )
        elif self._bmp_header is not None:
            _writeBmp(path, self.width, self.height, self._pixels, self._bmp_header)
        else:
            _writePng(path, self.width, self.height, self._pixels, self._alpha)

    def saveBmp(self, path: str) -> None:
        _writeBmp(path, self.width, self.height, self._pixels, self._bmp_header)
