import struct
import zlib
from io import BytesIO
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Tuple, Union

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _paethPredictor(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _applyPngFilter(
    filterType: int, rowData: bytearray, prevRow: Sequence[int], bytesPerPixel: int
) -> bytearray:
    recon = bytearray(len(rowData))
    for i in range(len(rowData)):
        left = recon[i - bytesPerPixel] if i >= bytesPerPixel else 0
        up = prevRow[i] if prevRow else 0
        upLeft = prevRow[i - bytesPerPixel] if (prevRow and i >= bytesPerPixel) else 0

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
            raise ValueError(f"Unsupported PNG filter: {filterType}")
    return recon


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


def _loadPng(
    stream,
) -> Tuple[
    int,
    int,
    bytearray,
    int,
    Optional[bytearray],
    List[Tuple[bytes, Optional[bytes], int]],
    Optional[dict],
]:
    signature = stream.read(8)
    if signature != PNG_SIGNATURE:
        raise ValueError("Unsupported PNG signature")

    width = height = None
    bitDepth = colorType = None
    compression = filterMethod = interlace = None
    idatChunks: List[bytes] = []
    chunk_records: List[Tuple[bytes, Optional[bytes], int]] = []

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

    if None in (
        width,
        height,
        bitDepth,
        colorType,
        compression,
        filterMethod,
        interlace,
    ):
        raise ValueError("Incomplete PNG header information")
    if bitDepth != 8:
        raise ValueError("Only 8-bit PNG images are supported")
    if colorType not in (2, 6):
        raise ValueError("Only RGB/RGBA PNG images are supported")
    if compression != 0 or filterMethod != 0 or interlace != 0:
        raise ValueError("Unsupported PNG configuration (compression/filter/interlace)")

    rawImage = zlib.decompress(b"".join(idatChunks))
    bytesPerPixel = 3 if colorType == 2 else 4
    rowLength = width * bytesPerPixel
    expected = height * (rowLength + 1)
    if len(rawImage) != expected:
        raise ValueError("Malformed PNG image data")

    pixel_count = width * height
    pixels = bytearray(pixel_count * 3)
    alpha = bytearray(pixel_count) if bytesPerPixel == 4 else None
    prevRow = bytearray(rowLength)
    offset = 0
    for y in range(height):
        filterType = rawImage[offset]
        offset += 1
        rowBytes = bytearray(rawImage[offset : offset + rowLength])
        offset += rowLength
        recon = _applyPngFilter(filterType, rowBytes, prevRow, bytesPerPixel)
        for x in range(width):
            srcIndex = x * bytesPerPixel
            destIndex = (y * width + x) * 3
            pixel_index = y * width + x
            pixels[destIndex] = recon[srcIndex]
            pixels[destIndex + 1] = recon[srcIndex + 1]
            pixels[destIndex + 2] = recon[srcIndex + 2]
            if alpha is not None:
                alpha[pixel_index] = recon[srcIndex + 3]
        prevRow = recon
    return width, height, pixels, bytesPerPixel, alpha, chunk_records, None


def _loadBmp(
    stream,
) -> Tuple[
    int,
    int,
    bytearray,
    int,
    Optional[bytearray],
    Optional[List[Tuple[bytes, Optional[bytes], int]]],
    Optional[dict],
]:
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
    for row in range(absHeight):
        rowData = stream.read(rowStride)
        if len(rowData) != rowStride:
            raise ValueError("Incomplete BMP pixel data")
        targetRow = absHeight - 1 - row if height > 0 else row
        baseIndex = targetRow * width * 3
        for x in range(width):
            pixelOffsetInRow = x * 3
            b = rowData[pixelOffsetInRow]
            g = rowData[pixelOffsetInRow + 1]
            r = rowData[pixelOffsetInRow + 2]
            dest = baseIndex + x * 3
            pixels[dest] = r & 0xFF
            pixels[dest + 1] = g & 0xFF
            pixels[dest + 2] = b & 0xFF
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


def _build_scanlines(
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]],
) -> bytes:
    rowStride = width * 3
    raw = bytearray()
    pix_buf = pixels if isinstance(pixels, bytearray) else bytearray(pixels)
    alpha_buf = None
    if alpha is not None:
        alpha_buf = alpha if isinstance(alpha, bytearray) else bytearray(alpha)

    for y in range(height):
        raw.append(0)
        row_start = y * rowStride
        for x in range(width):
            idx = row_start + x * 3
            raw.extend(pix_buf[idx : idx + 3])
            if alpha_buf is not None:
                raw.append(alpha_buf[y * width + x])
    return bytes(raw)


def _writePng(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]] = None,
) -> None:
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")

    colorType = 6 if alpha is not None else 2
    ihdr = struct.pack(">IIBBBBB", width, height, 8, colorType, 0, 0, 0)
    filtered = _build_scanlines(width, height, pixels, alpha)
    compressed = zlib.compress(filtered)
    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        output.write(_makeChunk(b"IHDR", ihdr))
        output.write(_makeChunk(b"IDAT", compressed))
        output.write(_makeChunk(b"IEND", b""))


def _split_idat_payload(data: bytes, target_lengths: Iterable[int]) -> List[bytes]:
    parts: List[bytes] = []
    offset = 0
    total = len(data)
    lengths = list(target_lengths)
    count = len(lengths)
    for idx, length in enumerate(lengths):
        if offset >= total:
            break
        if length <= 0:
            continue
        if idx == count - 1:
            take = total - offset
        else:
            take = min(length, total - offset)
        if take <= 0:
            continue
        parts.append(data[offset : offset + take])
        offset += take
    if offset < total:
        parts.append(data[offset:])
    if not parts and total:
        parts.append(data)
    return parts


def _writePngWithChunks(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]],
    chunks: List[Tuple[bytes, Optional[bytes], int]],
) -> None:
    if not chunks:
        _writePng(path, width, height, pixels, alpha)
        return

    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")

    filtered = _build_scanlines(width, height, pixels, alpha)
    compressed = zlib.compress(filtered)
    idat_lengths = [length for chunkType, _, length in chunks if chunkType == b"IDAT"]
    parts = _split_idat_payload(compressed, idat_lengths) or [compressed]

    def write_chunk(output, chunkType: bytes, payload: bytes) -> None:
        output.write(len(payload).to_bytes(4, "big"))
        output.write(chunkType)
        output.write(payload)
        crc = zlib.crc32(chunkType)
        crc = zlib.crc32(payload, crc) & 0xFFFFFFFF
        output.write(struct.pack(">I", crc))

    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        idat_written = False
        for chunkType, data, _ in chunks:
            if chunkType == b"IDAT":
                if not idat_written:
                    for part in parts:
                        write_chunk(output, b"IDAT", part)
                    idat_written = True
                continue
            payload = data if data is not None else b""
            write_chunk(output, chunkType, payload)
        if not idat_written:
            for part in parts:
                write_chunk(output, b"IDAT", part)


def _writeBmp(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    meta: Optional[dict] = None,
) -> None:
    rowStride = ((width * 3 + 3) // 4) * 4
    pixelArraySize = rowStride * height
    fileSize = 14 + 40 + pixelArraySize
    xppm = int(meta.get("xppm", 2835)) if meta else 2835
    yppm = int(meta.get("yppm", 2835)) if meta else 2835
    clrUsed = int(meta.get("clrUsed", 0)) if meta else 0
    clrImportant = int(meta.get("clrImportant", 0)) if meta else 0
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
                r = pixels[idx]
                g = pixels[idx + 1]
                b = pixels[idx + 2]
                output.write(bytes((b & 0xFF, g & 0xFF, r & 0xFF)))
            if rowPad:
                output.write(padBytes)


ImageInput = Union[str, Path, bytes, bytearray]


class SimpleImage:
    __slots__ = ("width", "height", "_pixels", "_alpha", "_png_chunks", "_bmp_header")

    def __init__(
        self,
        width: int,
        height: int,
        pixels: Sequence[int],
        alpha: Optional[Sequence[int]] = None,
        png_chunks: Optional[List[Tuple[bytes, Optional[bytes], int]]] = None,
        bmp_header: Optional[dict] = None,
    ):
        self.width = width
        self.height = height
        expected = width * height * 3
        if len(pixels) != expected:
            raise ValueError("Pixel data length does not match image dimensions")
        self._pixels = bytearray(pixels)
        if alpha is not None:
            if len(alpha) != width * height:
                raise ValueError("Alpha channel length does not match image dimensions")
            self._alpha = bytearray(alpha)
        else:
            self._alpha = None
        self._png_chunks = list(png_chunks) if png_chunks is not None else None
        self._bmp_header = dict(bmp_header) if bmp_header is not None else None

    @property
    def size(self) -> Tuple[int, int]:
        return self.width, self.height

    @staticmethod
    def _streamToImage(
        stream,
    ) -> Tuple[
        int,
        int,
        bytearray,
        int,
        Optional[bytearray],
        Optional[List[Tuple[bytes, Optional[bytes], int]]],
        Optional[dict],
    ]:
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
        alpha_copy = self._alpha[:] if self._alpha is not None else None
        png_chunks = self._png_chunks[:] if self._png_chunks is not None else None
        bmp_header = self._bmp_header.copy() if self._bmp_header is not None else None
        return SimpleImage(
            self.width,
            self.height,
            self._pixels[:],
            alpha_copy,
            png_chunks,
            bmp_header,
        )

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
