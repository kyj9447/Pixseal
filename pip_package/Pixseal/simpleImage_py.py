# 바이너리 구조체 패킹/언패킹에 사용
import struct

# PNG 압축/CRC 계산에 사용
import zlib

# 바이트 스트림 처리를 위한 클래스
from io import BytesIO

# 파일 경로 객체 처리
from pathlib import Path

# 타입 힌트 정의
from typing import BinaryIO, Iterable, List, Optional, Sequence, Tuple, TypeAlias, Union

# PNG 파일 시그니처(매직 넘버)
PNG_SIGNATURE: bytes = b"\x89PNG\r\n\x1a\n"


# PNG 필터에서 Paeth 예측값을 계산한다.
# Paeth 필터(타입 4)는 주변 3픽셀의 값으로 현재 값을 예측한다.
# a=왼쪽, b=위, c=좌상단이며 p=a+b-c 를 기준으로 가장 가까운 값을 선택한다.
def _paethPredictor(a: int, b: int, c: int) -> int:
    # 기본 예측값 계산
    p = a + b - c
    # 각 후보와의 거리 계산
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    # 가장 가까운 후보를 선택
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


# PNG 필터 타입에 따라 한 줄(스캔라인)을 복원한다.
# PNG는 각 스캔라인 앞에 "필터 타입 1바이트"가 붙고,
# 필터가 적용된 바이트를 원본으로 되돌리는 과정이 필요하다.
def _applyPngFilter(filterType: int, rowData: bytearray, prevRow: Sequence[int], bytesPerPixel: int) -> bytearray:
    # 복원된 결과를 담을 버퍼
    recon = bytearray(len(rowData))
    # 각 바이트를 순회하며 필터 해제
    for i in range(len(rowData)):
        # 왼쪽 픽셀 값(없으면 0)
        left = recon[i - bytesPerPixel] if i >= bytesPerPixel else 0
        # 윗줄 픽셀 값(없으면 0)
        up = prevRow[i] if prevRow else 0
        # 좌상단 픽셀 값(없으면 0)
        upLeft = prevRow[i - bytesPerPixel] if (prevRow and i >= bytesPerPixel) else 0

        # 필터 타입에 따라 복원 방식 선택
        # 0(None): 변환 없음
        # 1(Sub): 왼쪽 픽셀 값 더하기
        # 2(Up): 위쪽 픽셀 값 더하기
        # 3(Average): 왼쪽과 위쪽 평균 더하기
        # 4(Paeth): Paeth 예측값 더하기
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
            # 알 수 없는 필터는 오류 처리
            raise ValueError(f"Unsupported PNG filter: {filterType}")
    return recon


def _encodePngFilter(filterType: int, rowData: Sequence[int], prevRow: Sequence[int], bytesPerPixel: int) -> bytearray:
    if filterType == 0:
        return bytearray(rowData)
    filtered = bytearray(len(rowData))
    for i in range(len(rowData)):
        left = rowData[i - bytesPerPixel] if i >= bytesPerPixel else 0
        up = prevRow[i] if prevRow else 0
        upLeft = prevRow[i - bytesPerPixel] if (prevRow and i >= bytesPerPixel) else 0
        if filterType == 1:
            filtered[i] = (rowData[i] - left) & 0xFF
        elif filterType == 2:
            filtered[i] = (rowData[i] - up) & 0xFF
        elif filterType == 3:
            filtered[i] = (rowData[i] - ((left + up) >> 1)) & 0xFF
        elif filterType == 4:
            filtered[i] = (rowData[i] - _paethPredictor(left, up, upLeft)) & 0xFF
        else:
            raise ValueError(f"Unsupported PNG filter: {filterType}")
    return filtered


# PNG의 하나의 청크(type+data+crc)를 읽는다.
# PNG는 [length(4)][type(4)][data(length)][crc(4)] 구조로 반복된다.
# length는 data 길이만 의미하며, type/CRC는 포함하지 않는다.
def _readChunk(stream: BinaryIO) -> Tuple[bytes, bytes]:
    # 길이(4바이트)를 읽는다.
    lengthBytes = stream.read(4)
    if len(lengthBytes) == 0:
        # 더 이상 읽을 데이터가 없으면 종료 신호
        return b"", b""
    if len(lengthBytes) != 4:
        raise ValueError("Unexpected EOF while reading chunk length")
    # 빅엔디안 4바이트 정수로 변환
    length = struct.unpack(">I", lengthBytes)[0]
    # 청크 타입(4바이트) 읽기
    chunkType = stream.read(4)
    if len(chunkType) != 4:
        raise ValueError("Unexpected EOF while reading chunk type")
    # 청크 데이터 읽기
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Unexpected EOF while reading chunk data")
    # CRC 읽기
    crc = stream.read(4)
    if len(crc) != 4:
        raise ValueError("Unexpected EOF while reading chunk CRC")
    # CRC 검증: chunkType + data에 대해 CRC32 계산
    expectedCrc = zlib.crc32(chunkType)
    expectedCrc = zlib.crc32(data, expectedCrc) & 0xFFFFFFFF
    actualCrc = struct.unpack(">I", crc)[0]
    if actualCrc != expectedCrc:
        raise ValueError("Corrupted PNG chunk detected")
    return chunkType, data


# PNG 스트림에서 이미지 정보를 로드한다.
# PNG 열기 단계 요약:
# 1) 시그니처 검사
# 2) IHDR에서 이미지 메타정보 읽기
# 3) 모든 IDAT를 모아 zlib로 압축 해제
# 4) 스캔라인별 필터 해제 후 RGB(A) 버퍼로 복원
def _loadPng(
    stream: BinaryIO,
) -> Tuple[
        int,
        int,
        bytearray,
        int,
        Optional[bytearray],
        List[Tuple[bytes, Optional[bytes], int]],
        Optional[dict[str, int]],
        Optional[bytearray],
]:
    # 파일 시그니처 확인(8바이트 고정)
    signature = stream.read(8)
    if signature != PNG_SIGNATURE:
        raise ValueError("Unsupported PNG signature")

    # IHDR에서 읽을 값들을 초기화
    width: int = 0
    height: int = 0
    bitDepth = colorType = None
    compression = filterMethod = interlace = None
    # IDAT 데이터 목록
    idatChunks: List[bytes] = []
    # 원본 청크 구조 기록(재저장 시 유지용)
    chunk_records: List[Tuple[bytes, Optional[bytes], int]] = []

    # 청크를 순서대로 읽는다(IHDR/IDAT/IEND 등)
    while True:
        chunkType, data = _readChunk(stream)
        if chunkType == b"":
            break
        if chunkType == b"IHDR":
            # IHDR 포맷: width, height, bitDepth, colorType, compression, filter, interlace
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
            # IDAT는 압축된 이미지 데이터
            idatChunks.append(data)
            chunk_records.append((chunkType, None, len(data)))
        else:
            # 다른 청크는 그대로 기록
            chunk_records.append((chunkType, data, len(data)))

        if chunkType == b"IEND":
            break

    # 필수 헤더 값이 모두 있는지 확인
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
    # 지원되는 포맷인지 확인
    if bitDepth != 8:
        raise ValueError("Only 8-bit PNG images are supported")
    if colorType not in (2, 6):
        raise ValueError("Only RGB/RGBA PNG images are supported")
    if compression != 0 or filterMethod != 0 or interlace != 0:
        raise ValueError("Unsupported PNG configuration (compression/filter/interlace)")

    # IDAT를 모두 합쳐서 압축 해제
    # PNG는 여러 IDAT로 분할될 수 있으므로 합쳐서 zlib로 해제한다.
    rawImage = zlib.decompress(b"".join(idatChunks))
    # 컬러 타입에 따른 바이트 수
    bytesPerPixel = 3 if colorType == 2 else 4
    # 한 줄(필터 제외) 바이트 수
    rowLength = width * bytesPerPixel
    # 예상되는 전체 길이(각 줄의 필터 1바이트 포함)
    expected = height * (rowLength + 1)
    if len(rawImage) != expected:
        raise ValueError("Malformed PNG image data")

    # RGB 픽셀 저장용 버퍼(내부 표현은 RGB 고정)
    pixel_count = width * height
    pixels = bytearray(pixel_count * 3)
    # 알파 채널(있을 때만 별도 버퍼로 보관)
    alpha = bytearray(pixel_count) if bytesPerPixel == 4 else None
    filter_types = bytearray(height)
    # 이전 줄 버퍼(필터 해제용)
    prevRow = bytearray(rowLength)
    # rawImage에서 현재 위치
    offset = 0
    for y in range(height):
        # 각 줄의 첫 바이트는 필터 타입
        # 각 줄의 첫 바이트는 필터 타입
        filterType = rawImage[offset]
        offset += 1
        filter_types[y] = filterType
        # 현재 줄 데이터 추출
        rowBytes = bytearray(rawImage[offset:offset + rowLength])
        offset += rowLength
        # 필터 해제: 현재 줄 + 이전 줄 정보를 이용해 복원
        recon = _applyPngFilter(filterType, rowBytes, prevRow, bytesPerPixel)
        # 픽셀을 RGB/알파로 분리 저장
        for x in range(width):
            srcIndex = x * bytesPerPixel
            destIndex = (y * width + x) * 3
            pixel_index = y * width + x
            pixels[destIndex] = recon[srcIndex]
            pixels[destIndex + 1] = recon[srcIndex + 1]
            pixels[destIndex + 2] = recon[srcIndex + 2]
            if alpha is not None:
                alpha[pixel_index] = recon[srcIndex + 3]
        # 다음 줄을 위해 이전 줄 갱신(필터 해제에 필요)
        prevRow = recon
    return (
        width,
        height,
        pixels,
        bytesPerPixel,
        alpha,
        chunk_records,
        None,
        filter_types,
    )


# PNG 청크를 만들기 위한 바이너리 데이터 생성
# length + type + data + crc 형태로 구성한다.
def _makeChunk(chunkType: bytes, data: bytes) -> bytes:
    # 데이터 길이
    length = struct.pack(">I", len(data))
    # CRC 계산
    crcValue = zlib.crc32(chunkType)
    crcValue = zlib.crc32(data, crcValue) & 0xFFFFFFFF
    crc = struct.pack(">I", crcValue)
    # length + type + data + crc
    return length + chunkType + data + crc


# PNG 스캔라인을 생성한다(필터 타입이 있으면 재사용).
# PNG 저장 시 각 줄 앞에 필터 타입을 붙이고,
# 픽셀을 RGB(또는 RGBA) 순서로 나열한다.
def _build_scanlines(
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]],
    filter_types: Optional[Sequence[int]] = None,
) -> bytes:
    # 한 줄의 RGB 바이트 수
    rowStride = width * 3
    bytes_per_pixel = 4 if alpha is not None else 3
    row_length = width * bytes_per_pixel
    raw = bytearray()
    # 픽셀 버퍼를 bytearray로 통일
    pix_buf = pixels if isinstance(pixels, bytearray) else bytearray(pixels)
    alpha_buf = None
    if alpha is not None:
        alpha_buf = alpha if isinstance(alpha, bytearray) else bytearray(alpha)
    if filter_types is not None and len(filter_types) != height:
        raise ValueError("PNG filter count does not match image height")

    prev_row = bytearray(row_length)
    for y in range(height):
        row_buf = bytearray(row_length)
        row_start = y * rowStride
        for x in range(width):
            idx = row_start + x * 3
            if alpha_buf is not None:
                dest = x * 4
                row_buf[dest] = pix_buf[idx]
                row_buf[dest + 1] = pix_buf[idx + 1]
                row_buf[dest + 2] = pix_buf[idx + 2]
                row_buf[dest + 3] = alpha_buf[y * width + x]
            else:
                dest = x * 3
                row_buf[dest] = pix_buf[idx]
                row_buf[dest + 1] = pix_buf[idx + 1]
                row_buf[dest + 2] = pix_buf[idx + 2]
        filterType = filter_types[y] if filter_types is not None else 0
        if filterType > 4:
            raise ValueError(f"Unsupported PNG filter: {filterType}")
        raw.append(filterType)
        if filterType == 0:
            raw.extend(row_buf)
        else:
            raw.extend(_encodePngFilter(filterType, row_buf, prev_row, bytes_per_pixel))
        prev_row = row_buf
    return bytes(raw)


# PNG 파일로 저장한다.
# PNG 저장 단계 요약:
# 1) IHDR 생성(폭/높이/색상정보)
# 2) 스캔라인 생성(필터 적용)
# 3) zlib 압축으로 IDAT 생성
# 4) 시그니처 + IHDR + IDAT + IEND 기록
def _writePng(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]] = None,
    filter_types: Optional[Sequence[int]] = None,
) -> None:
    # 입력 길이 검증
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")

    # 알파 유무에 따라 컬러 타입 결정(2=RGB, 6=RGBA)
    colorType = 6 if alpha is not None else 2
    # IHDR: width, height, bitDepth(8), colorType, compression, filterMethod, interlace
    ihdr = struct.pack(">IIBBBBB", width, height, 8, colorType, 0, 0, 0)
    filtered = _build_scanlines(width, height, pixels, alpha, filter_types)
    # 스캔라인 전체를 zlib로 압축
    compressed = zlib.compress(filtered)
    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        output.write(_makeChunk(b"IHDR", ihdr))
        output.write(_makeChunk(b"IDAT", compressed))
        output.write(_makeChunk(b"IEND", b""))


# 압축된 IDAT 데이터를 기존 청크 길이에 맞춰 분할한다.
# 원본 PNG의 IDAT 청크 길이를 보존하면 재저장 시 구조가 유지된다.
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
            # 마지막 청크는 남은 모든 데이터
            take = total - offset
        else:
            # 길이에 맞춰 잘라서 사용
            take = min(length, total - offset)
        if take <= 0:
            continue
        parts.append(data[offset:offset + take])
        offset += take
    # 남은 데이터가 있으면 추가
    if offset < total:
        parts.append(data[offset:])
    # target_lengths가 비어도 데이터가 있으면 그대로 추가
    if not parts and total:
        parts.append(data)
    return parts


# 기존 청크 구조를 유지하면서 PNG를 저장한다.
# IDAT는 새로 압축한 데이터로 교체하되,
# 그 외 청크는 원래 순서/내용을 유지한다.
def _writePngWithChunks(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    alpha: Optional[Sequence[int]],
    chunks: List[Tuple[bytes, Optional[bytes], int]],
    filter_types: Optional[Sequence[int]] = None,
) -> None:
    if not chunks:
        _writePng(path, width, height, pixels, alpha, filter_types)
        return

    # 입력 길이 검증
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")

    # 새로운 IDAT 데이터 생성
    filtered = _build_scanlines(width, height, pixels, alpha, filter_types)
    compressed = zlib.compress(filtered)
    idat_lengths = [length for chunkType, _, length in chunks if chunkType == b"IDAT"]
    parts = _split_idat_payload(compressed, idat_lengths) or [compressed]

    # 청크를 쓰는 헬퍼 함수
    def write_chunk(output: BinaryIO, chunkType: bytes, payload: bytes) -> None:
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
                    # 분할된 IDAT를 모두 기록
                    for part in parts:
                        write_chunk(output, b"IDAT", part)
                    idat_written = True
                continue
            # 원본 청크 그대로 기록
            payload = data if data is not None else b""
            write_chunk(output, chunkType, payload)
        if not idat_written:
            # IDAT가 없던 경우 새로 기록
            for part in parts:
                write_chunk(output, b"IDAT", part)


# BMP 스트림에서 이미지 정보를 로드한다.
def _loadBmp(
    stream: BinaryIO,
) -> Tuple[
        int,
        int,
        bytearray,
        int,
        Optional[bytearray],
        Optional[List[Tuple[bytes, Optional[bytes], int]]],
        Optional[dict[str, int]],
        Optional[bytearray],
]:
    # BMP 파일 헤더(14바이트) 읽기
    header = stream.read(14)
    if len(header) != 14 or header[:2] != b"BM":
        raise ValueError("Unsupported BMP header")
    # 파일 크기와 픽셀 데이터 위치
    _, _, _, pixelOffset = struct.unpack("<IHHI", header[2:])
    # DIB 헤더 크기 읽기
    dibHeaderSizeBytes = stream.read(4)
    if len(dibHeaderSizeBytes) != 4:
        raise ValueError("Corrupted BMP DIB header")
    dibHeaderSize = struct.unpack("<I", dibHeaderSizeBytes)[0]
    if dibHeaderSize != 40:
        raise ValueError("Only BITMAPINFOHEADER BMP files are supported")
    # DIB 헤더 나머지(36바이트) 읽기
    dibData = stream.read(36)
    (
        width,
        height,
        planes,
        bitCount,
        compression,
        xPpm,
        yPpm,
        clrUsed,
        clrImportant,
    ) = struct.unpack("<iiHHIIiiII", dibData)
    if planes != 1 or bitCount != 24 or compression != 0:
        raise ValueError("Only uncompressed 24-bit BMP files are supported")
    # 높이가 음수면 위에서 아래 방향
    absHeight = abs(height)
    # 각 줄은 4바이트 정렬
    rowStride = ((width * 3 + 3) // 4) * 4
    pixels = bytearray(width * absHeight * 3)
    # 픽셀 데이터 시작 위치로 이동
    stream.seek(pixelOffset)
    for row in range(absHeight):
        # 한 줄 데이터 읽기
        rowData = stream.read(rowStride)
        if len(rowData) != rowStride:
            raise ValueError("Incomplete BMP pixel data")
        # BMP는 기본적으로 아래에서 위로 저장
        targetRow = absHeight - 1 - row if height > 0 else row
        baseIndex = targetRow * width * 3
        for x in range(width):
            pixelOffsetInRow = x * 3
            # BMP는 BGR 순서
            b = rowData[pixelOffsetInRow]
            g = rowData[pixelOffsetInRow + 1]
            r = rowData[pixelOffsetInRow + 2]
            dest = baseIndex + x * 3
            pixels[dest] = r & 0xFF
            pixels[dest + 1] = g & 0xFF
            pixels[dest + 2] = b & 0xFF
    # 일부 메타데이터 보관
    metadata = {
        "xppm": xPpm,
        "yppm": yPpm,
        "clrUsed": clrUsed,
        "clrImportant": clrImportant,
    }
    return width, absHeight, pixels, 3, None, None, metadata, None


# BMP 파일로 저장한다.
def _writeBmp(
    path: str,
    width: int,
    height: int,
    pixels: Sequence[int],
    meta: Optional[dict[str, int]] = None,
) -> None:
    # 한 줄을 4바이트 정렬로 계산
    rowStride = ((width * 3 + 3) // 4) * 4
    pixelArraySize = rowStride * height
    fileSize = 14 + 40 + pixelArraySize
    # 메타데이터(없으면 기본값)
    xppm = int(meta.get("xppm", 2835)) if meta else 2835
    yppm = int(meta.get("yppm", 2835)) if meta else 2835
    clrUsed = int(meta.get("clrUsed", 0)) if meta else 0
    clrImportant = int(meta.get("clrImportant", 0)) if meta else 0
    with open(path, "wb") as output:
        # BMP 헤더 작성
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
            ))
        # 한 줄 패딩 바이트 계산
        rowPad = rowStride - width * 3
        padBytes = b"\x00" * rowPad
        # BMP는 아래에서 위로 저장
        for y in range(height - 1, -1, -1):
            start = y * width * 3
            for x in range(width):
                idx = start + x * 3
                r = pixels[idx]
                g = pixels[idx + 1]
                b = pixels[idx + 2]
                # BMP는 BGR 순서로 저장
                output.write(bytes((b & 0xFF, g & 0xFF, r & 0xFF)))
            if rowPad:
                output.write(padBytes)


# 이미지 입력 타입 정의(파일 경로 또는 바이트)
ImageInput: TypeAlias = Union[str, Path, bytes, bytearray, "SimpleImage"]


class SimpleImage:
    # 인스턴스에서 사용하는 속성 이름을 제한
    __slots__ = (
        "width",
        "height",
        "pixels",
        "_alpha",
        "_png_chunks",
        "_png_filters",
        "_bmp_header",
    )

    def __init__(
        self,
        width: int,
        height: int,
        pixels: Sequence[int],
        alpha: Optional[Sequence[int]] = None,
        png_chunks: Optional[List[Tuple[bytes, Optional[bytes], int]]] = None,
        bmp_header: Optional[dict[str, int]] = None,
        png_filters: Optional[Sequence[int]] = None,
    ) -> None:
        # 이미지 크기 설정
        self.width = width
        self.height = height
        # 픽셀 데이터 길이 검증
        expected = width * height * 3
        if len(pixels) != expected:
            raise ValueError("Pixel data length does not match image dimensions")
        self.pixels = bytearray(pixels)
        # 알파 채널 처리
        if alpha is not None:
            if len(alpha) != width * height:
                raise ValueError("Alpha channel length does not match image dimensions")
            self._alpha = bytearray(alpha)
        else:
            self._alpha = None
        # PNG 청크 정보(있으면 복사)
        self._png_chunks = list(png_chunks) if png_chunks is not None else None
        if png_filters is not None:
            if len(png_filters) != height:
                raise ValueError("PNG filter count does not match image height")
            self._png_filters = bytearray(png_filters)
        else:
            self._png_filters = None
        # BMP 헤더 정보(있으면 복사)
        self._bmp_header = dict(bmp_header) if bmp_header is not None else None

    @property
    def size(self) -> Tuple[int, int]:
        # (너비, 높이) 튜플 반환
        return self.width, self.height

    @staticmethod
    def _streamToImage(
        stream: BinaryIO,
    ) -> Tuple[
            int,
            int,
            bytearray,
            int,
            Optional[bytearray],
            Optional[List[Tuple[bytes, Optional[bytes], int]]],
            Optional[dict[str, int]],
            Optional[bytearray],
    ]:
        # 시그니처로 포맷 판별
        signature = stream.read(8)
        stream.seek(0)
        if signature.startswith(PNG_SIGNATURE):
            return _loadPng(stream)
        if signature[:2] == b"BM":
            return _loadBmp(stream)
        raise ValueError("Unsupported image format")

    @classmethod
    def open(cls, source: ImageInput) -> "SimpleImage":
        # 파일 경로 또는 바이트 입력 처리
        if isinstance(source, SimpleImage):
            return source
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
                    png_filters,
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
                png_filters,
            ) = cls._streamToImage(stream)
        else:
            raise TypeError("source must be a file path or raw bytes")
        # SimpleImage 객체 생성
        image = cls(width, height, pixels, alpha, chunks, bmp_meta, png_filters)
        print(f"[SimpleImage] Opened image: {width}x{height}, channels={channels}")
        return image

    def _getPixel(self, coords: Tuple[int, int]) -> Tuple[int, int, int]:
        # 좌표에서 픽셀 값 가져오기
        x, y = coords
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise ValueError("Pixel coordinate out of bounds")
        index = (y * self.width + x) * 3
        return (
            self.pixels[index],
            self.pixels[index + 1],
            self.pixels[index + 2],
        )

    def _putPixel(self, coords: Tuple[int, int], value: Sequence[int]) -> None:
        # 좌표에 픽셀 값 넣기
        x, y = coords
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise ValueError("Pixel coordinate out of bounds")
        index = (y * self.width + x) * 3
        r, g, b = value
        self.pixels[index] = int(r) & 0xFF
        self.pixels[index + 1] = int(g) & 0xFF
        self.pixels[index + 2] = int(b) & 0xFF

    def _copy(self) -> "SimpleImage":
        # 내부 버퍼를 복사해서 새 객체 생성
        alpha_copy = self._alpha[:] if self._alpha is not None else None
        png_chunks = self._png_chunks[:] if self._png_chunks is not None else None
        png_filters = self._png_filters[:] if self._png_filters is not None else None
        bmp_header = self._bmp_header.copy() if self._bmp_header is not None else None
        return SimpleImage(
            self.width,
            self.height,
            self.pixels[:],
            alpha_copy,
            png_chunks,
            bmp_header,
            png_filters,
        )

    def save(self, path: str) -> None:
        # 원본 포맷 정보가 있으면 유지해서 저장
        if self._png_chunks is not None:
            _writePngWithChunks(
                path,
                self.width,
                self.height,
                self.pixels,
                self._alpha,
                self._png_chunks,
                self._png_filters,
            )
        elif self._bmp_header is not None:
            _writeBmp(path, self.width, self.height, self.pixels, self._bmp_header)
        else:
            _writePng(
                path,
                self.width,
                self.height,
                self.pixels,
                self._alpha,
                self._png_filters,
            )
