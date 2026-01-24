# Cython 컴파일 옵션 설정(파이썬 3 문법, 범위 체크/래핑 비활성화)
# cython: language_level=3, boundscheck=False, wraparound=False
from __future__ import annotations
# 바이너리 구조체 패킹/언패킹에 사용
import struct
# PNG 압축/CRC 계산에 사용
import zlib
# 바이트 스트림 처리
from io import BytesIO
# 파일 경로 처리
from pathlib import Path
# 타입 힌트 정의
from typing import List, Sequence, Tuple, Union

# Cython 기능 사용
cimport cython
# C 수준 uint8_t 타입 사용
from libc.stdint cimport uint8_t

# PNG 파일 시그니처(매직 넘버)
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"

# 이미지 입력 타입 정의
ImageInput = Union[str, Path, bytes, bytearray, "SimpleImage"]


# PNG 필터의 Paeth 예측값 계산(C 함수)
@cython.cfunc
cdef int _paethPredictor(int a, int b, int c) nogil:
    # PNG 필터 4(Paeth)의 핵심: 주변 3픽셀(a=왼쪽, b=위, c=좌상단)로 예측값을 계산
    # p = a + b - c 는 선형 예측 값(대각선 방향 변화도 고려)
    # 기본 예측값 계산
    cdef int p = a + b - c
    # 각 후보와의 거리 계산
    cdef int pa = p - a
    if pa < 0:
        pa = -pa
    cdef int pb = p - b
    if pb < 0:
        pb = -pb
    cdef int pc = p - c
    if pc < 0:
        pc = -pc
    # 가장 가까운 후보 선택
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


# PNG 필터 타입에 따라 한 줄(스캔라인)을 복원한다(C 함수)
@cython.cfunc
cdef int _applyPngFilter(
    int filterType,
    uint8_t[:] rowData,
    uint8_t[:] prevRow,
    int bytesPerPixel,
    uint8_t[:] recon,
) noexcept nogil:
    # PNG는 각 스캔라인 맨 앞에 "필터 타입 1바이트"가 붙는다.
    # rowData는 "필터 적용된 원본 바이트들", recon은 "필터 해제 후 복원된 바이트들"이다.
    # prevRow는 한 줄 위의 복원된 바이트(없으면 길이 0)다.
    # 입력 길이 가져오기
    cdef Py_ssize_t length = rowData.shape[0]
    cdef Py_ssize_t i
    cdef int left, up, upLeft
    if filterType < 0 or filterType > 4:
        return -1
    for i in range(length):
        # 왼쪽/위/좌상단 값 계산
        left = recon[i - bytesPerPixel] if i >= bytesPerPixel else 0
        up = prevRow[i] if prevRow.shape[0] else 0
        upLeft = prevRow[i - bytesPerPixel] if (prevRow.shape[0] and i >= bytesPerPixel) else 0

        # 필터 타입에 따라 복원
        # 0(None): 그대로 복사
        # 1(Sub): 왼쪽 픽셀 값을 더함
        # 2(Up): 위쪽 픽셀 값을 더함
        # 3(Average): 왼쪽과 위쪽 평균을 더함
        # 4(Paeth): 왼쪽/위/좌상단 중 가장 가까운 예측값을 더함
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
            return -1
    return 0


# PNG 청크를 읽는다(Python 함수)
def _readChunk(stream) -> Tuple[bytes, bytes]:
    # PNG는 [length(4)][type(4)][data(length)][crc(4)] 구조의 청크가 반복된다.
    # length는 데이터 길이만 의미하며, type과 crc는 포함하지 않는다.
    # 길이 읽기
    lengthBytes = stream.read(4)
    if len(lengthBytes) == 0:
        return b"", b""
    if len(lengthBytes) != 4:
        raise ValueError("Unexpected EOF while reading chunk length")
    length = struct.unpack(">I", lengthBytes)[0]
    # chunkType은 ASCII 4바이트(예: IHDR, IDAT, IEND)
    # 청크 타입 읽기
    chunkType = stream.read(4)
    if len(chunkType) != 4:
        raise ValueError("Unexpected EOF while reading chunk type")
    # 데이터 읽기
    data = stream.read(length)
    if len(data) != length:
        raise ValueError("Unexpected EOF while reading chunk data")
    # CRC 읽기 및 검증
    crc = stream.read(4)
    if len(crc) != 4:
        raise ValueError("Unexpected EOF while reading chunk CRC")
    expectedCrc = zlib.crc32(chunkType)
    expectedCrc = zlib.crc32(data, expectedCrc) & 0xFFFFFFFF
    actualCrc = struct.unpack(">I", crc)[0]
    if actualCrc != expectedCrc:
        raise ValueError("Corrupted PNG chunk detected")
    return chunkType, data


# PNG 스트림에서 이미지 정보를 로드한다(C 함수)
@cython.cfunc
cdef tuple _loadPng(object stream):
    # PNG 열기 과정 요약:
    # 1) 시그니처 검사(파일이 PNG인지 확인)
    # 2) IHDR에서 폭/높이/색상정보 파악
    # 3) IDAT를 모두 모아 zlib로 압축 해제
    # 4) 스캔라인별 필터 해제 후 RGB(A) 픽셀 버퍼로 복원
    # 시그니처 확인
    signature = stream.read(8)
    if signature != PNG_SIGNATURE:
        raise ValueError("Unsupported PNG signature")

    # IHDR에서 읽을 값 초기화(초기값 -1은 미설정 의미)
    cdef int width = -1
    cdef int height = -1
    cdef int bitDepth = -1
    cdef int colorType = -1
    cdef int compression = -1
    cdef int filterMethod = -1
    cdef int interlace = -1
    # IDAT 데이터 목록(압축된 이미지 본문)
    idatChunks: List[bytes] = []
    # 원본 청크 구조 기록
    chunk_records = []

    # 청크를 순서대로 읽는다(IHDR/IDAT/IEND 등)
    while True:
        chunkType, data = _readChunk(stream)
        if chunkType == b"":
            break
        if chunkType == b"IHDR":
            # IHDR 포맷: width, height, bitDepth, colorType, compression, filterMethod, interlace
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
            chunk_records.append((chunkType, data, len(data)))

        if chunkType == b"IEND":
            break

    # 필수 정보 확인
    if -1 in (width, height, bitDepth, colorType, compression, filterMethod, interlace):
        raise ValueError("Incomplete PNG header information")
    if bitDepth != 8:
        raise ValueError("Only 8-bit PNG images are supported")
    if colorType not in (2, 6):
        raise ValueError("Only RGB/RGBA PNG images are supported")
    if compression != 0 or filterMethod != 0 or interlace != 0:
        raise ValueError("Unsupported PNG configuration (compression/filter/interlace)")

    # IDAT를 합쳐 압축 해제
    # PNG의 이미지 데이터는 zlib(Deflate)로 압축되어 있으며 여러 IDAT로 분할될 수 있다.
    rawImage = zlib.decompress(b"".join(idatChunks))
    cdef int bytesPerPixel = 3 if colorType == 2 else 4
    cdef int rowLength = width * bytesPerPixel
    cdef int expected = height * (rowLength + 1)
    if len(rawImage) != expected:
        raise ValueError("Malformed PNG image data")

    # 픽셀/알파 버퍼 생성
    # 내부 표현은 항상 RGB 3바이트이며, 알파는 별도 버퍼로 유지한다.
    pixels = bytearray(width * height * 3)
    alpha = bytearray(width * height) if bytesPerPixel == 4 else None
    filter_types = bytearray(height)
    prevRow = bytearray(rowLength)
    # 메모리뷰로 빠르게 접근
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
        # 각 스캔라인 맨 앞 1바이트는 필터 타입
        # 필터 타입 읽기
        filterType = rawImage[offset]
        offset += 1
        filter_types[y] = filterType
        # 현재 줄 데이터 가져오기
        rowBytes = bytearray(rawImage[offset : offset + rowLength])
        offset += rowLength
        row_view = rowBytes
        recon = bytearray(rowLength)
        recon_view = recon
        # 필터 해제: 이전 줄(prevRow)과 현재 줄(rowBytes)을 사용해 복원
        if _applyPngFilter(filterType, row_view, prev_view, bytesPerPixel, recon_view) != 0:
            raise ValueError(f"Unsupported PNG filter: {filterType}")
        # RGB/알파로 분리 저장(필요 시 alpha 버퍼에 알파값 저장)
        for x in range(width):
            srcIndex = x * bytesPerPixel
            destIndex = (y * width + x) * 3
            pix_view[destIndex] = recon_view[srcIndex]
            pix_view[destIndex + 1] = recon_view[srcIndex + 1]
            pix_view[destIndex + 2] = recon_view[srcIndex + 2]
            if alpha is not None:
                alpha[y * width + x] = recon_view[srcIndex + 3]
        # 다음 줄을 위해 이전 줄 갱신(필터 해제에 사용)
        prevRow = recon
        prev_view = recon_view
    return width, height, pixels, bytesPerPixel, alpha, chunk_records, None, filter_types


# PNG 청크를 만들기 위한 바이너리 데이터 생성
def _makeChunk(chunkType: bytes, data: bytes) -> bytes:
    # length와 crc를 포함한 PNG 청크 바이트를 구성한다.
    # CRC는 chunkType+data에 대해 계산한다.
    length = struct.pack(">I", len(data))
    crcValue = zlib.crc32(chunkType)
    crcValue = zlib.crc32(data, crcValue) & 0xFFFFFFFF
    crc = struct.pack(">I", crcValue)
    return length + chunkType + data + crc


# PNG 스캔라인 바이트를 만든다(Cython 최적화)
@cython.boundscheck(False)
@cython.wraparound(False)
cdef void _write_png_bytes(
    int width,
    int height,
    uint8_t[:] pixels,
    object alpha_obj,
    bytearray raw,
    object filter_types,
):
    # PNG 저장 단계:
    # 1) 스캔라인 구성(RGB/RGBA)
    # 2) 필터 타입 적용(보존된 타입이 있으면 재사용)
    cdef bint has_alpha = alpha_obj is not None
    cdef bint has_filters = filter_types is not None
    cdef uint8_t[:] alpha_view
    cdef uint8_t[:] filter_view
    cdef int bytes_per_pixel = 4 if has_alpha else 3
    cdef int row_length = width * bytes_per_pixel
    cdef bytearray row_buf = bytearray(row_length)
    cdef bytearray prev_row = bytearray(row_length)
    cdef bytearray filt_buf = bytearray(row_length)
    cdef uint8_t[:] row_view = row_buf
    cdef uint8_t[:] prev_view = prev_row
    cdef uint8_t[:] filt_view = filt_buf
    cdef int y, x, start, idx, dest
    cdef int i
    cdef int filterType
    cdef int left, up, upLeft
    # raw는 재사용하므로 먼저 비움
    raw.clear()
    if has_alpha:
        alpha_view = alpha_obj
    if has_filters:
        if len(filter_types) != height:
            raise ValueError("PNG filter count does not match image height")
        filter_view = filter_types
    for y in range(height):
        # 스캔라인 원본 구성
        start = y * width * 3
        if has_alpha:
            for x in range(width):
                idx = start + x * 3
                dest = x * 4
                row_view[dest] = pixels[idx]
                row_view[dest + 1] = pixels[idx + 1]
                row_view[dest + 2] = pixels[idx + 2]
                row_view[dest + 3] = alpha_view[y * width + x]
        else:
            for x in range(width):
                idx = start + x * 3
                dest = x * 3
                row_view[dest] = pixels[idx]
                row_view[dest + 1] = pixels[idx + 1]
                row_view[dest + 2] = pixels[idx + 2]

        if has_filters:
            filterType = filter_view[y]
        else:
            filterType = 0
        if filterType > 4:
            raise ValueError(f"Unsupported PNG filter: {filterType}")
        raw.append(filterType)
        if filterType == 0:
            raw.extend(row_buf)
        else:
            for i in range(row_length):
                left = row_view[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                up = prev_view[i]
                upLeft = prev_view[i - bytes_per_pixel] if i >= bytes_per_pixel else 0
                if filterType == 1:
                    filt_view[i] = (row_view[i] - left) & 0xFF
                elif filterType == 2:
                    filt_view[i] = (row_view[i] - up) & 0xFF
                elif filterType == 3:
                    filt_view[i] = (row_view[i] - ((left + up) >> 1)) & 0xFF
                else:
                    filt_view[i] = (row_view[i] - _paethPredictor(left, up, upLeft)) & 0xFF
            raw.extend(filt_buf)
        prev_row[:] = row_buf


# PNG 파일로 저장한다.
def _writePng(
    path,
    int width,
    int height,
    object pixels,
    object alpha=None,
    object filter_types=None,
) -> None:
    # PNG 저장 과정 요약:
    # 1) IHDR 생성(이미지 메타정보)
    # 2) 픽셀을 스캔라인 구조로 변환(필터 적용)
    # 3) zlib 압축 후 IDAT 생성
    # 4) PNG 시그니처 + IHDR + IDAT + IEND 순으로 기록
    expected = width * height * 3
    if len(pixels) != expected:
        raise ValueError("Pixel data length does not match image dimensions")
    if alpha is not None and len(alpha) != width * height:
        raise ValueError("Alpha channel length does not match image dimensions")
    # IHDR: 폭/높이/비트깊이(8)/색상형식(2=RGB,6=RGBA)/압축/필터/인터레이스
    ihdr = struct.pack(">IIBBBBB", width, height, 8, 6 if alpha is not None else 2, 0, 0, 0)
    raw = bytearray()
    # bytearray로 변환해 Cython 함수에 전달
    if isinstance(pixels, bytearray):
        pix_buf = pixels
    else:
        pix_buf = bytearray(pixels)
    _write_png_bytes(width, height, pix_buf, alpha, raw, filter_types)
    # 스캔라인 전체를 zlib(Deflate)로 압축
    compressed = zlib.compress(bytes(raw))
    with open(path, "wb") as output:
        output.write(PNG_SIGNATURE)
        output.write(_makeChunk(b"IHDR", ihdr))
        output.write(_makeChunk(b"IDAT", compressed))
        output.write(_makeChunk(b"IEND", b""))


# 압축된 IDAT 데이터를 기존 청크 길이에 맞춰 분할한다.
def _split_idat_payload(bytes data, list lengths):
    # 기존 PNG의 IDAT 청크 크기들을 유지하고 싶을 때
    # 압축 데이터(data)를 해당 길이로 나누어 여러 IDAT로 분할한다.
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
            # 마지막 청크는 남은 모든 데이터
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


# 기존 청크 구조를 유지하면서 PNG를 저장한다.
def _writePngWithChunks(
    path,
    int width,
    int height,
    object pixels,
    object alpha,
    object chunks,
    object filter_types=None,
):
    # PNG 저장 시 기존 청크 구성을 유지하려는 경우:
    # - IDAT를 원래 길이로 분할
    # - IDAT 외 청크는 원본 순서/내용 유지
    # - 결과적으로 메타데이터/부가 청크가 보존됨
    if not chunks:
        _writePng(path, width, height, pixels, alpha, filter_types)
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
    _write_png_bytes(width, height, pix_buf, alpha, raw, filter_types)
    # 스캔라인을 압축해 IDAT용 데이터 생성
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
                    # 분할된 IDAT를 순서대로 기록
                    # 분할된 IDAT를 모두 기록
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
            # IDAT가 없던 경우 새로 기록
            # IDAT가 없던 경우 새로 기록
            for part in parts:
                output.write(len(part).to_bytes(4, "big"))
                output.write(b"IDAT")
                output.write(part)
                crc = zlib.crc32(b"IDAT")
                crc = zlib.crc32(part, crc) & 0xFFFFFFFF
                output.write(struct.pack(">I", crc))


# BMP 스트림에서 이미지 정보를 로드한다(C 함수)
@cython.cfunc
cdef tuple _loadBmp(object stream):
    # BMP 파일 헤더(14바이트) 읽기
    header = stream.read(14)
    if len(header) != 14 or header[:2] != b"BM":
        raise ValueError("Unsupported BMP header")
    # 파일 크기와 픽셀 오프셋 읽기
    fileSize, _, _, pixelOffset = struct.unpack("<IHHI", header[2:])
    # DIB 헤더 크기 읽기
    dibHeaderSizeBytes = stream.read(4)
    if len(dibHeaderSizeBytes) != 4:
        raise ValueError("Corrupted BMP DIB header")
    dibHeaderSize = struct.unpack("<I", dibHeaderSizeBytes)[0]
    if dibHeaderSize != 40:
        raise ValueError("Only BITMAPINFOHEADER BMP files are supported")
    # DIB 헤더 나머지 읽기
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
    # 높이가 음수면 위에서 아래로 저장
    absHeight = abs(height)
    rowStride = ((width * 3 + 3) // 4) * 4
    pixels = bytearray(width * absHeight * 3)
    # 픽셀 데이터 위치로 이동
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
        # 한 줄 읽기
        rowData = stream.read(rowStride)
        if len(rowData) != rowStride:
            raise ValueError("Incomplete BMP pixel data")
        # BMP는 아래에서 위로 저장됨
        targetRow = absHeight - 1 - row if height > 0 else row
        baseIndex = targetRow * width * 3
        for x in range(width):
            idx = baseIndex + x * 3
            # BMP는 BGR 순서
            pix_view[idx] = rowData[x * 3 + 2] & 0xFF
            pix_view[idx + 1] = rowData[x * 3 + 1] & 0xFF
            pix_view[idx + 2] = rowData[x * 3] & 0xFF
    # 일부 메타데이터 보관
    metadata = {
        "xppm": xPpm,
        "yppm": yPpm,
        "clrUsed": clrUsed,
        "clrImportant": clrImportant,
    }
    return width, absHeight, pixels, 3, None, None, metadata, None


# BMP 파일로 저장한다.
def _writeBmp(path, int width, int height, object pixels, object meta=None) -> None:
    rowStride = ((width * 3 + 3) // 4) * 4
    pixelArraySize = rowStride * height
    fileSize = 14 + 40 + pixelArraySize
    # 메타데이터 기본값 처리
    if meta is not None:
        xppm = int(meta.get("xppm", 2835))
        yppm = int(meta.get("yppm", 2835))
        clrUsed = int(meta.get("clrUsed", 0))
        clrImportant = int(meta.get("clrImportant", 0))
    else:
        xppm = yppm = 2835
        clrUsed = clrImportant = 0
    # 픽셀 버퍼 준비
    if isinstance(pixels, bytearray):
        pix_buf = pixels
    else:
        pix_buf = bytearray(pixels)
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
            )
        )
        rowPad = rowStride - width * 3
        padBytes = b"\x00" * rowPad
        # BMP는 아래에서 위로 저장
        for y in range(height - 1, -1, -1):
            start = y * width * 3
            for x in range(width):
                idx = start + x * 3
                r = pix_buf[idx]
                g = pix_buf[idx + 1]
                b = pix_buf[idx + 2]
                # BMP는 BGR 순서
                output.write(bytes((b & 0xFF, g & 0xFF, r & 0xFF)))
            if rowPad:
                output.write(padBytes)


# SimpleImage 클래스(Cython 구현)
cdef class SimpleImage:
    """Minimal RGB image helper implemented in Cython."""

    # 공개 속성 정의
    cdef public int width
    cdef public int height
    cdef public bytearray pixels
    cdef public object _alpha
    cdef public object _png_chunks
    cdef public object _png_filters
    cdef public object _bmp_header

    def __cinit__(
        self,
        int width,
        int height,
        object pixels,
        object alpha=None,
        object png_chunks=None,
        object bmp_header=None,
        object png_filters=None,
    ):
        # 픽셀 데이터 길이 검증
        cdef Py_ssize_t expected = width * height * 3
        if len(pixels) != expected:
            raise ValueError("Pixel data length does not match image dimensions")
        self.width = width
        self.height = height
        # 픽셀 버퍼 복사
        if isinstance(pixels, bytearray):
            self.pixels = bytearray(pixels)
        else:
            self.pixels = bytearray(pixels)
        # 알파 채널 처리
        if alpha is not None:
            if len(alpha) != width * height:
                raise ValueError("Alpha channel length does not match image dimensions")
            if isinstance(alpha, bytearray):
                self._alpha = bytearray(alpha)
            else:
                self._alpha = bytearray(alpha)
        else:
            self._alpha = None
        # PNG 청크 정보 복사
        if png_chunks is not None:
            self._png_chunks = list(png_chunks)
        else:
            self._png_chunks = None
        if png_filters is not None:
            if len(png_filters) != height:
                raise ValueError("PNG filter count does not match image height")
            self._png_filters = bytearray(png_filters)
        else:
            self._png_filters = None
        # BMP 헤더 정보 복사
        if bmp_header is not None:
            self._bmp_header = dict(bmp_header)
        else:
            self._bmp_header = None

    @property
    def size(self) -> Tuple[int, int]:
        # (너비, 높이) 튜플 반환
        return self.width, self.height

    @staticmethod
    def _streamToImage(stream):
        # 시그니처로 포맷 판별
        signature = stream.read(8)
        stream.seek(0)
        if signature.startswith(PNG_SIGNATURE):
            return _loadPng(stream)
        if signature[:2] == b"BM":
            return _loadBmp(stream)
        raise ValueError("Unsupported image format")

    @classmethod
    def open(cls, source: ImageInput) -> SimpleImage:
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

    def _copy(self) -> SimpleImage:
        # 내부 버퍼를 복사해서 새 객체 생성
        cdef object alpha_copy
        cdef object chunk_copy
        cdef object filter_copy
        if self._alpha is None:
            alpha_copy = None
        else:
            alpha_copy = self._alpha[:]
        if self._png_chunks is None:
            chunk_copy = None
        else:
            chunk_copy = self._png_chunks[:]
        if self._png_filters is None:
            filter_copy = None
        else:
            filter_copy = self._png_filters[:]
        if self._bmp_header is None:
            bmp_copy = None
        else:
            bmp_copy = dict(self._bmp_header)
        return SimpleImage(
            self.width,
            self.height,
            self.pixels[:],
            alpha_copy,
            chunk_copy,
            bmp_copy,
            filter_copy,
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
            _writePng(path, self.width, self.height, self.pixels, self._alpha, self._png_filters)
