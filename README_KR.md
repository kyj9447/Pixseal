<p align="center">
<img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/logo/Pixseal.png" width="200px"/>
</p>

[English README](https://github.com/kyj9447/Pixseal/blob/main/README.md)

# Pixseal (한국어)
### 당신이 발행한 것과, 발행하지 않은 것을 증명합니다.

Pixseal은 이미지가 **서명 이후 변경되었는지**를 탐지하는
Python 기반 **무결성/진본성 검증 도구**입니다.

Pixseal은 이미지 내부에 **암호학적으로 검증 가능한 무결성 씰**을
보이지 않게 삽입합니다. 검증 시점에 **편집, 필터, 크롭, 리사이즈,
재인코딩** 등 어떤 변경이라도 있으면 검증이 **실패**합니다.

Pixseal은 RSA 개인키로 payload와 이미지 해시를 서명하며,
검증은 대응하는 RSA 공개키 또는 이를 포함한 X.509 인증서를 사용합니다.

Pixseal은 시각적 워터마크가 아니라,
**변조 감지**를 위한 무결성 씰입니다.

Pixseal은 변조에 대한 강인성보다,
정확한 변조 감지(민감도)에 우선순위를 둡니다.

- GitHub: https://github.com/kyj9447/Pixseal
- Changelog: https://github.com/kyj9447/Pixseal/blob/main/CHANGELOG.md

## 주요 기능
- **이미지 무결성 검증**
  - 이미지가 원본 그대로임을 암호학적으로 증명
  - 단일 픽셀 변경까지 결정적으로 검출

- **변조 탐지**
  - 편집, 색상/필터, 크롭/리사이즈, 재인코딩, 픽셀 변경 등 감지

- **보이지 않는 무결성 씰**
  - 시각적 워터마크 없이 검증 데이터 삽입
  - 원본 시각 품질 유지

- **RSA 서명 + 인증서 지원**
  - RSA 개인키로 서명
  - RSA 공개키 또는 X.509 인증서로 검증

- **유연한 키 입력**
  - 키/인증서 객체, PEM/DER 바이트, 파일 경로 지원

- **완전 로컬/오프라인**
  - 외부 서버/네트워크 의존 없음
  - Cython 가속 + Python fallback

- **무손실 포맷 지원**
  - PNG, BMP(24-bit) 지원
  - JPEG/WebP 등 손실 포맷은 무결성 보장 성격에 맞지 않아 제외

## 설치

```bash
pip install Pixseal
# 로컬 개발
pip install -e ./pip_package
```

Python 3.8+ 필요. PyPI 배포용 wheel에는 Cython 확장이 포함되어,
`pip install Pixseal` 시 자동으로 적합한 빌드를 선택합니다.

### Cython 확장 빌드(소스 클론 시)

```bash
git clone https://github.com/kyj9447/Pixseal.git
cd Pixseal
python3 -m pip install -r requirements.txt
./compile_extension.sh
```

빌드가 안 되면 자동으로 Python fallback이 사용됩니다.
이 경우 순수 Python으로 동작하며 성능이 느릴 수 있습니다.

## 빠른 시작

### 이미지 서명

```python
from Pixseal import signImage

signed = signImage(
    imageInput="assets/original.png",
    payload="AutoTest123!",
    private_key="assets/CA/pixseal-dev-final.key",
    keyless=False,  # 기본: 키 기반 채널 선택
)
signed.save("assets/signed_original.png")
```

payload가 이미지 크기보다 짧아도 끝까지 반복됩니다.

### 이미지 검증

```python
from Pixseal import validateImage

report = validateImage(
    imageInput="assets/signed_original.png",
    publicKey="assets/CA/pixseal-dev-final.crt",
    keyless=False,  # 기본: 키 기반 채널 선택
)

print(report["verdict"])
```

## 키/인증서 입력 형식

- `signImage(..., private_key=...)` 지원:
  - `RSAPrivateKey`
  - PEM/DER bytes (`bytes`, `bytearray`, `memoryview`)
  - 파일 경로 (`str`, `Path`)

- `validateImage(..., publicKey=...)` 지원:
  - `RSAPublicKey`
  - `x509.Certificate`
  - PEM/DER bytes (`bytes`, `bytearray`, `memoryview`)
  - 파일 경로 (`str`, `Path`)

인증서가 주어지면 내부 RSA 공개키를 추출해 검증합니다.
※ 체인 검증은 포함하지 않습니다.

## 채널 선택 모드

1개 픽셀의 3개 채널 중, 어느 채널(R,G,B 중 1개)을 기준으로 읽기,쓰기를 할지 결정하는 기준입니다.
`signImage()`와 `validateImage()`는 `keyless : bool` 플래그를 받습니다.

- `keyless=False` : 공개키 바이트 기반 채널 선택 (기본값)
- `keyless=True`: 픽셀 기반 채널 선택

Keyless 모드는 추출 가능성에서 차이가 있습니다.

1. **키 기반 서명 이미지**
  - 키가 없으면 Pixseal 적용 자체를 인지할 수 없음 -> 추출 불가 + 검증 실패.
2. **Keyless 서명 이미지**
  - 키가 없어도 추출 자체는 가능 -> 검증 실패.

## Payload 구조

```json
{
  "payload": "AutoTest123!",
  "payloadSig": "BASE64_SIGNATURE",
  "imageHash": "SHA256_HEX",
  "imageHashSig": "BASE64_SIGNATURE"
}
```

- `payload`: 사용자 입력 텍스트
- `payloadSig`: payload의 RSA 서명(Base64)
- `imageHash`: 서명된 이미지 버퍼의 SHA256 해시(hex)
- `imageHashSig`: imageHash의 RSA 서명(Base64)

## 삽입 시퀀스 구조

```
<START-VALIDATION signature>
<payload JSON>
<payload JSON>
...(이미지 끝까지 반복)...
<payload JSON>   # truncated tail
<END-VALIDATION signature>
```

추출 시 Pixseal은 중복 라인을 제거(dedup)하여 보통 다음 4줄을 얻습니다.

```
<START-VALIDATION signature>
<payload JSON>
<payload JSON>   # truncated tail
<END-VALIDATION signature>
```

<sub>아주 낮은 확률로 truncated tail이 없을 수 있으며, 이때는 3줄만 반환됩니다.</sub>

## 검증 출력

Validation Report

- `lengthCheck`
  - `length`: dedup 결과 길이
  - `result`: 3 또는 4일 때 True
- `tailCheck`
  - `full`: 전체 payload 일부
  - `tail`: 잘린 payload 일부
  - `result`: full/tail 일치 여부
- `startVerify`, `endtVerify`
- `payloadVerify`
- `imageHashVerify`
- `imageHashCompareCheck`
  - `extractedHash`, `computedHash`, `result`
- `verdict`

Validation Report

- `lengthCheck`
  - `length` : 중복 제거된 배열 길이
  - `result` : 3 또는 4일 때 True
- `tailCheck`
  - `full` : 전체 payload 일부
  - `tail` : 잘린 payload 일부
  - `result` : full/tail 일치 여부
- `startVerify` : (배열 첫번째 Signiture + "START-VALIDATION") 의 검증 결과
- `endtVerify` : (배열 마지막 Signiture + "END-VALIDATION") 의 검증 결과 
- `payloadVerify` : (payloadSig + payload) 의 검증 결과 
- `imageHashVerify` : (imageHashSig + imageHash) 의 검증 결과
- `imageHashCompareCheck`
  - `extractedHash` : 추출된 payload의 imageHashSig 값
  - `computedHash` : 추출 단계에서 직접 계산된 이미지의 hash 값
  - `result` : extractedHash와 computedHash의 일치 여부
- `verdict` : 모든 검사 통과 종합 (하나라도 False면 실패 판정)

### 실패 출력

파싱/추출 실패 시 최소 보고서를 반환합니다.

```
{
  "status": "Failed",
  "error": "Reason string",
  "verdict": false
}
```
error 종류
- "Deduplication failed" : 줄바꿈 문자(\n) 등이 깨져서 중복제거 작업이 완전 실패한 경우
- "JSON extraction from payload failed" : 추출된 JSON 형식의 문자열에서 객체 형태 추출을 실패한 경우
- "Essenstial values in JSON are missing" : 추출된 값 중 검증에 필요한 값 중 일부, 혹은 전체가 누락된 경우

## CLI 데모 스크립트

`python testRun.py` 실행 시 메뉴형 데모를 제공합니다.

현재 백엔드 선택 프롬프트는 생략되어 있으며,
`PIXSEAL_SIMPLEIMAGE_BACKEND`가 설정되어 있으면 그 값을 사용하고,
없으면 기본 `auto` 동작(Cython 우선, Python fallback)을 사용합니다.

메뉴:

1. **1**: 이미지 서명 (`assets/original.png` → `assets/signed_original.png`)
2. **2**: 서명 이미지 검증
3. **3**: 서명 이미지 검증 실패 테스트(`assets/currupted_signed_original.png`)
4. **4**: 성능 벤치마크(서명+검증)
5. **5**: 성능 벤치마크(서명+검증) + Keyless 모드
6. **6**: 메모리(bytes) API 테스트
7. **7**: LineProfiler 데모 (성능 프로파일링)
8. **8**: 검증 멀티패스 테스트 ( placeholder 주입 -> payload 주입 -> placeholder 주입 반복시 결함 누적 여부 확인 )

옵션 **7**은 `line_profiler`가 설치되어 있어야 하며,
`kernprof -l testRun.py`로 실행해야 합니다.

## API 레퍼런스

| 함수 | 설명 |
| --- | --- |
| `signImage(imageInput, payload, private_key, keyless=False)` | PNG/BMP를 로드해 payload+sentinel을 서명하고 삽입. `SimpleImage` 반환. |
| `validateImage(imageInput, publicKey, keyless=False)` | 숨겨진 비트 스트림을 읽어 검증 보고서 반환. |

## 예시

| 원본 | 서명본 (`AutoTest123!`) |
| --- | --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/original.png" width="400px"/> | <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/signed_original.png" width="400px"/> |

검증 출력(성공):

```
Validation Report

{'lengthCheck': {'length': 4, 'result': True},
 'tailCheck': {'full': '{"payload":"AutoTest...lgu9lUM+s7OHUZywYqYYOYIFVTWCmq...',
               'tail': '{"payload":"AutoTest...lgu9lUM+s7',
               'result': True},
 'startVerify': True,
 'endtVerify': True,
 'payloadVerify': True,
 'imageHashVerify': True,
 'imageHashCompareCheck': {'extractedHash': '2129e43456029f39b20bbe96340dce6827c0ad2288107cb92c0b92136fec48d6',
                           'computedHash': '2129e43456029f39b20bbe96340dce6827c0ad2288107cb92c0b92136fec48d6',
                           'result': True},
 'verdict': True}
```

| 서명 후 변조됨 |
| --- |
| <img src="https://raw.githubusercontent.com/kyj9447/Pixseal/main/assets/currupted_signed_original.png" width="400px"/> |

검증 출력(실패):

```
Validation Report

{'lengthCheck': {'length': 31, 'result': False},
 'tailCheck': {'result': 'Not Required'},
 'startVerify': True,
 'endtVerify': True,
 'payloadVerify': True,
 'imageHashVerify': True,
 'imageHashCompareCheck': {'extractedHash': '68d500c751dfa298d55dfc1cd2ab5c9f43ec139f02f6a11027211c4d144c2870',
                           'computedHash': '43fd2108f5aa16045f4b64d70a0ce05991043cba6878f66d82abd3e7edb9d51e',
                           'result': False},
 'verdict': False}
```
