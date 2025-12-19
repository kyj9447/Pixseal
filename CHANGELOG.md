## [0.1.2]

### Added
- **Byte-stream API support** – Core entry points such as `SimpleImage.open`, `signImage`, and `validateImage` now accept either file paths or raw PNG/BMP byte streams.
- **TailCheck in validation report** – `validateImage` now exposes `tailCheckResult` in the returned `validationReport`, comparing the complete ciphertext with its truncated counterpart so you can detect tampering even when decryption isn’t possible.

## [0.1.3]

### Fixed
- **Decrypt skip messaging** – Fixed the condition that shows `decryptSkipMessage`, ensuring it only surfaces when plaintext decryption was actually skipped.

## [0.1.4]

### Fixed
- **Performance Optimization** - Performance optimization for readHiddenBit() function
- before : Signing time: 6.418772 seconds / **Validating time: 3.330089 seconds**
- after : Signing time: 6.431127 seconds / **Validating time: 2.615719 seconds** (approx. 20% improved)

## [0.1.5]

### Fixed
- **Performance Optimization** - Performance optimization for addHiddenBit() function
- before : **Signing time: 6.395789 seconds** / Validating time: 2.561549 seconds
- after : **Signing time: 4.637004 seconds** / Validating time: 2.557634 seconds (approx. 28% improved)

## [0.1.6]

### Fixed
- **Performance Optimization** – Further optimization of `addHiddenBit()` function
- Benchmarked against **v0.1.5**
- Signing time: **4.637004s → 4.064458s** (~12.3% improvement)

## [0.2.0]

### Added
- **Performance Optimization** - Cython backend for SimpleImage with automatic fallback to pure Python when the extension is unavailable.
- before : Signing time: 4.032087 seconds / Validating time: 2.624742 seconds (pure Python)
- after : **Signing time: 1.432151 seconds** / **Validating time: 0.856585 seconds** (approx. 66% total time reduction when using Cython backend)