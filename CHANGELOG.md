### Test Environment
All tests were conducted in the following environment:
- CPU: Ryzen 7 5700G
- RAM: 32GB DDR4
- OS: Ubuntu 24.04 LTS
- Test images: PNG (2000×1500)

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

## [0.2.1]

### Added
- Github Actions workflow added.

## [0.2.2]

### Added
- Meta data reservation added (PNG, BMP)
- Filter data reservation added (PNG)

## [0.3.0]
- Added binding between injected data and the target image, neutralizing extract-and-reinject attacks
- Minor performance overhead

### Changed
- Added image hashing and verification key injection
- Updated payload structure to include payload + public key + image hash

## [1.0.0]

### Changed
- Switched from direct RSA public/private key usage to CA-backed certificates for verification input.
- Channel selection is now based on a public-key-derived hash instead of image pixel values to strengthen integrity guarantees.
  This incurs significant performance overhead. The legacy pixel-based path remains fast but cannot guarantee that
  the signing-time hash placeholder equals the validation-time hash placeholder.

### Performance
- New baseline: Signing time **13.035883s** / Validating time **12.009071s**.

### Upcoming
- Channel selection algorithm improvements (including a legacy-safe integrity path or alternative algorithm).
- Cython module introduction for the heaviest hotspots.


## [1.1.0]

### Changed
- Channel selection now uses raw key material rather than a derived hash.
  - This simplifies the pipeline and reduces cryptographic overhead without weakening randomness.
- Legacy channel embedding has been changed from ±1 value shifts to direct
  target-bit replacement (...XXX0 / ...XXX1), guaranteeing repeatable integrity.
- Introduced a `keyless` flag in `signImage()` and `validateImage()` to explicitly
  choose pixel-based channel selection or key-based selection (default).
- `validateImage()` to return a failure report instead of raising errors.
### Performance
Signing time **2.575809s** / Validating time **1.531062s**.


## [1.1.1]

### Changed
- Update key-based channel selection to use image-sized repeated key array

### Performance
- Signing time **2.134768s** (approx. 17% improved)
- Validating time **1.094935s** (approx. 28% improved)
