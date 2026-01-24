Maintainer Guide
================

이 문서는 릴리스를 담당하는 유지보수자만 참고하십시오. 일반 사용자 안내는
루트 `README.md`에 정리되어 있습니다.

## 1. GitHub Actions 자동 배포

현재 배포 워크플로는 수동 실행(`workflow_dispatch`)만 사용합니다.

사전 준비:

1. PyPI에서 API 토큰을 생성하고 저장합니다.
2. GitHub 저장소 **Settings → Secrets and variables → Actions**에
   `PYPI_API_TOKEN` 이름으로 토큰을 추가합니다.

워크플로 동작:

1. `cibuildwheel`이 Linux/Windows용 휠을 빌드합니다.
2. Ubuntu job이 SDist를 생성합니다.
3. `publish` job이 모든 아티팩트를 다운로드해 PyPI에 업로드합니다.

배포 절차(예: PyPI):

1. Actions 탭에서 **Publish to PyPI** 워크플로를 수동 실행합니다.
2. 로그에서 휠/SDist 빌드 및 업로드 성공 여부를 확인합니다.

테스트 배포는 **Publish to Test PyPI** 워크플로를 사용합니다.

## 2. 수동 배포 (필요 시)

CI에 접근할 수 없거나 임시로 핫픽스를 배포해야 할 때는 로컬에서 아래 명령을
사용합니다.

```bash
python3 -m pip install --upgrade pip
python3 -m pip install build twine
./publish.sh
```

`publish.sh`는 `python -m build`를 실행해 최신 wheel/sdist를 만든 뒤 `twine`으로
업로드합니다. PyPI 자격 증명은 환경 변수(`TWINE_USERNAME`, `TWINE_PASSWORD`) 또는
`~/.pypirc`로 공급하세요.

## 3. 빌드/확장 모듈

- Cython 확장은 `pyproject.toml`의 `ext-modules`에 등록되어 있으며,
  `cibuildwheel`이 wheel 빌드 시 자동으로 `.pyx`를 컴파일합니다.
- 로컬에서 확장 모듈을 빌드하려면 `./compile_extension.sh`를 사용합니다.

## 4. 테스트 스크립트

- `testRun.py`: CLI 데모 스크립트입니다. 현재 **백엔드 선택 프롬프트는 제거**되어 있으며,
  `PIXSEAL_SIMPLEIMAGE_BACKEND` 값(또는 기본 `auto`)을 그대로 사용합니다.
- `total_test.py`: 키/키리스, 메모리 라운드트립, 변조 검출 등 주요 경로를
  한 번에 검증하는 통합 테스트 스크립트입니다.

## 5. 보안

- `token.txt`와 같은 민감 정보는 절대 커밋하지 마십시오.
- PyPI API 토큰을 재발급했다면 GitHub Secrets도 함께 갱신해야 합니다.
