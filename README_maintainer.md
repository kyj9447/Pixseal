Maintainer Guide
================

이 문서는 릴리스를 담당하는 유지보수자만 참고하십시오. 일반 사용자 안내는
루트 `README.md`에 정리되어 있습니다.

## 1. GitHub Actions 자동 배포

`.github/workflows/publish.yml` 워크플로는 다음 조건에서 실행됩니다.

- 태그가 `v*` 패턴일 때 `git push --tags`가 발생
- 또는 Actions 탭에서 `workflow_dispatch`로 수동 실행

사전 준비:

1. PyPI에서 API 토큰을 생성하고 저장합니다.
2. GitHub 저장소 **Settings → Secrets and variables → Actions**에
   `PYPI_API_TOKEN` 이름으로 토큰을 추가합니다.

워크플로 동작:

1. `cibuildwheel`이 Linux/macOS/Windows용 휠을 각각 빌드합니다.
2. Ubuntu job이 SDist를 생성합니다.
3. `publish` job이 모든 아티팩트를 다운로드해 `twine upload`로 PyPI에 업로드합니다.

배포 절차:

```bash
git tag v0.2.0
git push origin v0.2.0
```

Actions 탭에서 워크플로 완료 상태와 로그를 확인하세요.

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

## 3. 보안

- `token.txt`와 같은 민감 정보는 절대 커밋하지 마십시오.
- PyPI API 토큰을 재발급했다면 GitHub Secrets도 함께 갱신해야 합니다.
