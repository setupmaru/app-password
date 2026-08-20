# App Password

선택한 Windows 앱의 직접 실행을 마스터 비밀번호로 보호하는 Tauri 앱입니다.

## 현재 제공하는 기능

- Argon2id 기반 마스터 비밀번호 설정 및 변경
- Windows에 설치된 데스크톱 앱 자동 탐색 및 30초 간격 갱신
- 앱별 토글 방식의 보호 활성화/비활성화
- 자동 시작 Windows 서비스가 보호 앱의 직접 실행을 감지하고 미인증 실행 종료
- 직접 실행이 차단되면 App Password를 열어 인증 후 정상 실행
- 인증 성공 후 1~60분 임시 허용
- 5회 실패 시 30초 입력 제한
- 모든 임시 허용 즉시 해제
- 시스템 트레이 아이콘

Windows 서비스는 100ms 간격으로 새 프로세스를 확인합니다. 커널 드라이버 방식이 아니므로 프로세스가 생성된 직후 종료되며, 아주 짧은 실행 구간까지 완전히 없애지는 못합니다.

## 개발 실행

```powershell
npm install
npm run tauri dev
```

## 테스트와 빌드

```powershell
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
New-Item -ItemType Directory -Force src-tauri/binaries | Out-Null
New-Item -ItemType File -Force src-tauri/binaries/app-password-guard-x86_64-pc-windows-msvc.exe | Out-Null
cargo build --manifest-path src-tauri/Cargo.toml --release --bin app-password-guard
Copy-Item src-tauri/target/release/app-password-guard.exe src-tauri/binaries/app-password-guard-x86_64-pc-windows-msvc.exe
npm run tauri build -- --bundles nsis
```

앱 설정은 `%APPDATA%\\com.local.apppassword\\config.json`, 서비스 동기화 상태는 `%PROGRAMDATA%\\AppPassword`에 저장됩니다. 비밀번호 원문은 저장하지 않습니다. 설치 프로그램은 관리자 권한으로 실행되며 `AppPasswordGuard` 서비스를 자동 시작으로 등록합니다.
