# App Password

선택한 Windows 실행 파일을 마스터 비밀번호 확인 후 실행하는 로컬 전용 Tauri MVP입니다.

## 현재 제공하는 기능

- Argon2id 기반 마스터 비밀번호 설정 및 변경
- Windows `.exe` 선택과 보호 목록 관리
- 앱별 보호 활성화/비활성화
- 인증 성공 후 1~60분 임시 허용
- 5회 실패 시 30초 입력 제한
- 모든 임시 허용 즉시 해제
- 시스템 트레이 아이콘

## 개발 실행

```powershell
npm install
npm run tauri dev
```

## 테스트와 빌드

```powershell
npm run build
cargo test --manifest-path src-tauri/Cargo.toml
npm run tauri build
```

설정은 Windows의 `%APPDATA%\\com.local.apppassword\\config.json`에 저장됩니다. 비밀번호 원문은 저장하지 않습니다.
