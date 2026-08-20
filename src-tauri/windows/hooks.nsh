!macro NSIS_HOOK_PREINSTALL
  DetailPrint "기존 App Password 보호 서비스를 정리하는 중..."
  nsExec::ExecToLog 'sc.exe stop AppPasswordGuard'
  Sleep 600
  nsExec::ExecToLog 'taskkill.exe /F /IM app-password-guard.exe'
  nsExec::ExecToLog 'sc.exe delete AppPasswordGuard'
  Sleep 1000
  Delete "$INSTDIR\app-password-guard.exe"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "App Password 보호 서비스를 설치하는 중..."
  ReadEnvStr $0 "PROGRAMDATA"
  CreateDirectory "$0\AppPassword"
  CreateDirectory "$0\AppPassword\events"
  nsExec::ExecToLog 'icacls.exe "$0\AppPassword" /grant *S-1-5-32-545:(OI)(CI)M /T /C'
  nsExec::ExecToStack '$\"$INSTDIR\app-password-guard.exe$\" --install'
  Pop $1
  Pop $2
  ${If} $1 != 0
    DetailPrint "App Password Guard 서비스 설치 실패: $2"
    MessageBox MB_ICONSTOP|MB_OK "Windows 보호 서비스를 설치하지 못했습니다.$\r$\n설치 프로그램을 관리자 권한으로 다시 실행해 주세요."
    Abort
  ${EndIf}
  nsExec::ExecToLog 'sc.exe failure AppPasswordGuard reset= 86400 actions= restart/1000/restart/3000/restart/10000'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "AppPassword" '$\"$INSTDIR\${MAINBINARYNAME}.exe$\" --background'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "AppPassword"
  DetailPrint "App Password 보호 서비스를 제거하는 중..."
  nsExec::ExecToLog 'sc.exe stop AppPasswordGuard'
  Sleep 800
  nsExec::ExecToLog 'sc.exe delete AppPasswordGuard'
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  ReadEnvStr $0 "PROGRAMDATA"
  Delete "$0\AppPassword\heartbeat"
!macroend
