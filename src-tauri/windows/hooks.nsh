!macro NSIS_HOOK_PREINSTALL
  DetailPrint "기존 App Password 보호 서비스를 정리하는 중..."
  nsExec::ExecToLog 'sc.exe stop AppPasswordGuard'
  Sleep 800
  nsExec::ExecToLog 'sc.exe delete AppPasswordGuard'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "App Password 보호 서비스를 설치하는 중..."
  ReadEnvStr $0 "PROGRAMDATA"
  CreateDirectory "$0\AppPassword"
  CreateDirectory "$0\AppPassword\events"
  nsExec::ExecToLog 'icacls.exe "$0\AppPassword" /grant *S-1-5-32-545:(OI)(CI)M /T /C'
  nsExec::ExecToLog 'sc.exe create AppPasswordGuard binPath= "$\"$INSTDIR\app-password-guard.exe$\"" start= auto DisplayName= "$\"App Password Guard$\""'
  nsExec::ExecToLog 'sc.exe description AppPasswordGuard "App Password protected application process guard"'
  nsExec::ExecToLog 'sc.exe failure AppPasswordGuard reset= 86400 actions= restart/1000/restart/3000/restart/10000'
  nsExec::ExecToLog 'sc.exe start AppPasswordGuard'
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
