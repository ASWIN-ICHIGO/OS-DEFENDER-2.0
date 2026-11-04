; OS-DEFENDER 2.0 NSIS Installer Script
; Requires NSIS 3.x with nsProcess and AccessControl plugins

!define PRODUCT_NAME "OS-DEFENDER"
!define PRODUCT_VERSION "2.0.0"
!define PRODUCT_PUBLISHER "Aswin"
!define SERVICE_NAME "OSDefenderAgent"
!define INSTALL_DIR "$PROGRAMFILES\OS-DEFENDER"
!define DATA_DIR "$COMMONAPPDATA\OS-DEFENDER"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "os-defender-${PRODUCT_VERSION}-setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin

;--- Pages ---
Page license
Page directory
Page instfiles

LicenseData "..\..\LICENSE"

;--- Install Section ---
Section "Install"
    SetOutPath "$INSTDIR"

    ; Stop existing service
    nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'
    Sleep 2000
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'
    Sleep 1000

    ; Copy binaries
    File "..\..\target\release\os-defender-agent.exe"
    File "..\..\target\release\os-defender.exe"

    ; Create data directories
    CreateDirectory "${DATA_DIR}"
    CreateDirectory "${DATA_DIR}\quarantine"
    CreateDirectory "${DATA_DIR}\logs"

    ; Write default config
    IfFileExists "${DATA_DIR}\agent.toml" skip_config
    FileOpen $0 "${DATA_DIR}\agent.toml" w
    FileWrite $0 '[agent]$\r$\n'
    FileWrite $0 'poll_interval_ms = 2000$\r$\n'
    FileWrite $0 'heartbeat_timeout_secs = 60$\r$\n'
    FileWrite $0 'policy_mode = "dry_run"$\r$\n'
    FileWrite $0 'watch_dirs = "C:\Windows\System32\drivers\etc,C:\Users"$\r$\n'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '[storage]$\r$\n'
    FileWrite $0 'db_path = "C:\ProgramData\OS-DEFENDER\os-defender.db"$\r$\n'
    FileWrite $0 '$\r$\n'
    FileWrite $0 '[quarantine]$\r$\n'
    FileWrite $0 'dir = "C:\ProgramData\OS-DEFENDER\quarantine"$\r$\n'
    FileClose $0
    skip_config:

    ; Register Windows service
    nsExec::ExecToLog 'sc create ${SERVICE_NAME} binPath= "$INSTDIR\os-defender-agent.exe --service" start= auto DisplayName= "OS-DEFENDER Protection Agent"'
    nsExec::ExecToLog 'sc description ${SERVICE_NAME} "OS-DEFENDER real-time endpoint protection agent"'
    nsExec::ExecToLog 'sc failure ${SERVICE_NAME} reset= 86400 actions= restart/5000/restart/10000/restart/30000'

    ; Add to PATH
    EnVar::AddValue "PATH" "$INSTDIR"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Registry for Add/Remove Programs
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "DisplayName" "${PRODUCT_NAME} ${PRODUCT_VERSION}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "DisplayVersion" "${PRODUCT_VERSION}"
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "NoModify" 1
    WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" \
        "NoRepair" 1

    ; Start service
    nsExec::ExecToLog 'sc start ${SERVICE_NAME}'
SectionEnd

;--- Uninstall Section ---
Section "Uninstall"
    ; Stop and remove service
    nsExec::ExecToLog 'sc stop ${SERVICE_NAME}'
    Sleep 2000
    nsExec::ExecToLog 'sc delete ${SERVICE_NAME}'

    ; Remove binaries
    Delete "$INSTDIR\os-defender-agent.exe"
    Delete "$INSTDIR\os-defender.exe"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove from PATH
    EnVar::DeleteValue "PATH" "$INSTDIR"

    ; Remove registry
    DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"

    ; Note: data directory is preserved
    MessageBox MB_YESNO "Remove data directory (${DATA_DIR})?" IDNO keep_data
    RMDir /r "${DATA_DIR}"
    keep_data:
SectionEnd
