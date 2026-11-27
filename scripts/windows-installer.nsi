; Kite Windows NSIS installer (x64).
;
; Build (Linux host, needs nsis):
;   makensis -DSOURCE_EXE=/path/to/kite-desktop.exe windows-installer.nsi
;
; Optional defines:
;   OUT_FILE=<path>             default: ../dist/windows/kite-<version>-windows-x64-setup.exe
;   ICON=<path to .ico>         default: ../apps/desktop/src-tauri/icons/icon.ico
;   VERSION=<x.y.z>             default: 0.1.0

Unicode true
!include "MUI2.nsh"

!define VERSION "0.1.0"
!ifndef SOURCE_EXE
  !define SOURCE_EXE "${__FILEDIR__}/../dist/windows/kite-desktop.exe"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "${__FILEDIR__}/../dist/windows/kite-${VERSION}-windows-x64-setup.exe"
!endif
!ifndef ICON
  !define ICON "${__FILEDIR__}/../apps/desktop/src-tauri/icons/icon.ico"
!endif

Name "Kite"
OutFile "${OUT_FILE}"
InstallDir "$PROGRAMFILES64\Kite"
InstallDirRegKey HKLM "Software\Kite" "InstallDir"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

!define MUI_ABORTWARNING
!define MUI_ICON "${ICON}"
!define MUI_UNICON "${ICON}"

!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "SimpChinese"
!insertmacro MUI_LANGUAGE "English"

Section "Kite" SecMain
  SetShellVarContext all
  SetOutPath "$INSTDIR"
  File /oname=kite-desktop.exe "${SOURCE_EXE}"
  CreateShortcut "$DESKTOP\Kite.lnk" "$INSTDIR\kite-desktop.exe"
  CreateDirectory "$SMPROGRAMS\Kite"
  CreateShortcut "$SMPROGRAMS\Kite\Kite.lnk" "$INSTDIR\kite-desktop.exe"
  CreateShortcut "$SMPROGRAMS\Kite\Uninstall Kite.lnk" "$INSTDIR\uninstall.exe"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Kite" "InstallDir" "$INSTDIR"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "DisplayName" "Kite"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "DisplayVersion" "${VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "Publisher" "Kite"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "DisplayIcon" "$INSTDIR\kite-desktop.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite" "NoRepair" 1
  ; Explorer context menu: "Send with Kite" for files.
  WriteRegStr HKLM "Software\Classes\*\shell\KiteSend" "" "Send with Kite"
  WriteRegStr HKLM "Software\Classes\*\shell\KiteSend" "Icon" "$INSTDIR\kite-desktop.exe"
  WriteRegStr HKLM "Software\Classes\*\shell\KiteSend\command" "" '"$INSTDIR\kite-desktop.exe" --share "%1"'
SectionEnd

Section "Uninstall"
  SetShellVarContext all
  Delete "$DESKTOP\Kite.lnk"
  Delete "$SMPROGRAMS\Kite\Kite.lnk"
  Delete "$SMPROGRAMS\Kite\Uninstall Kite.lnk"
  RMDir "$SMPROGRAMS\Kite"
  RMDir /r "$INSTDIR"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\Kite"
  DeleteRegKey HKLM "Software\Kite"
  DeleteRegKey HKLM "Software\Classes\*\shell\KiteSend"
SectionEnd
