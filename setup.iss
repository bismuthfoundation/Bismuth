[Setup]
AppName=Bismuth Node
AppVersion=4.x
DefaultDirName={pf}\Bismuth Node
DefaultGroupName=Bismuth Node
UninstallDisplayIcon={app}\node.exe
Compression=lzma2
SolidCompression=yes
OutputBaseFilename=Bismuth_node_setup
SetupIconFile=graphics\icon.ico
DisableDirPage=no

WizardImageFile=graphics\left.bmp
WizardSmallImageFile=graphics\mini.bmp

[Files]
Source: "dist\*" ; DestDir: "{app}"; Flags: recursesubdirs;

[Icons]
Name: "{group}\Bismuth Node"; Filename: "{app}\node.exe"
Name: "{group}\Stop Bismuth Node"; Filename: "{app}\node_stop.exe"
Name: "{group}\Uninstall Bismuth Node"; Filename: "{uninstallexe}"

Name: "{commondesktop}\Bismuth Node"; Filename: "{app}\node.exe"
Name: "{commondesktop}\Stop Bismuth Node"; Filename: "{app}\node_stop.exe"

[Registry]
; keys for 64-bit systems
Root: HKCU32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64
Root: HKLM32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64
; keys for 64-bit systems
Root: HKCU32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node_stop.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64
Root: HKLM32; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node_stop.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: not IsWin64

; keys for 64-bit systems
Root: HKCU64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64
; keys for 64-bit systems
Root: HKCU64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node_stop.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64
Root: HKLM64; Subkey: "SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"; ValueType: String; ValueName: "{app}\node_stop.exe"; ValueData: "RUNASADMIN"; Flags: uninsdeletekeyifempty uninsdeletevalue; Check: IsWin64

[Run]
Filename: "{app}\node.exe"; Description: "Full Node"; Flags: shellexec postinstall skipifsilent unchecked
