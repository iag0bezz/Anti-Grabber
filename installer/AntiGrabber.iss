#define MyAppName "AntiGrabber"
#ifndef MyAppVersion
  #define MyAppVersion "0.1.0"
#endif
#define MyAppPublisher "AntiGrabber contributors"
#define MyServiceName "AntiGrabberService"
#define DistDir "..\dist"

[Setup]
AppId={{4C9C6B3D-6E2A-4C77-9E1B-3D1F1C6E9A02}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=..\dist\installer
OutputBaseFilename=AntiGrabberSetup
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
UninstallDisplayIcon={app}\Service\AntiGrabber.Service.exe
WizardStyle=modern

[Languages]
Name: "brazilianportuguese"; MessagesFile: "compiler:Languages\BrazilianPortuguese.isl"

[Types]
Name: "full"; Description: "Completa (serviço + bandeja)"
Name: "custom"; Description: "Personalizada"; Flags: iscustom

[Components]
Name: "service"; Description: "Serviço de proteção (AntiGrabberService)"; Types: full custom; Flags: fixed
Name: "tray"; Description: "Ícone de bandeja"; Types: full custom
Name: "testharness"; Description: "TestHarness (linha de comando, opcional)"; Types: custom

[Files]
Source: "{#DistDir}\AntiGrabber.Service\*"; DestDir: "{app}\Service"; Flags: ignoreversion recursesubdirs; Components: service
Source: "{#DistDir}\AntiGrabber.Tray\*"; DestDir: "{app}\Tray"; Flags: ignoreversion recursesubdirs; Components: tray
Source: "{#DistDir}\AntiGrabber.TestHarness\*"; DestDir: "{app}\TestHarness"; Flags: ignoreversion recursesubdirs; Components: testharness
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\SECURITY.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\Tray\AntiGrabber.Tray.exe"; Components: tray; AppUserModelID: "com.antigrabber.tray"
Name: "{group}\Desinstalar {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{commonstartup}\{#MyAppName}"; Filename: "{app}\Tray\AntiGrabber.Tray.exe"; Components: tray; Tasks: startuptray; AppUserModelID: "com.antigrabber.tray"

[Tasks]
Name: "startuptray"; Description: "Iniciar o ícone de bandeja junto com o Windows"; Components: tray

[Run]
Filename: "{sys}\sc.exe"; Parameters: "create ""{#MyServiceName}"" binPath= ""{app}\Service\AntiGrabber.Service.exe"" start= auto obj= LocalSystem"; Flags: runhidden; Components: service; StatusMsg: "Registrando serviço..."
Filename: "{sys}\sc.exe"; Parameters: "description ""{#MyServiceName}"" ""Protege contra grabbers (roubo de token Discord/Steam). 100% local, sem telemetria."""; Flags: runhidden; Components: service
Filename: "{sys}\sc.exe"; Parameters: "failure ""{#MyServiceName}"" reset= 86400 actions= restart/5000/restart/5000/restart/30000"; Flags: runhidden; Components: service
Filename: "{sys}\sc.exe"; Parameters: "start ""{#MyServiceName}"""; Flags: runhidden; Components: service; StatusMsg: "Iniciando serviço..."
Filename: "{app}\Tray\AntiGrabber.Tray.exe"; Description: "Abrir o AntiGrabber agora"; Flags: postinstall nowait skipifsilent unchecked; Components: tray

[UninstallRun]
Filename: "{sys}\taskkill.exe"; Parameters: "/IM AntiGrabber.Tray.exe /F"; Flags: runhidden; RunOnceId: "KillTray"
Filename: "{sys}\sc.exe"; Parameters: "stop ""{#MyServiceName}"""; Flags: runhidden; RunOnceId: "StopSvc"
Filename: "{sys}\sc.exe"; Parameters: "delete ""{#MyServiceName}"""; Flags: runhidden; RunOnceId: "DeleteSvc"
Filename: "{sys}\sc.exe"; Parameters: "stop WinDivert"; Flags: runhidden; RunOnceId: "StopDriver"
Filename: "{sys}\sc.exe"; Parameters: "delete WinDivert"; Flags: runhidden; RunOnceId: "DeleteDriver"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\AntiGrabber"
