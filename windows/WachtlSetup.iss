; Wachtl – ein Setup für Probe (Client) und Server (Inno Setup 6)
; Bauen: windows\build-server.ps1 (übergibt AppVersion, BuildDir und ProbeDir)
;
; Rolle: Probe (Standard) oder Server. Steht eine Vorbelegung fest, fragt das Setup nicht nach.
;
; Vorbelegung für die Probe (spätere Quellen gewinnen):
;   1. im Setup eingebaut – „Setup herunterladen“ im Web-UI (Verwaltung › Probes registrieren).
;      Dann zeigt das Setup nur noch „Installieren“.
;   2. wachtl-probe.ini neben der Setup-Datei ([wachtl] servers=… pin=… token=… proxy=…)
;   3. Parameter: /Server=https://name:8443,https://10.0.0.5:8443 /Pin= /Token= /Proxy= /Hostname=
;
; Unbeaufsichtigt:
;   Probe:  WachtlSetup-Standort.exe /VERYSILENT /SUPPRESSMSGBOXES            (vorbelegt)
;           WachtlSetup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES /Server=… /Pin=… /Token=…
;   Tray-Symbol (Problem melden, Über, Beenden) startet bei jeder Anmeldung; /NoTray lässt es weg (wird gemerkt),
;   /Tray schaltet es wieder ein.
;   Server: WachtlSetup-x.y.z.exe /VERYSILENT /SUPPRESSMSGBOXES /Role=Server /Hostnames="wachtl.kunde.local"
;           /AdminPassword="…" [/HttpsPort=443] [/HttpPort=80] [/IperfPort=5201] [/RtpPort=5004] [/DataDir="D:\Wachtl"]
;           [/RawDays=30] [/AggMonths=13] [/EmailTo=… /EmailFrom=… /SmtpHost=mail:587 /SmtpUser=… /SmtpPassword=…] [/TeamsUrl=…]
; Exit-Code 0 = läuft (Probe: angemeldet oder Anmeldung folgt automatisch, sobald der Server erreichbar ist),
; 10 = installiert, aber nicht betriebsbereit (Grund im /LOG). /SUPPRESSMSGBOXES ist unbeaufsichtigt Pflicht.

#ifndef AppVersion
  #define AppVersion "0.9.2"
#endif
#ifndef BuildDir
  #define BuildDir "..\build\server"
#endif
#ifndef ProbeDir
  #define ProbeDir "..\dist\probe"
#endif

[Setup]
; je Rolle die AppId der bisherigen Setups: vorhandene Probes und Server werden an Ort und Stelle aktualisiert
AppId={code:GetAppId}
AppName=Wachtl
AppVersion={#AppVersion}
AppVerName=Wachtl {#AppVersion}
AppPublisher=Wachtl
DefaultDirName={code:GetDefaultDir}
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableWelcomePage=yes
DefaultGroupName={code:GetProductName}
UsePreviousAppDir=yes
; Pflicht bei einer AppId aus [Code]; es gibt ohnehin nur Deutsch
UsePreviousLanguage=no
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.14393
OutputBaseFilename=WachtlSetup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=assets\wachtl.ico
WizardImageFile=assets\wizard-100.bmp,assets\wizard-150.bmp,assets\wizard-200.bmp
WizardSmallImageFile=assets\wizard-small-100.bmp,assets\wizard-small-150.bmp,assets\wizard-small-200.bmp
SetupLogging=yes
TimeStampsInUTC=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayName={code:GetProductName}
UninstallDisplayIcon={app}\wachtl.ico
VersionInfoVersion={#AppVersion}

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[InstallDelete]
; Server: alte Setup-Kopien für den Download aus dem Web-UI entfernen
Type: files; Name: "{app}\probe\WachtlSetup-*.exe"; Check: IsServer
Type: files; Name: "{app}\probe\WachtlProbeSetup-*.exe"; Check: IsServer
; Probe: frühere Setup-Kopie (bis 0.4) – sie könnte einen Token enthalten
Type: files; Name: "{app}\WachtlProbeSetup.exe"; Check: IsClient

[Files]
Source: "assets\wachtl.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\THIRD-PARTY.txt"; DestDir: "{app}"; Flags: ignoreversion
; Tray-Symbol neben der Uhr, beide Rollen (.NET Framework 4.6.2 aus Windows, ~100 KB)
Source: "{#ProbeDir}\wachtl-tray.exe"; DestDir: "{app}"; Flags: ignoreversion
; ---- Probe ----
Source: "{#ProbeDir}\wachtl-probe.exe"; DestDir: "{app}"; Flags: ignoreversion; Check: IsClient
Source: "{#ProbeDir}\iperf3\*"; DestDir: "{app}\iperf3"; Flags: ignoreversion recursesubdirs; Check: IsClient
Source: "..\probe\setup\wachtl-status.cmd"; DestDir: "{app}"; Flags: ignoreversion; Check: IsClient
; ---- Server ----
Source: "{#BuildDir}\python\*"; DestDir: "{app}\python"; Flags: recursesubdirs ignoreversion; Check: IsServer
Source: "{#BuildDir}\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs ignoreversion; Check: IsServer
Source: "{#BuildDir}\bin\*"; DestDir: "{app}\bin"; Flags: recursesubdirs ignoreversion; Check: IsServer
Source: "{#BuildDir}\service\WachtlServer.exe"; DestDir: "{app}\service"; Flags: ignoreversion; Check: IsServer
Source: "{#BuildDir}\wachtl-server.cmd"; DestDir: "{app}"; Flags: ignoreversion; Check: IsServer
Source: "wachtl-status.cmd"; DestDir: "{app}"; Flags: ignoreversion; Check: IsServer
Source: "wachtl-passwort.cmd"; DestDir: "{app}"; Flags: ignoreversion; Check: IsServer
Source: "{#BuildDir}\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs ignoreversion; Check: IsServer
; Das Setup selbst: daraus erzeugt das Web-UI die vorbelegten Setups für die Probes
Source: "{srcexe}"; DestDir: "{app}\probe"; DestName: "WachtlSetup-{#AppVersion}.exe"; Flags: external ignoreversion; Check: IsServer

[INI]
Filename: "{group}\Wachtl Dashboard.url"; Section: "InternetShortcut"; Key: "URL"; String: "{code:GetUrl}"; Check: IsServer

[Icons]
Name: "{group}\Wachtl Status"; Filename: "{app}\wachtl-status.cmd"; WorkingDir: "{app}"; IconFilename: "{app}\wachtl.ico"
Name: "{group}\Logdateien"; Filename: "{code:LogDir}"
Name: "{group}\Wachtl – Problem melden"; Filename: "{app}\wachtl-tray.exe"; Parameters: "--report"
Name: "{group}\Zugangsdaten (setup-info.txt)"; Filename: "{code:GetDataDir}\setup-info.txt"; Check: IsServer
Name: "{group}\Admin-Passwort zurücksetzen"; Filename: "{app}\wachtl-passwort.cmd"; WorkingDir: "{app}"; IconFilename: "{app}\wachtl.ico"; Check: IsServer
Name: "{group}\Setups für die Probes"; Filename: "{app}\probe"; Check: IsServer

[Registry]
Root: HKLM; Subkey: "Software\Wachtl Server"; ValueType: string; ValueName: "DataDir"; ValueData: "{code:GetDataDir}"; Flags: uninsdeletekey; Check: IsServer
Root: HKLM; Subkey: "Software\Wachtl Server"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"; Check: IsServer

; Tray-Symbol bei jeder Anmeldung (alle Benutzer); je Rolle ein eigener Eintrag, damit eine Deinstallation den anderen nicht löscht
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Wachtl Tray"; ValueData: """{app}\wachtl-tray.exe"""; Flags: uninsdeletevalue; Check: IsClient and TrayWanted
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Wachtl Server Tray"; ValueData: """{app}\wachtl-tray.exe"""; Flags: uninsdeletevalue; Check: IsServer and TrayWanted
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "Wachtl Tray"; Flags: deletevalue; Check: IsClient and not TrayWanted
Root: HKLM; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueName: "Wachtl Server Tray"; Flags: deletevalue; Check: IsServer and not TrayWanted
Root: HKLM; Subkey: "{code:TrayRegKey}"; ValueType: dword; ValueName: "NoTray"; ValueData: 1; Flags: uninsdeletekey; Check: not TrayWanted
Root: HKLM; Subkey: "{code:TrayRegKey}"; ValueName: "NoTray"; Flags: deletevalue; Check: TrayWanted

[Run]
Filename: "{code:GetUrl}"; Description: "Wachtl im Browser öffnen"; Flags: postinstall shellexec nowait skipifsilent; Check: ServerSucceeded
Filename: "notepad.exe"; Parameters: """{code:GetDataDir}\setup-info.txt"""; Description: "Zugangsdaten und SPKI-Pin anzeigen"; Flags: postinstall nowait skipifsilent unchecked; Check: ServerSucceeded

[UninstallRun]
; Tray-Symbole aller angemeldeten Benutzer schließen
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM wachtl-tray.exe"; Flags: runhidden waituntilterminated; RunOnceId: "StopTray"
; ---- Probe: zuerst am Server abmelden (Token wird dort ungültig), dann Dienst, Prozesse und Firewall-Regeln ----
Filename: "{app}\wachtl-probe.exe"; Parameters: "deregister --out ""{commonappdata}\Wachtl\deregister.ini"""; Flags: runhidden waituntilterminated; RunOnceId: "Deregister"; Check: IsClient
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /F /TN ""Wachtl Zertifikat"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteTrustTask"; Check: IsClient
Filename: "{app}\wachtl-probe.exe"; Parameters: "trust --remove 1"; Flags: runhidden waituntilterminated; RunOnceId: "Untrust"; Check: IsClient
Filename: "{sys}\net.exe"; Parameters: "stop Wachtl"; Flags: runhidden waituntilterminated; RunOnceId: "StopWachtl"; Check: IsClient
Filename: "{sys}\sc.exe"; Parameters: "delete Wachtl"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteWachtl"; Check: IsClient
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -Command ""Get-Process iperf3,wachtl-probe,wachtl-tray -ErrorAction SilentlyContinue | Where-Object {{ $_.Path -like '{app}\*' } | Stop-Process -Force"""; Flags: runhidden waituntilterminated; RunOnceId: "StopProcesses"; Check: IsClient
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule ""name=Wachtl Probe iperf3"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteFirewall"; Check: IsClient
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule ""name=Wachtl Probe RTP"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteFirewallRtp"; Check: IsClient
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all ""program={app}\iperf3\iperf3.exe"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteFirewallIperf"; Check: IsClient
Filename: "{sys}\netsh.exe"; Parameters: "advfirewall firewall delete rule name=all ""program={app}\wachtl-probe.exe"""; Flags: runhidden waituntilterminated; RunOnceId: "DeleteFirewallProbe"; Check: IsClient
; ---- Server: Dienst (samt Server-Probe), Firewall-Regeln und geplante Sicherung entfernen, Ports prüfen ----
Filename: "{app}\python\python.exe"; Parameters: "-m wachtl.win.installer uninstall --result ""{commonappdata}\Wachtl Server Deinstallation.ini"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "WachtlUninstall"; Check: IsServer

[UninstallDelete]
Type: files; Name: "{app}\wachtl-tray.old"
Type: files; Name: "{commonappdata}\Wachtl\state.json"; Check: IsClient
Type: files; Name: "{commonappdata}\Wachtl\state.json.tmp"; Check: IsClient
Type: files; Name: "{commonappdata}\Wachtl\config.json"; Check: IsClient
Type: files; Name: "{commonappdata}\Wachtl\config.json.tmp"; Check: IsClient
Type: files; Name: "{commonappdata}\Wachtl\enroll-pending.json"; Check: IsClient
Type: dirifempty; Name: "{app}\iperf3"; Check: IsClient
Type: filesandordirs; Name: "{app}\app"; Check: IsServer
Type: filesandordirs; Name: "{app}\python"; Check: IsServer
Type: filesandordirs; Name: "{app}\service"; Check: IsServer
Type: filesandordirs; Name: "{app}\probe"; Check: IsServer
Type: files; Name: "{app}\datadir.txt"; Check: IsServer
Type: files; Name: "{group}\Wachtl Dashboard.url"; Check: IsServer
Type: dirifempty; Name: "{app}"

[Code]
const
  RoleClient = 0;
  RoleServer = 1;
  ServiceName = 'Wachtl';
  ServiceAccount = 'NT SERVICE\Wachtl';
  ModeKeep = 0;
  ModeProxy = 1;
  ModeNew = 2;
  ServerRegKey = 'Software\Wachtl Server';
  ExitEnrollDeferred = 7;

var
  Role: Integer;
  RoleFixed: Boolean;
  RoleReason: String;
  RolePage: TInputOptionWizardPage;
  { Probe }
  Prefilled: Boolean;
  PreServers, PrePin, PreToken, PreProxy, PreSite: String;
  ModePage: TInputOptionWizardPage;
  ConnectPage: TInputQueryWizardPage;
  ClientEnrolled, ServiceExists, ClientOk, EnrollDone, EnrollDeferred, CheckDone: Boolean;
  EnrolledKey, SiteName, ProbeExe, Hostname, ClientError, ClientNote: String;
  { Server }
  AddressPage, AdminPage, NotifyPage: TInputQueryWizardPage;
  StoragePage: TInputDirWizardPage;
  RawDaysEdit, AggMonthsEdit, PinEdit: TNewEdit;
  ServerUpgrade, ServerOk: Boolean;
  ExistingDataDir, ResultUrl, ResultPin, ResultError: String;
  { Deinstallation }
  UninstallServer: Boolean;
  UninstallDataDir: String;

// ============================================================ Hilfen

function GetParam(const Name, Default: String): String;
begin
  Result := ExpandConstant('{param:' + Name + '|}');
  if Result = '' then
    Result := Default;
end;

function Quote(const S: String): String;
begin
  Result := '"' + S + '"';
end;

function RunHidden(const Exe, Params: String): Integer;
begin
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

function IsServer(): Boolean;
begin
  Result := Role = RoleServer;
end;

function IsClient(): Boolean;
begin
  Result := Role = RoleClient;
end;

function GetAppId(Param: String): String;
begin
  if IsServer() then
    Result := '{B7E2C1A4-3D5F-4C8E-9A61-2F7D0E9B4C13}'
  else
    Result := '{4D6A9E31-7C2B-4F58-B1E0-93A5C7D2F861}';
end;

var
  TrayDecided, TrayOn: Boolean;

function TrayRegKey(Param: String): String;
begin
  if IsServer() then
    Result := 'Software\Wachtl Server'
  else
    Result := 'Software\Wachtl Probe';
end;

{ Symbol ja/nein: /NoTray schaltet ab, /Tray wieder an; ohne Parameter bleibt die Wahl der letzten Installation }
function TrayWanted(): Boolean;
var
  I: Integer;
begin
  if not TrayDecided then
  begin
    TrayOn := not RegValueExists(HKLM, TrayRegKey(''), 'NoTray');
    for I := 1 to ParamCount do
      if (CompareText(ParamStr(I), '/NoTray') = 0) or (CompareText(ParamStr(I), '/NoTray=1') = 0) then
        TrayOn := False
      else if CompareText(ParamStr(I), '/Tray') = 0 then
        TrayOn := True;
    TrayDecided := True;
  end;
  Result := TrayOn;
end;

function GetDefaultDir(Param: String): String;
begin
  if IsServer() then
    Result := ExpandConstant('{autopf}\Wachtl Server')
  else
    Result := ExpandConstant('{autopf}\Wachtl');
end;

function GetProductName(Param: String): String;
begin
  if IsServer() then
    Result := 'Wachtl Server'
  else
    Result := 'Wachtl Probe';
end;

function RoleName(Param: String): String;
begin
  if IsServer() then
    Result := 'server'
  else
    Result := 'client';
end;

function ProbeDataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\Wachtl');
end;

function IsNumberInRange(const S: String; Lo, Hi: Integer): Boolean;
var
  V: Integer;
begin
  V := StrToIntDef(Trim(S), -1);
  Result := (V >= Lo) and (V <= Hi) and (IntToStr(V) = Trim(S));
end;

// ============================================================ Vorbelegung im Setup selbst

// Liest den Block, den das Web-UI an das Setup anhängt (letzte 8 KB der eigenen Datei).
function ReadEmbeddedConfig(const IniFile: String): Boolean;
var
  Stream: TFileStream;
  Size: Int64;
  Buf: AnsiString;
  Text: String;
  P, E: Integer;
begin
  Result := False;
  try
    Stream := TFileStream.Create(ExpandConstant('{srcexe}'), $0040);  // fmOpenRead or fmShareDenyNone
    try
      // ein Setup ist immer viel größer als 8 KB
      Size := Stream.Size;
      Stream.Seek(Size - 8192, 0);
      SetLength(Buf, 8192);
      Stream.ReadBuffer(Buf, 8192);
    finally
      Stream.Free;
    end;
  except
    Log('Wachtl: Vorbelegung nicht lesbar: ' + GetExceptionMessage);
    Exit;
  end;
  Text := String(Buf);
  P := Pos('@@WACHTL-SETUP-CONFIG@@', Text);
  E := Pos('@@WACHTL-SETUP-END@@', Text);
  if (P > 0) and (E > P) then
  begin
    Text := Copy(Text, P + Length('@@WACHTL-SETUP-CONFIG@@'), E - P - Length('@@WACHTL-SETUP-CONFIG@@'));
    Result := SaveStringToFile(IniFile, AnsiString(Text), False);
  end;
end;

procedure LoadPrefill();
var
  Embedded, Beside: String;
begin
  Embedded := ExpandConstant('{tmp}\wachtl-embedded.ini');
  Beside := ExpandConstant('{src}\wachtl-probe.ini');
  if ReadEmbeddedConfig(Embedded) then
  begin
    PreServers := GetIniString('wachtl', 'servers', '', Embedded);
    PrePin := GetIniString('wachtl', 'pin', '', Embedded);
    PreToken := GetIniString('wachtl', 'token', '', Embedded);
    PreProxy := GetIniString('wachtl', 'proxy', '', Embedded);
    PreSite := GetIniString('wachtl', 'site', '', Embedded);
    Log('Wachtl: Vorbelegung im Setup gefunden (Standort ' + PreSite + ', Server ' + PreServers + ')');
  end
  else if FileExists(Beside) then
  begin
    PreServers := GetIniString('wachtl', 'servers', GetIniString('wachtl', 'server', '', Beside), Beside);
    PrePin := GetIniString('wachtl', 'pin', '', Beside);
    PreToken := GetIniString('wachtl', 'token', '', Beside);
    PreProxy := GetIniString('wachtl', 'proxy', '', Beside);
    Log('Wachtl: Vorbelegung aus ' + Beside);
  end;
  PreServers := GetParam('Server', PreServers);
  PrePin := GetParam('Pin', PrePin);
  PreToken := GetParam('Token', PreToken);
  PreProxy := GetParam('Proxy', PreProxy);
  Hostname := GetParam('Hostname', GetComputerNameString());
  Prefilled := (Trim(PreServers) <> '') and (Trim(PrePin) <> '') and (Trim(PreToken) <> '');
end;

// ============================================================ Rolle bestimmen

procedure DetermineRole();
var
  Code: Integer;
  Requested: String;
  ServerPresent, ClientPresent: Boolean;
begin
  Role := RoleClient;
  RoleFixed := False;
  ClientEnrolled := FileExists(ProbeDataDir() + '\state.json') or FileExists(ProbeDataDir() + '\enroll-pending.json');
  ServiceExists := Exec(ExpandConstant('{sys}\sc.exe'), 'query ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  ServerUpgrade := RegQueryStringValue(HKLM, ServerRegKey, 'DataDir', ExistingDataDir)
                   and RegValueExists(HKLM, ServerRegKey, 'Configured')
                   and FileExists(ExistingDataDir + '\config\wachtl.env');
  ServerPresent := ServerUpgrade;
  ClientPresent := ClientEnrolled or ServiceExists;
  Requested := Lowercase(GetParam('Role', ''));
  RoleFixed := True;
  if Requested = 'server' then
  begin
    Role := RoleServer;
    RoleReason := 'Parameter /Role=Server';
  end
  else if (Requested = 'client') or (Requested = 'probe') then
    RoleReason := 'Parameter /Role=Client'
  else if Prefilled then
    RoleReason := 'vorbelegtes Probe-Setup'
  else if ServerPresent and not ClientPresent then
  begin
    Role := RoleServer;
    RoleReason := 'Update des Wachtl-Servers';
  end
  else if ClientPresent and not ServerPresent then
    RoleReason := 'Update der Wachtl-Probe'
  else
  begin
    // neu oder beides vorhanden: fragen (unbeaufsichtigt ohne /Role: Server, falls vorhanden, sonst Probe)
    RoleFixed := WizardSilent();
    if ServerPresent then
      Role := RoleServer;
    RoleReason := 'Auswahl';
  end;
  Log('Wachtl: Rolle ' + RoleName('') + ' (' + RoleReason + ')');
end;

// ============================================================ Probe: Hilfen

function Mode(): Integer;
begin
  if not ClientEnrolled then
    Result := ModeNew
  else if ModePage.Values[ModeProxy] then
    Result := ModeProxy
  else if ModePage.Values[ModeNew] then
    Result := ModeNew
  else
    Result := ModeKeep;
end;

function Servers(): String;
begin
  Result := Trim(ConnectPage.Values[0]);
end;

function FirstServer(): String;
var
  S: String;
  P: Integer;
begin
  S := Servers();
  StringChangeEx(S, ';', ',', True);
  P := Pos(',', S);
  if P > 0 then
    S := Copy(S, 1, P - 1);
  S := Trim(S);
  if (S <> '') and (Pos('://', S) = 0) then
    S := 'https://' + S;
  Result := S;
end;

function ProxyValue(): String;
begin
  Result := Trim(ConnectPage.Values[3]);
end;

function ProxyArg(): String;
begin
  if ProxyValue() <> '' then
    Result := ' --proxy ' + Quote(ProxyValue())
  else
    Result := '';
end;

function EnsureProbeExe(): String;
begin
  if ProbeExe = '' then
  begin
    ExtractTemporaryFile('wachtl-probe.exe');
    ProbeExe := ExpandConstant('{tmp}\wachtl-probe.exe');
  end;
  Result := ProbeExe;
end;

function RunProbe(const Exe, Params, ResultFile: String): Integer;
begin
  DeleteFile(ResultFile);
  Result := RunHidden(Exe, Params + ' --out ' + Quote(ResultFile));
end;

function ResultValue(const ResultFile, Key: String): String;
begin
  Result := GetIniString('result', Key, '', ResultFile);
  StringChangeEx(Result, '\n', #13#10, True);
end;

function EnrollParams(): String;
begin
  Result := 'enroll --server ' + Quote(Servers()) + ' --pin ' + Quote(Trim(ConnectPage.Values[1])) +
            ' --token ' + Quote(Trim(ConnectPage.Values[2])) + ' --hostname ' + Quote(Hostname) +
            ' --defer-offline 1' + ProxyArg();
end;

// ============================================================ Server: Hilfen

function FirstHostname(const List: String): String;
var
  S: String;
  P: Integer;
begin
  S := List;
  StringChangeEx(S, ';', ',', True);
  P := Pos(',', S);
  if P > 0 then
    S := Copy(S, 1, P - 1);
  Result := Trim(S);
end;

function DefaultHostnames(): String;
var
  Domain, Computer: String;
begin
  Computer := Lowercase(GetComputerNameString());
  Domain := '';
  if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'NV Domain', Domain) then
    if not RegQueryStringValue(HKLM, 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters', 'Domain', Domain) then
      Domain := '';
  if Trim(Domain) <> '' then
    Result := Computer + '.' + Lowercase(Trim(Domain)) + ', ' + Computer
  else
    Result := Computer;
end;

function ReadEnvValue(const Key: String): String;
var
  Lines: TArrayOfString;
  I: Integer;
begin
  Result := '';
  if LoadStringsFromFile(ExistingDataDir + '\config\wachtl.env', Lines) then
    for I := 0 to GetArrayLength(Lines) - 1 do
      if Pos(Key + '=', Lines[I]) = 1 then
        Result := Copy(Lines[I], Length(Key) + 2, Length(Lines[I]));
end;

function PortInUse(Port: Integer): Boolean;
var
  TmpFile, Line, Needle: String;
  Lines: TArrayOfString;
  I, Code: Integer;
begin
  Result := False;
  if Port <= 0 then
    Exit;
  TmpFile := ExpandConstant('{tmp}\netstat.txt');
  Exec(ExpandConstant('{cmd}'), '/C netstat -ano -p TCP > "' + TmpFile + '"', '', SW_HIDE, ewWaitUntilTerminated, Code);
  if not LoadStringsFromFile(TmpFile, Lines) then
    Exit;
  Needle := ':' + IntToStr(Port) + ' ';
  for I := 0 to GetArrayLength(Lines) - 1 do
  begin
    Line := Uppercase(Lines[I]);
    if ((Pos('LISTEN', Line) > 0) or (Pos('ABH', Line) > 0)) and (Pos(Needle, Line) > 0) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function JsonEscape(const S: String): String;
begin
  Result := S;
  StringChangeEx(Result, '\', '\\', True);
  StringChangeEx(Result, '"', '\"', True);
  StringChangeEx(Result, #9, '\t', True);
  StringChangeEx(Result, #13, '', True);
  StringChangeEx(Result, #10, '\n', True);
end;

function JsonPair(const Key, Value: String; Last: Boolean): String;
begin
  Result := '  "' + Key + '": "' + JsonEscape(Value) + '"';
  if not Last then
    Result := Result + ',';
end;

// ============================================================ Werte für die Abschnitte oben

function GetDataDir(Param: String): String;
begin
  if not IsServer() then
    Result := ''
  else if ServerUpgrade then
    Result := ExistingDataDir
  else
    Result := RemoveBackslash(Trim(StoragePage.Values[0]));
end;

function LogDir(Param: String): String;
begin
  if IsServer() then
    Result := GetDataDir('') + '\logs'
  else
    Result := ProbeDataDir() + '\logs';
end;

function GetUrl(Param: String): String;
var
  Port: String;
begin
  if ResultUrl <> '' then
    Result := ResultUrl
  else if ServerUpgrade then
    Result := ReadEnvValue('WACHTL_PUBLIC_URL')
  else
  begin
    Port := Trim(AddressPage.Values[1]);
    Result := 'https://' + FirstHostname(AddressPage.Values[0]);
    if Port <> '443' then
      Result := Result + ':' + Port;
  end;
end;

function ServerSucceeded(): Boolean;
begin
  Result := IsServer() and ServerOk;
end;

// ============================================================ Assistent

function InitializeSetup(): Boolean;
begin
  LoadPrefill();
  DetermineRole();
  Result := True;
end;

procedure InitializeWizard();
var
  L1, L2: TNewStaticText;
  Top: Integer;
begin
  RolePage := CreateInputOptionPage(wpWelcome,
    'Was soll auf diesem Rechner laufen?', 'Wachtl besteht aus Probes an den Standorten und einem zentralen Server.',
    'Im Normalfall eine Probe. Den Server gibt es einmal je Kunde.', True, False);
  RolePage.Add('Probe – misst von diesem PC aus und meldet an den Wachtl-Server (Standard)');
  RolePage.Add('Wachtl-Server – sammelt die Messwerte, Web-Oberfläche und Alarme');
  RolePage.SelectedValueIndex := Role;

  // ---- Probe ----
  ModePage := CreateInputOptionPage(RolePage.ID,
    'Vorhandene Probe', 'Diese Probe ist bereits registriert.', 'Was soll geschehen?', True, False);
  ModePage.Add('Nur aktualisieren – Registrierung und Einstellungen behalten');
  ModePage.Add('Proxy ändern');
  ModePage.Add('Neu registrieren – anderer Server, anderer Standort oder neuer Token');
  ModePage.SelectedValueIndex := ModeKeep;

  ConnectPage := CreateInputQueryPage(ModePage.ID,
    'Verbindung zum Wachtl-Server', 'Wohin soll diese Probe melden?',
    'Alle Werte stehen im Web-UI unter Verwaltung › Probes registrieren. Einfacher: dort „Setup herunterladen“ – ' +
    'dann ist alles schon eingetragen. Mehrere Adressen (Name und IP) mit Komma trennen.');
  ConnectPage.Add('Server (z. B. https://wachtl.kunde.local, https://10.0.0.5):', False);
  ConnectPage.Add('SPKI-Pin (leer = beim Server nachfragen):', False);
  ConnectPage.Add('Enrollment-Token:', False);
  ConnectPage.Add('Proxy (nur falls nötig, z. B. http://proxy:3128):', False);
  ConnectPage.Values[0] := PreServers;
  ConnectPage.Values[1] := PrePin;
  ConnectPage.Values[2] := PreToken;
  ConnectPage.Values[3] := PreProxy;

  // ---- Server ----
  AddressPage := CreateInputQueryPage(ConnectPage.ID,
    'Server-Adresse', 'Unter welcher Adresse erreichen Probes und Browser diesen Server?',
    'Servernamen mit Komma trennen. Die IP-Adressen dieses Servers ergänzt das Setup automatisch, ' +
    'damit Probes ihn auch ohne Namensauflösung finden. Der erste Eintrag wird die Adresse im Browser.');
  AddressPage.Add('Servernamen:', False);
  AddressPage.Add('HTTPS-Port:', False);
  AddressPage.Add('HTTP-Port für die Umleitung auf HTTPS (0 = aus):', False);
  AddressPage.Add('iperf3-Port für Bandbreitenmessungen der Probes (TCP und UDP, 0 = aus):', False);
  AddressPage.Values[0] := GetParam('Hostnames', DefaultHostnames());
  AddressPage.Values[1] := GetParam('HttpsPort', '443');
  AddressPage.Values[2] := GetParam('HttpPort', '80');
  AddressPage.Values[3] := GetParam('IperfPort', '5201');

  AdminPage := CreateInputQueryPage(AddressPage.ID,
    'Administrator', 'Passwort für die Anmeldung als „admin“ im Web-UI',
    'Weitere Benutzer legen Sie später im Web-UI an.');
  AdminPage.Add('Passwort:', True);
  AdminPage.Add('Passwort wiederholen:', True);
  AdminPage.Values[0] := GetParam('AdminPassword', '');
  AdminPage.Values[1] := GetParam('AdminPassword', '');

  NotifyPage := CreateInputQueryPage(AdminPage.ID,
    'Benachrichtigungen', 'Wohin sollen Alarme gehen? (optional)',
    'Leere Felder schalten den Kanal ab. Alles lässt sich später im Web-UI unter Verwaltung › Benachrichtigungen ändern.');
  NotifyPage.Add('E-Mail an (mehrere mit Komma):', False);
  NotifyPage.Add('Absenderadresse:', False);
  NotifyPage.Add('SMTP-Server (host:port, z. B. mail.kunde.de:587):', False);
  NotifyPage.Add('SMTP-Benutzer (optional):', False);
  NotifyPage.Add('SMTP-Passwort (optional):', True);
  NotifyPage.Add('Microsoft-Teams-Webhook (https://…):', False);
  NotifyPage.Values[0] := GetParam('EmailTo', '');
  NotifyPage.Values[1] := GetParam('EmailFrom', '');
  NotifyPage.Values[2] := GetParam('SmtpHost', '');
  NotifyPage.Values[3] := GetParam('SmtpUser', '');
  NotifyPage.Values[4] := GetParam('SmtpPassword', '');
  NotifyPage.Values[5] := GetParam('TeamsUrl', '');

  StoragePage := CreateInputDirPage(NotifyPage.ID,
    'Daten und Aufbewahrung', 'Wo sollen Datenbank, Messwerte, Zertifikat und Sicherungen liegen?',
    'Für 25 Probes mit je 10 Zielen reichen etwa 5 GB. Der Ordner wird auf SYSTEM, Administratoren ' +
    'und das Dienstkonto beschränkt.', False, '');
  StoragePage.Add('Datenordner:');
  StoragePage.Values[0] := GetParam('DataDir', ExpandConstant('{commonappdata}\Wachtl Server'));

  Top := StoragePage.Buttons[0].Top + StoragePage.Buttons[0].Height + ScaleY(24);
  L1 := TNewStaticText.Create(StoragePage);
  L1.Parent := StoragePage.Surface;
  L1.Top := Top;
  L1.Caption := 'Rohdaten im 1-Sekunden-Takt aufbewahren (Tage, 1–365):';
  RawDaysEdit := TNewEdit.Create(StoragePage);
  RawDaysEdit.Parent := StoragePage.Surface;
  RawDaysEdit.Top := L1.Top + L1.Height + ScaleY(4);
  RawDaysEdit.Width := ScaleX(80);
  RawDaysEdit.Text := GetParam('RawDays', '30');

  L2 := TNewStaticText.Create(StoragePage);
  L2.Parent := StoragePage.Surface;
  L2.Top := RawDaysEdit.Top + RawDaysEdit.Height + ScaleY(12);
  L2.Caption := 'Verlauf in 1-Minuten-Auflösung aufbewahren (Monate, 1–120):';
  AggMonthsEdit := TNewEdit.Create(StoragePage);
  AggMonthsEdit.Parent := StoragePage.Surface;
  AggMonthsEdit.Top := L2.Top + L2.Height + ScaleY(4);
  AggMonthsEdit.Width := ScaleX(80);
  AggMonthsEdit.Text := GetParam('AggMonths', '13');

  PinEdit := TNewEdit.Create(WizardForm);
  PinEdit.Parent := WizardForm.FinishedPage;
  PinEdit.ReadOnly := True;
  PinEdit.Visible := False;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = RolePage.ID then
    Result := RoleFixed
  else if PageID = ModePage.ID then
    Result := IsServer() or not ClientEnrolled
  else if PageID = ConnectPage.ID then
    // vorbelegt: nichts zu fragen; vorhandene Probe: nur bei „Neu registrieren“ oder „Proxy ändern“
    Result := IsServer() or (Prefilled and (Mode() = ModeNew)) or (Mode() = ModeKeep)
  else if (PageID = AddressPage.ID) or (PageID = AdminPage.ID) or (PageID = NotifyPage.ID) or (PageID = StoragePage.ID) then
    Result := IsClient() or ServerUpgrade;
end;

// Verbindung und Pin prüfen (verbraucht den Token nicht). Bei nicht erreichbarem Server: nachfragen.
function CheckConnection(): Boolean;
var
  ResultFile, Params, Pin, SeenPin, Err: String;
  Code: Integer;
begin
  Result := False;
  ResultFile := ExpandConstant('{tmp}\check.ini');
  if Mode() = ModeProxy then
    Params := 'check --use-state 1' + ProxyArg()
  else
  begin
    Pin := Trim(ConnectPage.Values[1]);
    Params := 'check --server ' + Quote(Servers());
    if Pin <> '' then
      Params := Params + ' --pin ' + Quote(Pin);
    Params := Params + ProxyArg();
  end;
  WizardForm.NextButton.Enabled := False;
  try
    Code := RunProbe(EnsureProbeExe(), Params, ResultFile);
  finally
    WizardForm.NextButton.Enabled := True;
  end;
  SeenPin := ResultValue(ResultFile, 'pin');
  Err := ResultValue(ResultFile, 'error');
  if Code = 0 then
  begin
    if (Mode() = ModeNew) and (Pin = '') then
    begin
      if MsgBox('Der Server meldet folgenden SPKI-Pin:' + #13#10#13#10 + SeenPin + #13#10#13#10 +
                'Stimmt er mit dem Web-UI (Verwaltung › Probes registrieren) überein?', mbConfirmation, MB_YESNO) = IDYES then
      begin
        ConnectPage.Values[1] := SeenPin;
        Result := True;
      end;
    end
    else
      Result := True;
  end
  else if (Code = 4) and (Mode() = ModeNew) and (Pin <> '') then
  begin
    // Server nicht erreichbar, aber alle Werte da: trotzdem installieren, der Dienst meldet sich später an
    Result := MsgBox('Der Wachtl-Server ist im Moment nicht erreichbar:' + #13#10#13#10 + Err + #13#10#13#10 +
                     'Trotzdem installieren? Die Probe meldet sich automatisch an, sobald der Server erreichbar ist.',
                     mbConfirmation, MB_YESNO) = IDYES;
  end
  else
  begin
    if Err = '' then
      Err := 'Prüfung fehlgeschlagen (Code ' + IntToStr(Code) + ').';
    MsgBox('Keine Verbindung zum Wachtl-Server:' + #13#10#13#10 + Err, mbError, MB_OK);
  end;
  CheckDone := Result;
end;

function ValidateServerPages(CurPageID: Integer): Boolean;
var
  HttpsPort, HttpPort, IperfPort: Integer;
begin
  Result := True;
  if CurPageID = AddressPage.ID then
  begin
    if Trim(AddressPage.Values[0]) = '' then
    begin
      MsgBox('Bitte mindestens einen Servernamen oder eine IP-Adresse angeben.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Pos('://', AddressPage.Values[0]) > 0) or (Pos('/', AddressPage.Values[0]) > 0) then
    begin
      MsgBox('Bitte nur Namen oder IP-Adressen angeben – ohne https:// und ohne Pfad.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if not IsNumberInRange(AddressPage.Values[1], 1, 65535) or not IsNumberInRange(AddressPage.Values[2], 0, 65535)
       or not IsNumberInRange(AddressPage.Values[3], 0, 65535) then
    begin
      MsgBox('Ports müssen Zahlen zwischen 1 und 65535 sein (HTTP und iperf3: 0 = aus).', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    HttpsPort := StrToInt(Trim(AddressPage.Values[1]));
    HttpPort := StrToInt(Trim(AddressPage.Values[2]));
    IperfPort := StrToInt(Trim(AddressPage.Values[3]));
    if HttpsPort = HttpPort then
    begin
      MsgBox('HTTP- und HTTPS-Port müssen verschieden sein.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (IperfPort > 0) and ((IperfPort = HttpsPort) or (IperfPort = HttpPort)) then
    begin
      MsgBox('Der iperf3-Port muss sich von den Web-Ports unterscheiden.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (IperfPort > 0) and PortInUse(IperfPort) then
    begin
      if MsgBox('Port ' + IntToStr(IperfPort) + ' wird bereits verwendet (läuft schon ein iperf3-Server?).' + #13#10 +
                'Die iperf3-Gegenstelle auf diesem Server abschalten?', mbConfirmation, MB_YESNO) = IDYES then
        AddressPage.Values[3] := '0'
      else
      begin
        Result := False;
        Exit;
      end;
    end;
    if PortInUse(HttpsPort) then
    begin
      MsgBox('Port ' + IntToStr(HttpsPort) + ' wird bereits verwendet (häufig durch IIS).' + #13#10 +
             'Bitte einen anderen HTTPS-Port wählen, z. B. 8443.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (HttpPort > 0) and PortInUse(HttpPort) then
    begin
      if MsgBox('Port ' + IntToStr(HttpPort) + ' wird bereits verwendet.' + #13#10 +
                'Die Umleitung von HTTP auf HTTPS abschalten?', mbConfirmation, MB_YESNO) = IDYES then
        AddressPage.Values[2] := '0'
      else
        Result := False;
    end;
  end
  else if CurPageID = AdminPage.ID then
  begin
    if AdminPage.Values[0] = '' then
    begin
      MsgBox('Bitte ein Passwort eingeben.', mbError, MB_OK);
      Result := False;
    end
    else if AdminPage.Values[0] <> AdminPage.Values[1] then
    begin
      MsgBox('Die Passwörter stimmen nicht überein.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = NotifyPage.ID then
  begin
    if (Trim(NotifyPage.Values[0]) <> '') and ((Pos('@', NotifyPage.Values[1]) = 0) or (Pos(':', NotifyPage.Values[2]) = 0)) then
    begin
      MsgBox('Für E-Mail bitte Absenderadresse und SMTP-Server als host:port angeben.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Trim(NotifyPage.Values[5]) <> '') and (Pos('https://', Lowercase(Trim(NotifyPage.Values[5]))) <> 1) then
    begin
      MsgBox('Der Teams-Webhook muss mit https:// beginnen.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = StoragePage.ID then
  begin
    if Length(RemoveBackslashUnlessRoot(Trim(StoragePage.Values[0]))) <= 3 then
    begin
      MsgBox('Bitte einen Unterordner wählen, nicht die Wurzel eines Laufwerks (z. B. D:\Wachtl).', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if not IsNumberInRange(RawDaysEdit.Text, 1, 365) or not IsNumberInRange(AggMonthsEdit.Text, 1, 120) then
    begin
      MsgBox('Aufbewahrung: Rohdaten 1–365 Tage, Verlauf 1–120 Monate.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = RolePage.ID then
  begin
    Role := RolePage.SelectedValueIndex;
    WizardForm.DirEdit.Text := GetDefaultDir('');
  end
  else if CurPageID = ConnectPage.ID then
  begin
    if (Mode() = ModeNew) and ((Servers() = '') or (Trim(ConnectPage.Values[2]) = '')) then
    begin
      MsgBox('Bitte Server-Adresse und Enrollment-Token angeben.', mbError, MB_OK);
      Result := False;
    end
    else if Pos('http://', Lowercase(Servers())) > 0 then
    begin
      MsgBox('Die Verbindung muss verschlüsselt sein: bitte https:// verwenden.', mbError, MB_OK);
      Result := False;
    end
    else if (ProxyValue() <> '') and (Pos('://', ProxyValue()) = 0) then
    begin
      MsgBox('Bitte den Proxy mit Schema angeben, z. B. http://proxy.kunde.local:3128', mbError, MB_OK);
      Result := False;
    end
    else
      Result := CheckConnection();
  end
  else if IsServer() then
    Result := ValidateServerPages(CurPageID);
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  if IsClient() then
  begin
    Result := 'Wachtl Probe' + NewLine + NewLine;
    case Mode() of
      ModeKeep:
        Result := Result + 'Programm aktualisieren, Registrierung bleibt erhalten.' + NewLine;
      ModeProxy:
        if ProxyValue() = '' then
          Result := Result + 'Proxy entfernen (direkte Verbindung).' + NewLine
        else
          Result := Result + 'Neuer Proxy: ' + ProxyValue() + NewLine;
    else
      begin
        if PreSite <> '' then
          Result := Result + 'Standort:' + NewLine + Space + PreSite + NewLine + NewLine;
        Result := Result + 'Server:' + NewLine + Space + Servers() + NewLine;
        if ProxyValue() <> '' then
          Result := Result + Space + 'über Proxy ' + ProxyValue() + NewLine;
        Result := Result + NewLine + 'Name im Dashboard:' + NewLine + Space + Hostname + NewLine;
      end;
    end;
    Result := Result + NewLine + 'Dienst „Wachtl Netzwerk-Probe“ (startet automatisch, auch ohne Anmeldung).';
  end
  else
  begin
    Result := 'Wachtl-Server' + NewLine + NewLine;
    if ServerUpgrade then
      Result := Result + 'Update einer vorhandenen Installation' + NewLine +
        Space + 'Datenordner: ' + ExistingDataDir + NewLine +
        Space + 'Daten, Zertifikat und Einstellungen bleiben erhalten.' + NewLine
    else
    begin
      Result := Result + 'Adresse:' + NewLine + Space + GetUrl('') + NewLine +
        Space + 'Zertifikat für: ' + AddressPage.Values[0] + ' und die IP-Adressen dieses Servers' + NewLine;
      if Trim(AddressPage.Values[2]) <> '0' then
        Result := Result + Space + 'HTTP-Port ' + Trim(AddressPage.Values[2]) + ' leitet auf HTTPS um' + NewLine;
      Result := Result + NewLine + 'Datenordner:' + NewLine + Space + StoragePage.Values[0] + NewLine +
        Space + 'Rohdaten ' + RawDaysEdit.Text + ' Tage, Verlauf ' + AggMonthsEdit.Text + ' Monate' + NewLine +
        NewLine + 'Benachrichtigungen:' + NewLine;
      if Trim(NotifyPage.Values[0]) <> '' then
        Result := Result + Space + 'E-Mail an ' + NotifyPage.Values[0] + NewLine;
      if Trim(NotifyPage.Values[5]) <> '' then
        Result := Result + Space + 'Microsoft Teams' + NewLine;
      if (Trim(NotifyPage.Values[0]) = '') and (Trim(NotifyPage.Values[5]) = '') then
        Result := Result + Space + 'keine (später im Web-UI einstellbar)' + NewLine;
    end;
    Result := Result + NewLine + 'Es werden eingerichtet: Windows-Dienst „Wachtl Server“, Firewall-Regeln, ' +
      'tägliche Sicherung um 02:15 Uhr.';
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if (CurPageID = wpReady) and IsClient() and Prefilled and (Mode() = ModeNew) then
  begin
    WizardForm.PageNameLabel.Caption := 'Wachtl Probe installieren';
    if PreSite <> '' then
      WizardForm.PageDescriptionLabel.Caption := 'Für den Standort „' + PreSite + '“ ist alles vorbereitet.'
    else
      WizardForm.PageDescriptionLabel.Caption := 'Alles ist vorbereitet.';
    WizardForm.ReadyLabel.Caption := 'Klicken Sie auf „Installieren“. Mehr ist nicht zu tun.';
  end
  else if CurPageID = wpFinished then
  begin
    if IsClient() then
    begin
      if ClientOk then
      begin
        WizardForm.FinishedHeadingLabel.Caption := 'Wachtl Probe läuft';
        if EnrollDeferred then
          WizardForm.FinishedLabel.Caption := 'Die Probe ist installiert. Der Wachtl-Server war gerade nicht erreichbar – ' +
            'sie meldet sich automatisch an, sobald er erreichbar ist.' + #13#10#13#10 + ClientNote
        else if Mode() = ModeNew then
          WizardForm.FinishedLabel.Caption := 'Die Probe „' + Hostname + '“ ist registriert' +
            ' und erscheint in den nächsten 30 Sekunden im Dashboard.'
        else
          WizardForm.FinishedLabel.Caption := 'Die Probe wurde aktualisiert und läuft wieder.';
      end
      else
      begin
        WizardForm.FinishedHeadingLabel.Caption := 'Probe nicht gestartet';
        WizardForm.FinishedLabel.Caption := ClientError + #13#10#13#10 + 'Setup nach dem Beheben einfach erneut starten.';
      end;
      WizardForm.FinishedLabel.AdjustHeight();
    end
    else if ServerOk then
    begin
      WizardForm.FinishedHeadingLabel.Caption := 'Wachtl Server läuft';
      WizardForm.FinishedLabel.Caption :=
        'Adresse: ' + ResultUrl + #13#10#13#10 +
        'Anmeldung als „admin“ mit dem gewählten Passwort.' + #13#10#13#10 +
        'Probes installieren: im Web-UI unter Verwaltung › Probes registrieren „Setup herunterladen“. ' +
        'SPKI-Pin (auch in setup-info.txt):';
      WizardForm.FinishedLabel.AdjustHeight();
      PinEdit.Left := WizardForm.FinishedLabel.Left;
      PinEdit.Top := WizardForm.FinishedLabel.Top + WizardForm.FinishedLabel.Height + ScaleY(8);
      PinEdit.Width := WizardForm.FinishedLabel.Width;
      PinEdit.Text := ResultPin;
      PinEdit.Visible := True;
      WizardForm.RunList.Top := PinEdit.Top + PinEdit.Height + ScaleY(16);
    end
    else
    begin
      WizardForm.FinishedHeadingLabel.Caption := 'Einrichtung nicht abgeschlossen';
      WizardForm.FinishedLabel.Caption :=
        'Die Programmdateien sind installiert, der Server läuft aber noch nicht.' + #13#10#13#10 +
        ResultError + #13#10#13#10 + 'Protokoll: ' + GetDataDir('') + '\logs\setup.log';
      WizardForm.FinishedLabel.AdjustHeight();
    end;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := '';
  // Tray-Symbole laufen weiter: laufende wachtl-tray.exe umbenennen statt beenden, die neue kommt daneben
  DeleteFile(ExpandConstant('{app}\wachtl-tray.old'));
  RenameFile(ExpandConstant('{app}\wachtl-tray.exe'), ExpandConstant('{app}\wachtl-tray.old'));
  // laufenden Dienst vor dem Kopieren stoppen, sonst sind Dateien gesperrt
  if IsClient() then
    RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName)
  else
    RunHidden(ExpandConstant('{sys}\net.exe'), 'stop WachtlServer');
end;

// ============================================================ Probe einrichten

procedure EnrollClient();
var
  ResultFile, Err: String;
  Code: Integer;
begin
  if (Mode() <> ModeNew) or EnrollDone then
    Exit;
  if (Servers() = '') or (Trim(ConnectPage.Values[1]) = '') or (Trim(ConnectPage.Values[2]) = '') then
  begin
    ClientError := 'Server, Pin oder Token fehlen.';
    Exit;
  end;
  WizardForm.StatusLabel.Caption := 'Probe wird am Wachtl-Server angemeldet …';
  ResultFile := ExpandConstant('{tmp}\enroll.ini');
  Code := RunProbe(ExpandConstant('{app}\wachtl-probe.exe'), EnrollParams(), ResultFile);
  if Code = 0 then
  begin
    SiteName := ResultValue(ResultFile, 'site');
    EnrollDone := True;
  end
  else if Code = ExitEnrollDeferred then
  begin
    EnrollDone := True;
    EnrollDeferred := True;
    ClientNote := ResultValue(ResultFile, 'error');
    Log('Wachtl Probe: Server nicht erreichbar, Registrierung wird nachgeholt: ' + ClientNote);
  end
  else
  begin
    Err := ResultValue(ResultFile, 'error');
    if Err = '' then
      Err := 'Registrierung fehlgeschlagen (Code ' + IntToStr(Code) + ').';
    if Code = 5 then
      Err := Err + #13#10#13#10 + 'Ist der Token abgelaufen oder verbraucht? Im Web-UI ein neues Setup herunterladen.';
    ClientError := Err;
  end;
end;

procedure InstallClientService();
var
  Sc, Exe, Dir: String;
  Code, I: Integer;
begin
  Sc := ExpandConstant('{sys}\sc.exe');
  Exe := ExpandConstant('{app}\wachtl-probe.exe');
  Dir := ProbeDataDir();
  WizardForm.StatusLabel.Caption := 'Dienst wird eingerichtet …';

  if Mode() = ModeProxy then
    if RunHidden(Exe, 'configure --proxy ' + Quote(ProxyValue()) + ' --out ' + Quote(ExpandConstant('{tmp}\configure.ini'))) <> 0 then
    begin
      ClientError := 'Proxy konnte nicht gespeichert werden.';
      Exit;
    end;

  if not ServiceExists then
    if RunHidden(Sc, 'create ' + ServiceName + ' binPath= "\"' + Exe + '\"" start= delayed-auto obj= ' +
                 Quote(ServiceAccount) + ' DisplayName= "Wachtl Netzwerk-Probe"') <> 0 then
    begin
      ClientError := 'Der Dienst konnte nicht angelegt werden (sc create).';
      Exit;
    end;
  RunHidden(Sc, 'config ' + ServiceName + ' start= delayed-auto obj= ' + Quote(ServiceAccount));
  RunHidden(Sc, 'description ' + ServiceName + ' "Misst Latenz, Paketverlust, Pfade und Bandbreite und meldet sie an den Wachtl-Server."');
  RunHidden(Sc, 'failure ' + ServiceName + ' reset= 86400 actions= restart/10000/restart/30000/restart/60000');
  RunHidden(Sc, 'failureflag ' + ServiceName + ' 1');

  // Token und Puffer: nur SYSTEM, Administratoren und das Dienstkonto (SIDs = sprachunabhängig)
  ForceDirectories(Dir);
  RunHidden(ExpandConstant('{sys}\icacls.exe'), Quote(Dir) + ' /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F ' +
            '/grant:r *S-1-5-32-544:(OI)(CI)F /grant:r ' + Quote(ServiceAccount + ':(OI)(CI)M') + ' /C /Q');
  RunHidden(ExpandConstant('{sys}\icacls.exe'), Quote(Dir + '\*') + ' /reset /T /C /Q');
  // Logdateien dürfen alle Benutzer lesen (Startmenü-Verknüpfung), Token und Puffer nicht
  ForceDirectories(Dir + '\logs');
  RunHidden(ExpandConstant('{sys}\icacls.exe'), Quote(Dir + '\logs') + ' /grant *S-1-5-32-545:(OI)(CI)RX /C /Q');
  // iperf3-Gegenstelle: nur iperf3.exe darf eingehende Verbindungen annehmen; ob sie läuft, entscheidet das Web-UI
  RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule "name=Wachtl Probe iperf3"');
  RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall add rule "name=Wachtl Probe iperf3" dir=in action=allow ' +
            '"program=' + ExpandConstant('{app}\iperf3\iperf3.exe') + '" enable=yes profile=any');
  // RTP-Reflektor (Sprachtests anderer Probes): nur der Wachtl-Dienst, nur UDP; ob er läuft, entscheidet das Web-UI
  RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall delete rule "name=Wachtl Probe RTP"');
  RunHidden(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall add rule "name=Wachtl Probe RTP" dir=in action=allow ' +
            'protocol=UDP "program=' + ExpandConstant('{app}\wachtl-probe.exe') + '" enable=yes profile=any');
  // Neu registriert: alte, noch nicht gesendete Messwerte gehören zur alten Registrierung
  if ClientEnrolled and EnrollDone then
  begin
    DeleteFile(Dir + '\buffer.db');
    DeleteFile(Dir + '\buffer.db-wal');
    DeleteFile(Dir + '\buffer.db-shm');
    DeleteFile(Dir + '\config.json');
  end;

  WizardForm.StatusLabel.Caption := 'Dienst wird gestartet …';
  RunHidden(Sc, 'start ' + ServiceName);
  Code := 1;
  for I := 1 to 15 do
  begin
    Sleep(1000);
    // Systemordner enthält keine Leerzeichen – ohne Anführungszeichen, sonst verschluckt cmd.exe die Pipe
    Code := RunHidden(ExpandConstant('{cmd}'), '/C ' + Sc + ' query ' + ServiceName + ' | find "RUNNING" >nul');
    if Code = 0 then
      Break;
  end;
  if Code <> 0 then
    ClientError := 'Der Dienst wurde eingerichtet, läuft aber nicht. Details: ' + Dir + '\logs'
  else
    ClientOk := True;
end;

// Server-Zertifikat unter „Vertrauenswürdige Stammzertifizierungsstellen“ ablegen, damit Browser auf dem PC
// das Web-UI ohne Warnung öffnen. Nur ein Komfort: schlägt es fehl, läuft die Probe trotzdem (sie prüft den Pin).
procedure TrustServerCertificate();
var
  ResultFile: String;
  Code: Integer;
begin
  if EnrollDeferred then
  begin
    Log('Wachtl Probe: Server nicht erreichbar – Zertifikat wird beim nächsten Setup oder Update abgelegt.');
    Exit;
  end;
  WizardForm.StatusLabel.Caption := 'Server-Zertifikat wird als vertrauenswürdig hinterlegt …';
  ResultFile := ExpandConstant('{tmp}	rust.ini');
  Code := RunProbe(ExpandConstant('{app}\wachtl-probe.exe'), 'trust', ResultFile);
  if Code = 0 then
    Log('Wachtl Probe: Zertifikat: ' + ResultValue(ResultFile, 'outcome') + ' ' + ResultValue(ResultFile, 'thumbprint'))
  else
    Log('Wachtl Probe: Zertifikat nicht abgelegt (Code ' + IntToStr(Code) + '): ' + ResultValue(ResultFile, 'error'));
end;

// Täglich und nach dem Start als SYSTEM prüfen: holt nach, was beim Setup nicht ging (Server offline), und
// übernimmt eine neu ausgestellte Wachtl-CA (z. B. nach neuen Servernamen). Der Dienst selbst darf das nicht.
procedure ScheduleTrustTask();
var
  Script: String;
begin
  Script := '$a = New-ScheduledTaskAction -Execute ''' + ExpandConstant('{app}\wachtl-probe.exe') + ''' -Argument ''trust''; ' +
    '$t = @((New-ScheduledTaskTrigger -Daily -At 12:00), (New-ScheduledTaskTrigger -AtStartup)); ' +
    '$t[1].Delay = ''PT5M''; ' +
    '$s = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries ' +
    '-ExecutionTimeLimit (New-TimeSpan -Minutes 10); ' +
    'Register-ScheduledTask -TaskName ''Wachtl Zertifikat'' -Action $a -Trigger $t -Settings $s -User ''SYSTEM'' ' +
    '-RunLevel Highest -Force | Out-Null';
  if RunHidden(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'),
               '-NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Script + '"') <> 0 then
    Log('Wachtl Probe: geplante Aufgabe „Wachtl Zertifikat“ konnte nicht angelegt werden.');
end;

procedure SetupClient();
begin
  EnrollClient();
  if ClientError <> '' then
  begin
    Log('Wachtl Probe: ' + ClientError);
    Exit;
  end;
  if not ClientEnrolled and not EnrollDone then
  begin
    ClientError := 'Die Probe ist nicht registriert.';
    Exit;
  end;
  InstallClientService();
  if not ClientOk then
    Log('Wachtl Probe: ' + ClientError)
  else
  begin
    TrustServerCertificate();
    ScheduleTrustTask();
  end;
end;

// ============================================================ Server einrichten

function WriteInputFile(const FileName: String): Boolean;
var
  L: TArrayOfString;
begin
  SetArrayLength(L, 21);
  L[0] := '{';
  L[1] := JsonPair('hostnames', AddressPage.Values[0], False);
  L[2] := '  "https_port": ' + Trim(AddressPage.Values[1]) + ',';
  L[3] := '  "http_port": ' + Trim(AddressPage.Values[2]) + ',';
  // RTP-Reflektor (Sprachtest, UDP) ohne eigene Seite im Assistenten: Standard 5004, unbeaufsichtigt /RtpPort=
  L[4] := '  "iperf_port": ' + Trim(AddressPage.Values[3]) + ',' + #13#10 +
          '  "rtp_port": ' + IntToStr(StrToIntDef(GetParam('RtpPort', '5004'), 5004)) + ',';
  L[5] := JsonPair('data_dir', GetDataDir(''), False);
  L[6] := JsonPair('install_dir', ExpandConstant('{app}'), False);
  L[7] := JsonPair('admin_password', AdminPage.Values[0], False);
  L[8] := '  "raw_days": ' + Trim(RawDaysEdit.Text) + ',';
  L[9] := '  "agg_months": ' + Trim(AggMonthsEdit.Text) + ',';
  L[10] := '  "notify": {';
  L[11] := '  ' + JsonPair('email_to', Trim(NotifyPage.Values[0]), False);
  L[12] := '  ' + JsonPair('email_from', Trim(NotifyPage.Values[1]), False);
  L[13] := '  ' + JsonPair('smtp_smarthost', Trim(NotifyPage.Values[2]), False);
  L[14] := '  ' + JsonPair('smtp_username', Trim(NotifyPage.Values[3]), False);
  L[15] := '  ' + JsonPair('smtp_password', NotifyPage.Values[4], False);
  L[16] := '  ' + JsonPair('smtp_require_tls', 'true', False);
  L[17] := '  ' + JsonPair('teams_webhook_url', Trim(NotifyPage.Values[5]), True);
  L[18] := '  }';
  L[19] := '}';
  L[20] := '';
  Result := SaveStringsToUTF8File(FileName, L, False);
end;

procedure SetupServer();
var
  InputFile, ResultFile, Params, Python, LogHint: String;
  Code: Integer;
begin
  Python := ExpandConstant('{app}\python\python.exe');
  ResultFile := ExpandConstant('{tmp}\wachtl-result.ini');
  if ServerUpgrade then
    Params := '-m wachtl.win.installer upgrade --data "' + ExistingDataDir + '" --result "' + ResultFile + '"'
  else
  begin
    InputFile := ExpandConstant('{tmp}\wachtl-setup.json');
    if not WriteInputFile(InputFile) then
    begin
      ResultError := 'Eingaben konnten nicht gespeichert werden.';
      Exit;
    end;
    Params := '-m wachtl.win.installer install --input "' + InputFile + '" --result "' + ResultFile + '"';
  end;

  WizardForm.StatusLabel.Caption := 'Server wird eingerichtet: Zertifikat, Datenbank, Dienst, Firewall …';
  WizardForm.FilenameLabel.Caption := 'Das kann bis zu drei Minuten dauern.';
  WizardForm.ProgressGauge.Style := npbstMarquee;
  try
    if not Exec(Python, Params, ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, Code) then
      Code := -1;
  finally
    WizardForm.ProgressGauge.Style := npbstNormal;
    if InputFile <> '' then
      DeleteFile(InputFile);  // enthält Passwörter
  end;

  ServerOk := (Code = 0) and (GetIniString('result', 'ok', '0', ResultFile) = '1');
  ResultUrl := GetIniString('result', 'url', '', ResultFile);
  ResultPin := GetIniString('result', 'pin', '', ResultFile);
  ResultError := GetIniString('result', 'error', '', ResultFile);
  StringChangeEx(ResultError, '\n', #13#10, True);
  if ServerOk then
    RegWriteStringValue(HKLM, ServerRegKey, 'Configured', '1')
  else
  begin
    if ResultError = '' then
      ResultError := 'Die Einrichtung wurde mit Code ' + IntToStr(Code) + ' beendet.';
    LogHint := GetDataDir('') + '\logs\setup.log';
    if not WizardSilent() then
      MsgBox('Die Einrichtung des Servers ist fehlgeschlagen:' + #13#10#13#10 + ResultError + #13#10#13#10 +
             'Protokoll: ' + LogHint + #13#10#13#10 +
             'Nach dem Beheben der Ursache das Setup einfach erneut ausführen.', mbError, MB_OK);
    Log('Wachtl-Einrichtung fehlgeschlagen: ' + ResultError);
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Code: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    if IsClient() then
      SetupClient()
    else
      SetupServer();
    { Tray-Symbol gleich für den angemeldeten Benutzer zeigen. Unbeaufsichtigt läuft das Setup meist als SYSTEM
      (Softwareverteilung) – dann erscheint es ab der nächsten Anmeldung über den Autostart. }
    if TrayWanted() and not WizardSilent() and ((IsClient() and ClientOk) or (IsServer() and ServerOk)) then
      ExecAsOriginalUser(ExpandConstant('{app}\wachtl-tray.exe'), '', '', SW_SHOWNORMAL, ewNoWait, Code);
  end;
end;

function GetCustomSetupExitCode(): Integer;
begin
  if (IsClient() and ClientOk) or (IsServer() and ServerOk) then
    Result := 0
  else
    Result := 10;
end;

// ============================================================ Deinstallation

function InitializeUninstall(): Boolean;
begin
  // jede Rolle hat ihren eigenen Deinstaller; der Server erkennt sich am eingebetteten Python
  UninstallServer := FileExists(ExpandConstant('{app}\python\python.exe'));
  if not RegQueryStringValue(HKLM, ServerRegKey, 'DataDir', UninstallDataDir) then
    UninstallDataDir := '';
  Result := True;
end;

// Unbeaufsichtigt: /REMOVEDATA löscht beim Server auch den Datenordner (Datenbank, Schlüssel, Sicherungen)
function RemoveDataParam(): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/REMOVEDATA') = 0 then
      Result := True;
end;

function ClientLeftovers(): String;
var
  Code: Integer;
begin
  Result := '';
  if Exec(ExpandConstant('{sys}\sc.exe'), 'query Wachtl', '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0) then
    Result := Result + '- Dienst „Wachtl“ ist noch vorhanden (Neustart nötig?)' + #13#10;
  if Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall show rule "name=Wachtl Probe iperf3"', '', SW_HIDE,
          ewWaitUntilTerminated, Code) and (Code = 0) then
    Result := Result + '- Firewall-Regel „Wachtl Probe iperf3“ ist noch vorhanden' + #13#10;
  if Exec(ExpandConstant('{sys}\netsh.exe'), 'advfirewall firewall show rule "name=Wachtl Probe RTP"', '', SW_HIDE,
          ewWaitUntilTerminated, Code) and (Code = 0) then
    Result := Result + '- Firewall-Regel „Wachtl Probe RTP“ ist noch vorhanden' + #13#10;
  if Exec(ExpandConstant('{sys}\schtasks.exe'), '/Query /TN "Wachtl Zertifikat"', '', SW_HIDE, ewWaitUntilTerminated, Code)
     and (Code = 0) then
    Result := Result + '- Geplante Aufgabe „Wachtl Zertifikat“ ist noch vorhanden' + #13#10;
end;

procedure UninstallClientDone();
var
  Dir, Ini, Note, Rest: String;
begin
  Dir := ProbeDataDir();
  Ini := Dir + '\deregister.ini';
  Note := '';
  if FileExists(Ini) and (GetIniString('result', 'deregistered', '', Ini) <> '1') then
    Note := 'Der Wachtl-Server war nicht erreichbar – die Probe bitte im Dashboard löschen, ' +
            'damit ihr Eintrag verschwindet. (Ihr Token wurde auf diesem PC gelöscht.)';
  DeleteFile(Ini);
  if DirExists(Dir) then
    if UninstallSilent() or
       (MsgBox('Auch gepufferte Messwerte und Logdateien löschen?' + #13#10#13#10 + Dir + #13#10#13#10 +
               'Das Token der Probe ist bereits gelöscht. Bei „Nein“ bleiben nur Puffer und Logs zur Fehlersuche liegen.',
               mbConfirmation, MB_YESNO or MB_DEFBUTTON1) = IDYES) then
      DelTree(Dir, True, True, True);
  Rest := ClientLeftovers();
  if Rest <> '' then
    Log('Wachtl Probe: nach der Deinstallation noch vorhanden:' + #13#10 + Rest);
  if not UninstallSilent() then
  begin
    if Rest <> '' then
      MsgBox('Nicht alles konnte entfernt werden:' + #13#10 + Rest, mbError, MB_OK)
    else if Note <> '' then
      MsgBox(Note, mbInformation, MB_OK);
  end;
end;

procedure UninstallServerDone();
var
  ResultIni, Leftovers: String;
begin
  ResultIni := ExpandConstant('{commonappdata}\Wachtl Server Deinstallation.ini');
  Leftovers := '';
  if FileExists(ResultIni) then
  begin
    Leftovers := GetIniString('result', 'error', '', ResultIni);
    StringChangeEx(Leftovers, '\n', #13#10, True);
    DeleteFile(ResultIni);
  end;
  if Leftovers <> '' then
  begin
    Log('Wachtl Server: nach der Deinstallation noch vorhanden: ' + Leftovers);
    if not UninstallSilent() then
      MsgBox('Nicht alles konnte entfernt werden:' + #13#10#13#10 + Leftovers, mbError, MB_OK);
  end;
  if (UninstallDataDir <> '') and DirExists(UninstallDataDir) then
  begin
    if UninstallSilent() then
    begin
      if RemoveDataParam() then
        DelTree(UninstallDataDir, True, True, True);
    end
    else if MsgBox('Sollen auch alle Daten gelöscht werden?' + #13#10#13#10 + UninstallDataDir + #13#10#13#10 +
                'Datenbank, Messwerte, Zertifikat mit privatem Schlüssel und Sicherungen gehen dabei verloren. ' +
                'Bei „Nein“ bleiben sie für eine spätere Neuinstallation erhalten – dann den Ordner sicher verwahren.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(UninstallDataDir, True, True, True);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
  if UninstallServer then
    UninstallServerDone()
  else
    UninstallClientDone();
end;
