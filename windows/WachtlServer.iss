; Wachtl Server – Setup-Assistent (Inno Setup 6)
; Bauen: siehe build-server.ps1 (übergibt AppVersion und BuildDir)
;
; Unbeaufsichtigte Installation, z. B.:
;   WachtlServerSetup-0.3.0.exe /VERYSILENT /SUPPRESSMSGBOXES /Hostnames="wachtl.kunde.local,10.0.0.5"
;       /AdminPassword="…" [/HttpsPort=443] [/HttpPort=80] [/IperfPort=5201] [/DataDir="D:\Wachtl"] [/RawDays=30] [/AggMonths=13]
;       [/EmailTo=… /EmailFrom=… /SmtpHost=mail:587 /SmtpUser=… /SmtpPassword=…] [/TeamsUrl=https://…]

#ifndef AppVersion
  #define AppVersion "0.3.0"
#endif
#ifndef BuildDir
  #define BuildDir "..\build\server"
#endif

[Setup]
AppId={{B7E2C1A4-3D5F-4C8E-9A61-2F7D0E9B4C13}
AppName=Wachtl Server
AppVersion={#AppVersion}
AppVerName=Wachtl Server {#AppVersion}
AppPublisher=Wachtl
DefaultDirName={autopf}\Wachtl Server
DefaultGroupName=Wachtl Server
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.14393
OutputBaseFilename=WachtlServerSetup-{#AppVersion}
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
UninstallDisplayName=Wachtl Server
UninstallDisplayIcon={app}\wachtl.ico
VersionInfoVersion={#AppVersion}

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Files]
Source: "{#BuildDir}\python\*"; DestDir: "{app}\python"; Flags: recursesubdirs ignoreversion
Source: "{#BuildDir}\app\*"; DestDir: "{app}\app"; Flags: recursesubdirs ignoreversion
Source: "{#BuildDir}\bin\*"; DestDir: "{app}\bin"; Flags: recursesubdirs ignoreversion
Source: "{#BuildDir}\service\WachtlServer.exe"; DestDir: "{app}\service"; Flags: ignoreversion
Source: "{#BuildDir}\wachtl-server.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "wachtl-status.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\THIRD-PARTY.txt"; DestDir: "{app}"; Flags: ignoreversion
Source: "assets\wachtl.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#BuildDir}\docs\*"; DestDir: "{app}\docs"; Flags: recursesubdirs ignoreversion
Source: "{#BuildDir}\probe\*"; DestDir: "{app}\probe"; Flags: recursesubdirs ignoreversion skipifsourcedoesntexist

[INI]
Filename: "{group}\Wachtl Dashboard.url"; Section: "InternetShortcut"; Key: "URL"; String: "{code:GetUrl}"

[Icons]
Name: "{group}\Wachtl Status"; Filename: "{app}\wachtl-status.cmd"; WorkingDir: "{app}"; IconFilename: "{app}\wachtl.ico"
Name: "{group}\Zugangsdaten (setup-info.txt)"; Filename: "{code:GetDataDir}\setup-info.txt"
Name: "{group}\Logdateien"; Filename: "{code:GetDataDir}\logs"
Name: "{group}\Probe-Paket"; Filename: "{app}\probe"; Check: ProbeIncluded

[Registry]
Root: HKLM; Subkey: "Software\Wachtl Server"; ValueType: string; ValueName: "DataDir"; ValueData: "{code:GetDataDir}"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Wachtl Server"; ValueType: string; ValueName: "Version"; ValueData: "{#AppVersion}"

[Run]
Filename: "{code:GetUrl}"; Description: "Wachtl im Browser öffnen"; Flags: postinstall shellexec nowait skipifsilent; Check: SetupSucceeded
Filename: "notepad.exe"; Parameters: """{code:GetDataDir}\setup-info.txt"""; Description: "Zugangsdaten und SPKI-Pin anzeigen"; Flags: postinstall nowait skipifsilent unchecked; Check: SetupSucceeded

[UninstallRun]
; Dienst (samt Server-Probe), Firewall-Regeln und geplante Sicherung entfernen, danach prüfen, dass kein Port offen bleibt
Filename: "{app}\python\python.exe"; Parameters: "-m wachtl.win.installer uninstall --result ""{commonappdata}\Wachtl Server Deinstallation.ini"""; WorkingDir: "{app}"; Flags: runhidden waituntilterminated; RunOnceId: "WachtlUninstall"

[UninstallDelete]
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\python"
Type: filesandordirs; Name: "{app}\service"
Type: files; Name: "{app}\datadir.txt"
Type: files; Name: "{group}\Wachtl Dashboard.url"

[Code]
const
  RegKey = 'Software\Wachtl Server';

var
  AddressPage, AdminPage, NotifyPage: TInputQueryWizardPage;
  StoragePage: TInputDirWizardPage;
  RawDaysEdit, AggMonthsEdit: TNewEdit;
  PinEdit: TNewEdit;
  IsUpgrade, SetupOk: Boolean;
  ExistingDataDir, ResultUrl, ResultPin, ResultError, UninstallDataDir: String;

{ ---------- Hilfen ---------- }

function GetParam(const Name, Default: String): String;
begin
  Result := ExpandConstant('{param:' + Name + '|}');
  if Result = '' then
    Result := Default;
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

function IsNumberInRange(const S: String; Lo, Hi: Integer): Boolean;
var
  V: Integer;
begin
  V := StrToIntDef(Trim(S), -1);
  Result := (V >= Lo) and (V <= Hi) and (IntToStr(V) = Trim(S));
end;

{ Liest einen Wert aus der vorhandenen Konfiguration (für Updates). }
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

{ Prüft mit netstat, ob ein TCP-Port bereits lauscht. }
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

{ ---------- Werte für [Files]/[Run]/[Icons] ---------- }

function GetDataDir(Param: String): String;
begin
  if IsUpgrade then
    Result := ExistingDataDir
  else
    Result := RemoveBackslash(Trim(StoragePage.Values[0]));
end;

function GetUrl(Param: String): String;
var
  Port: String;
begin
  if ResultUrl <> '' then
    Result := ResultUrl
  else if IsUpgrade then
    Result := ReadEnvValue('WACHTL_PUBLIC_URL')
  else
  begin
    Port := Trim(AddressPage.Values[1]);
    Result := 'https://' + FirstHostname(AddressPage.Values[0]);
    if Port <> '443' then
      Result := Result + ':' + Port;
  end;
end;

function SetupSucceeded(): Boolean;
begin
  Result := SetupOk;
end;

function ProbeIncluded(): Boolean;
begin
  Result := DirExists(ExpandConstant('{app}\probe'));
end;

{ ---------- Assistent ---------- }

function InitializeSetup(): Boolean;
begin
  { Update nur, wenn eine frühere Einrichtung erfolgreich war – sonst alle Seiten erneut zeigen }
  IsUpgrade := RegQueryStringValue(HKLM, RegKey, 'DataDir', ExistingDataDir)
               and RegValueExists(HKLM, RegKey, 'Configured')
               and FileExists(ExistingDataDir + '\config\wachtl.env');
  Result := True;
end;

procedure InitializeWizard();
var
  L1, L2: TNewStaticText;
  Top: Integer;
begin
  AddressPage := CreateInputQueryPage(wpSelectDir,
    'Server-Adresse', 'Unter welcher Adresse erreichen Probes und Browser diesen Server?',
    'Servernamen und IP-Adressen mit Komma trennen. Der erste Eintrag wird die Adresse im Browser; ' +
    'alle Einträge kommen in das Zertifikat.');
  AddressPage.Add('Servernamen / IP-Adressen:', False);
  AddressPage.Add('HTTPS-Port:', False);
  AddressPage.Add('HTTP-Port für die Umleitung auf HTTPS (0 = aus):', False);
  AddressPage.Add('iperf3-Port für Bandbreitenmessungen der Probes (TCP und UDP, 0 = aus):', False);
  AddressPage.Values[0] := GetParam('Hostnames', DefaultHostnames());
  AddressPage.Values[1] := GetParam('HttpsPort', '443');
  AddressPage.Values[2] := GetParam('HttpPort', '80');
  AddressPage.Values[3] := GetParam('IperfPort', '5201');

  AdminPage := CreateInputQueryPage(AddressPage.ID,
    'Administrator', 'Passwort für die Anmeldung als „admin“ im Web-UI',
    'Mindestens 12 Zeichen. Weitere Benutzer legen Sie später im Web-UI an.');
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

  { Pin auf der letzten Seite zum Kopieren }
  PinEdit := TNewEdit.Create(WizardForm);
  PinEdit.Parent := WizardForm.FinishedPage;
  PinEdit.ReadOnly := True;
  PinEdit.Visible := False;
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := IsUpgrade and ((PageID = AddressPage.ID) or (PageID = AdminPage.ID) or
                           (PageID = NotifyPage.ID) or (PageID = StoragePage.ID));
end;

function NextButtonClick(CurPageID: Integer): Boolean;
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
    if HttpsPort = HttpPort then
    begin
      MsgBox('HTTP- und HTTPS-Port müssen verschieden sein.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    IperfPort := StrToInt(Trim(AddressPage.Values[3]));
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
    if Length(AdminPage.Values[0]) < 12 then
    begin
      MsgBox('Das Passwort muss mindestens 12 Zeichen lang sein.', mbError, MB_OK);
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
    if Trim(NotifyPage.Values[0]) <> '' then
    begin
      if (Pos('@', NotifyPage.Values[1]) = 0) or (Pos(':', NotifyPage.Values[2]) = 0) then
      begin
        MsgBox('Für E-Mail bitte Absenderadresse und SMTP-Server als host:port angeben.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
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

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine;
  if IsUpgrade then
    Result := Result + 'Update einer vorhandenen Installation' + NewLine +
      Space + 'Datenordner: ' + ExistingDataDir + NewLine +
      Space + 'Daten, Zertifikat und Einstellungen bleiben erhalten.' + NewLine
  else
  begin
    Result := Result + 'Adresse:' + NewLine + Space + GetUrl('') + NewLine +
      Space + 'Zertifikat für: ' + AddressPage.Values[0] + NewLine;
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

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Code: Integer;
begin
  { Laufenden Dienst vor dem Kopieren stoppen, sonst sind Dateien gesperrt }
  Exec(ExpandConstant('{sys}\net.exe'), 'stop WachtlServer', '', SW_HIDE, ewWaitUntilTerminated, Code);
  Result := '';
end;

function WriteInputFile(const FileName: String): Boolean;
var
  L: TArrayOfString;
begin
  SetArrayLength(L, 21);
  L[0] := '{';
  L[1] := JsonPair('hostnames', AddressPage.Values[0], False);
  L[2] := '  "https_port": ' + Trim(AddressPage.Values[1]) + ',';
  L[3] := '  "http_port": ' + Trim(AddressPage.Values[2]) + ',';
  L[4] := '  "iperf_port": ' + Trim(AddressPage.Values[3]) + ',';
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

procedure RunServerSetup();
var
  InputFile, ResultFile, Params, Python, LogHint: String;
  Code: Integer;
begin
  Python := ExpandConstant('{app}\python\python.exe');
  ResultFile := ExpandConstant('{tmp}\wachtl-result.ini');
  if IsUpgrade then
    Params := '-m wachtl.win.installer upgrade --data "' + ExistingDataDir + '" --result "' + ResultFile + '"'
  else
  begin
    InputFile := ExpandConstant('{tmp}\wachtl-setup.json');
    if not WriteInputFile(InputFile) then
    begin
      ResultError := 'Eingaben konnten nicht gespeichert werden.';
      SetupOk := False;
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
      DeleteFile(InputFile);  { enthält Passwörter }
  end;

  SetupOk := (Code = 0) and (GetIniString('result', 'ok', '0', ResultFile) = '1');
  ResultUrl := GetIniString('result', 'url', '', ResultFile);
  ResultPin := GetIniString('result', 'pin', '', ResultFile);
  ResultError := GetIniString('result', 'error', '', ResultFile);
  StringChangeEx(ResultError, '\n', #13#10, True);
  if SetupOk then
    RegWriteStringValue(HKLM, RegKey, 'Configured', '1');
  if not SetupOk then
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
begin
  if CurStep = ssPostInstall then
    RunServerSetup();
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    if SetupOk then
    begin
      WizardForm.FinishedHeadingLabel.Caption := 'Wachtl Server läuft';
      WizardForm.FinishedLabel.Caption :=
        'Adresse: ' + ResultUrl + #13#10#13#10 +
        'Anmeldung als „admin“ mit dem gewählten Passwort.' + #13#10#13#10 +
        'SPKI-Pin für die Installation der Probes (auch in setup-info.txt im Datenordner):';
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

{ Unbeaufsichtigte Installation: Fehlschlag der Einrichtung als Exit-Code 10 melden }
function GetCustomSetupExitCode(): Integer;
begin
  if SetupOk then
    Result := 0
  else
    Result := 10;
end;

{ ---------- Deinstallation ---------- }

function InitializeUninstall(): Boolean;
begin
  if not RegQueryStringValue(HKLM, RegKey, 'DataDir', UninstallDataDir) then
    UninstallDataDir := '';
  Result := True;
end;

{ Unbeaufsichtigt: /REMOVEDATA löscht auch den Datenordner (Datenbank, Schlüssel, Sicherungen) }
function RemoveDataParam(): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), '/REMOVEDATA') = 0 then
      Result := True;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  ResultIni, Leftovers: String;
begin
  if CurUninstallStep <> usPostUninstall then
    Exit;
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
