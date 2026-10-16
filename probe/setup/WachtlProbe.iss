; Wachtl Probe – Setup-Assistent für die Windows-Clients (Inno Setup 6)
; Bauen: probe\build.ps1 (übergibt AppVersion und PublishDir)
;
; Vorbelegung (in dieser Reihenfolge, spätere gewinnen):
;   1. wachtl-probe.ini neben der Setup-Datei – das Paket aus dem Web-UI (Verwaltung › Probes registrieren)
;        [wachtl]
;        server=https://wachtl.kunde.local
;        pin=kpbQ…=
;        token=wachtl-…
;        proxy=
;   2. Parameter: /Server= /Pin= /Token= /Proxy= /Hostname=
;
; Unbeaufsichtigt (z. B. per Softwareverteilung):
;   WachtlProbeSetup-0.2.0.exe /VERYSILENT /SUPPRESSMSGBOXES /Server=https://wachtl.kunde.local /Pin=… /Token=…
; Exit-Code 0 = Probe läuft, 10 = installiert, aber Registrierung oder Dienststart fehlgeschlagen.

#ifndef AppVersion
  #define AppVersion "0.2.0"
#endif
#ifndef PublishDir
  #define PublishDir "..\..\dist\probe"
#endif

[Setup]
AppId={{4D6A9E31-7C2B-4F58-B1E0-93A5C7D2F861}
AppName=Wachtl Probe
AppVersion={#AppVersion}
AppVerName=Wachtl Probe {#AppVersion}
AppPublisher=Wachtl
DefaultDirName={autopf}\Wachtl
DisableDirPage=yes
DisableProgramGroupPage=yes
DefaultGroupName=Wachtl Probe
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.14393
OutputBaseFilename=WachtlProbeSetup-{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\..\windows\assets\wachtl.ico
WizardImageFile=..\..\windows\assets\wizard-100.bmp,..\..\windows\assets\wizard-150.bmp,..\..\windows\assets\wizard-200.bmp
WizardSmallImageFile=..\..\windows\assets\wizard-small-100.bmp,..\..\windows\assets\wizard-small-150.bmp,..\..\windows\assets\wizard-small-200.bmp
SetupLogging=yes
TimeStampsInUTC=yes
CloseApplications=no
RestartApplications=no
UninstallDisplayName=Wachtl Probe
UninstallDisplayIcon={app}\wachtl-probe.exe
VersionInfoVersion={#AppVersion}

[Languages]
Name: "german"; MessagesFile: "compiler:Languages\German.isl"

[Files]
Source: "{#PublishDir}\wachtl-probe.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#PublishDir}\Install-Wachtl.ps1"; DestDir: "{app}"; Flags: ignoreversion
; Setup selbst ablegen – darüber lassen sich Einstellungen später ändern
Source: "{srcexe}"; DestDir: "{app}"; DestName: "WachtlProbeSetup.exe"; Flags: external ignoreversion; Check: NotRunningFromApp

[Icons]
Name: "{group}\Wachtl Probe – Einstellungen ändern"; Filename: "{app}\WachtlProbeSetup.exe"; IconFilename: "{app}\wachtl-probe.exe"
Name: "{group}\Wachtl Probe – Status"; Filename: "{cmd}"; Parameters: "/k ""{app}\wachtl-probe.exe"" status"; IconFilename: "{app}\wachtl-probe.exe"
Name: "{group}\Wachtl Probe – Logdateien"; Filename: "{commonappdata}\Wachtl\logs"

[Run]
Filename: "{code:GetServer}"; Description: "Wachtl-Dashboard im Browser öffnen"; Flags: postinstall shellexec nowait skipifsilent unchecked; Check: DashboardKnown

[UninstallRun]
Filename: "{sys}\net.exe"; Parameters: "stop Wachtl"; Flags: runhidden waituntilterminated; RunOnceId: "StopWachtl"
Filename: "{sys}\sc.exe"; Parameters: "delete Wachtl"; Flags: runhidden waituntilterminated; RunOnceId: "DeleteWachtl"

[Code]
const
  ServiceName = 'Wachtl';
  ServiceAccount = 'NT SERVICE\Wachtl';
  ModeKeep = 0;
  ModeProxy = 1;
  ModeNew = 2;

var
  ModePage: TInputOptionWizardPage;
  ServerPage, ProxyPage, TokenPage: TInputQueryWizardPage;
  IsEnrolled, ServiceExists, SetupOk, EnrollDone: Boolean;
  SetupError, SiteName, ProbeExe: String;

{ ---------- Hilfen ---------- }

function GetParam(const Name, Default: String): String;
begin
  Result := ExpandConstant('{param:' + Name + '|}');
  if Result = '' then
    Result := Default;
end;

function IniDefault(const Key: String): String;
begin
  Result := GetIniString('wachtl', Key, '', ExpandConstant('{src}\wachtl-probe.ini'));
end;

function Quote(const S: String): String;
begin
  Result := '"' + S + '"';
end;

function DataDir(): String;
begin
  Result := ExpandConstant('{commonappdata}\Wachtl');
end;

function RunHidden(const Exe, Params: String): Integer;
begin
  if not Exec(Exe, Params, '', SW_HIDE, ewWaitUntilTerminated, Result) then
    Result := -1;
end;

function Mode(): Integer;
begin
  if not IsEnrolled then
    Result := ModeNew
  else if ModePage.Values[ModeProxy] then
    Result := ModeProxy
  else if ModePage.Values[ModeNew] then
    Result := ModeNew
  else
    Result := ModeKeep;
end;

{ Probe-Programm für Prüfungen schon vor dem Kopieren bereitstellen }
function EnsureProbeExe(): String;
begin
  if ProbeExe = '' then
  begin
    ExtractTemporaryFile('wachtl-probe.exe');
    ProbeExe := ExpandConstant('{tmp}\wachtl-probe.exe');
  end;
  Result := ProbeExe;
end;

{ Führt wachtl-probe.exe aus und liefert Exit-Code; Ergebnis steht in ResultFile }
function RunProbe(const Params, ResultFile: String): Integer;
begin
  DeleteFile(ResultFile);
  Result := RunHidden(EnsureProbeExe(), Params + ' --out ' + Quote(ResultFile));
end;

function ResultValue(const ResultFile, Key: String): String;
begin
  Result := GetIniString('result', Key, '', ResultFile);
  StringChangeEx(Result, '\n', #13#10, True);
end;

function GetServer(Param: String): String;
begin
  Result := Trim(ServerPage.Values[0]);
  if (Result <> '') and (Pos('://', Result) = 0) then
    Result := 'https://' + Result;
end;

function DashboardKnown(): Boolean;
begin
  Result := SetupOk and (GetServer('') <> '');
end;

function NotRunningFromApp(): Boolean;
begin
  Result := CompareText(ExpandConstant('{srcexe}'), ExpandConstant('{app}\WachtlProbeSetup.exe')) <> 0;
end;

function ProxyArg(): String;
begin
  if Trim(ProxyPage.Values[0]) <> '' then
    Result := ' --proxy ' + Quote(Trim(ProxyPage.Values[0]))
  else
    Result := '';
end;

{ ---------- Assistent ---------- }

function InitializeSetup(): Boolean;
var
  Code: Integer;
begin
  IsEnrolled := FileExists(ExpandConstant('{commonappdata}\Wachtl\state.json'));
  ServiceExists := Exec(ExpandConstant('{sys}\sc.exe'), 'query ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
  Result := True;
end;

procedure InitializeWizard();
begin
  ModePage := CreateInputOptionPage(wpWelcome,
    'Vorhandene Installation', 'Diese Probe ist bereits registriert.',
    'Was soll geschehen?', True, False);
  ModePage.Add('Nur aktualisieren – Registrierung und Einstellungen behalten');
  ModePage.Add('Proxy ändern');
  ModePage.Add('Neu registrieren – anderer Server, anderer Standort oder neuer Token');
  ModePage.SelectedValueIndex := ModeKeep;

  ServerPage := CreateInputQueryPage(ModePage.ID,
    'Wachtl-Server', 'Mit welchem Server soll sich diese Probe verbinden?',
    'Adresse und SPKI-Pin stehen in setup-info.txt auf dem Server und auf der Seite ' +
    '„Probes registrieren“ im Web-UI. Ohne Pin fragt der Assistent den Server und zeigt den Pin zur Kontrolle an.');
  ServerPage.Add('Server-Adresse (z. B. https://wachtl.kunde.local):', False);
  ServerPage.Add('SPKI-Pin:', False);
  ServerPage.Values[0] := GetParam('Server', IniDefault('server'));
  ServerPage.Values[1] := GetParam('Pin', IniDefault('pin'));

  ProxyPage := CreateInputQueryPage(ServerPage.ID,
    'Verbindung', 'Braucht dieser PC einen Proxy, um den Server zu erreichen?',
    'Leer lassen für eine direkte Verbindung (Normalfall im internen Netz). Ein Proxy mit TLS-Prüfung ' +
    'muss den Wachtl-Server ausnehmen. Beim Weiter prüft der Assistent die Verbindung.');
  ProxyPage.Add('Proxy (optional, z. B. http://proxy.kunde.local:3128):', False);
  ProxyPage.Values[0] := GetParam('Proxy', IniDefault('proxy'));

  TokenPage := CreateInputQueryPage(ProxyPage.ID,
    'Registrierung', 'Mit welchem Token soll sich die Probe anmelden?',
    'Den Enrollment-Token erzeugt ein Administrator im Web-UI unter Verwaltung › Probes registrieren. ' +
    'Er legt auch fest, zu welchem Standort die Probe gehört.');
  TokenPage.Add('Enrollment-Token:', False);
  TokenPage.Add('Name dieser Probe im Dashboard:', False);
  TokenPage.Values[0] := GetParam('Token', IniDefault('token'));
  TokenPage.Values[1] := GetParam('Hostname', GetComputerNameString());
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := False;
  if PageID = ModePage.ID then
    Result := not IsEnrolled
  else if (PageID = ServerPage.ID) or (PageID = TokenPage.ID) then
    Result := Mode() <> ModeNew
  else if PageID = ProxyPage.ID then
    Result := Mode() = ModeKeep;
end;

{ Verbindung und Pin prüfen, ohne den Token zu verbrauchen }
function CheckConnection(): Boolean;
var
  ResultFile, Params, Pin, SeenPin, Err: String;
  Code: Integer;
begin
  Result := False;
  ResultFile := ExpandConstant('{tmp}\check.ini');
  if Mode() = ModeProxy then
    Params := 'check --use-state 1 --proxy ' + Quote(Trim(ProxyPage.Values[0]))
  else
  begin
    Pin := Trim(ServerPage.Values[1]);
    Params := 'check --server ' + Quote(GetServer(''));
    if Pin <> '' then
      Params := Params + ' --pin ' + Quote(Pin);
    Params := Params + ProxyArg();
  end;
  WizardForm.NextButton.Enabled := False;
  try
    Code := RunProbe(Params, ResultFile);
  finally
    WizardForm.NextButton.Enabled := True;
  end;
  SeenPin := ResultValue(ResultFile, 'pin');
  Err := ResultValue(ResultFile, 'error');
  if Code = 0 then
  begin
    if (Mode() = ModeNew) and (Pin = '') and WizardSilent() then
    begin
      Log('Wachtl Probe: unbeaufsichtigt ohne /Pin= – Pin wird nicht ungeprüft übernommen.');
      Result := False;
    end
    else if (Mode() = ModeNew) and (Pin = '') then
    begin
      if MsgBox('Der Server meldet folgenden SPKI-Pin:' + #13#10#13#10 + SeenPin + #13#10#13#10 +
                'Stimmt er mit setup-info.txt auf dem Server bzw. dem Web-UI überein?',
                mbConfirmation, MB_YESNO) = IDYES then
      begin
        ServerPage.Values[1] := SeenPin;
        Result := True;
      end;
    end
    else
      Result := True;
  end
  else
  begin
    if Err = '' then
      Err := 'Prüfung fehlgeschlagen (Code ' + IntToStr(Code) + ').';
    MsgBox('Keine Verbindung zum Wachtl-Server:' + #13#10#13#10 + Err, mbError, MB_OK);
  end;
end;

{ Registrieren schon im Assistenten: Fehler (Token abgelaufen …) lassen sich direkt korrigieren }
function Enroll(): Boolean;
var
  ResultFile, Params, Err: String;
  Code: Integer;
begin
  ResultFile := ExpandConstant('{tmp}\enroll.ini');
  Params := 'enroll --server ' + Quote(GetServer('')) + ' --pin ' + Quote(Trim(ServerPage.Values[1])) +
            ' --token ' + Quote(Trim(TokenPage.Values[0])) + ' --hostname ' + Quote(Trim(TokenPage.Values[1])) + ProxyArg();
  WizardForm.NextButton.Enabled := False;
  try
    Code := RunProbe(Params, ResultFile);
  finally
    WizardForm.NextButton.Enabled := True;
  end;
  Result := Code = 0;
  if Result then
  begin
    SiteName := ResultValue(ResultFile, 'site');
    EnrollDone := True;
  end
  else
  begin
    Err := ResultValue(ResultFile, 'error');
    if Err = '' then
      Err := 'Registrierung fehlgeschlagen (Code ' + IntToStr(Code) + ').';
    MsgBox(Err, mbError, MB_OK);
  end;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Name: String;
  I: Integer;
begin
  Result := True;
  if CurPageID = ServerPage.ID then
  begin
    if Trim(ServerPage.Values[0]) = '' then
    begin
      MsgBox('Bitte die Adresse des Wachtl-Servers angeben.', mbError, MB_OK);
      Result := False;
    end
    else if Pos('http://', Lowercase(Trim(ServerPage.Values[0]))) = 1 then
    begin
      MsgBox('Die Verbindung muss verschlüsselt sein: bitte https:// verwenden.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = ProxyPage.ID then
  begin
    if (Trim(ProxyPage.Values[0]) <> '') and (Pos('://', ProxyPage.Values[0]) = 0) then
    begin
      MsgBox('Bitte den Proxy mit Schema angeben, z. B. http://proxy.kunde.local:3128', mbError, MB_OK);
      Result := False;
    end
    else
      Result := CheckConnection();
  end
  else if CurPageID = TokenPage.ID then
  begin
    Name := Trim(TokenPage.Values[1]);
    if Trim(TokenPage.Values[0]) = '' then
    begin
      MsgBox('Bitte den Enrollment-Token eingeben.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Name = '') or (Length(Name) > 63) then
    begin
      MsgBox('Bitte einen Namen mit 1 bis 63 Zeichen angeben.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    for I := 1 to Length(Name) do
      if Pos(Name[I], 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.') = 0 then
      begin
        MsgBox('Der Name darf nur Buchstaben (ohne Umlaute), Ziffern, Punkt, Binde- und Unterstrich enthalten.', mbError, MB_OK);
        Result := False;
        Exit;
      end;
    Result := Enroll();
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo,
  MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
begin
  Result := MemoDirInfo + NewLine + NewLine;
  case Mode() of
    ModeKeep:
      Result := Result + 'Programm aktualisieren, Registrierung bleibt erhalten.' + NewLine;
    ModeProxy:
      if Trim(ProxyPage.Values[0]) = '' then
        Result := Result + 'Proxy entfernen (direkte Verbindung).' + NewLine
      else
        Result := Result + 'Neuer Proxy: ' + Trim(ProxyPage.Values[0]) + NewLine;
  else
    begin
      Result := Result + 'Server:' + NewLine + Space + GetServer('') + NewLine;
      if Trim(ProxyPage.Values[0]) <> '' then
        Result := Result + Space + 'über Proxy ' + Trim(ProxyPage.Values[0]) + NewLine;
      Result := Result + NewLine + 'Registriert als:' + NewLine + Space + Trim(TokenPage.Values[1]);
      if SiteName <> '' then
        Result := Result + ' am Standort ' + SiteName;
      Result := Result + NewLine;
    end;
  end;
  Result := Result + NewLine + 'Dienst „Wachtl Netzwerk-Probe“ (startet automatisch, auch ohne Anmeldung).';
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  RunHidden(ExpandConstant('{sys}\net.exe'), 'stop ' + ServiceName);
  Result := '';
end;

{ Unbeaufsichtigt: Prüfung und Registrierung erst hier, weil keine Seiten durchlaufen werden }
function SilentEnroll(): Boolean;
var
  ResultFile: String;
begin
  Result := True;
  if (Mode() <> ModeNew) or EnrollDone then
    Exit;
  ResultFile := ExpandConstant('{tmp}\enroll.ini');
  if RunProbe('enroll --server ' + Quote(GetServer('')) + ' --pin ' + Quote(Trim(ServerPage.Values[1])) +
              ' --token ' + Quote(Trim(TokenPage.Values[0])) + ' --hostname ' + Quote(Trim(TokenPage.Values[1])) +
              ProxyArg(), ResultFile) <> 0 then
  begin
    SetupError := ResultValue(ResultFile, 'error');
    if SetupError = '' then
      SetupError := 'Registrierung fehlgeschlagen.';
    Result := False;
  end;
end;

procedure InstallService();
var
  Sc, Exe: String;
  Code, I: Integer;
begin
  Sc := ExpandConstant('{sys}\sc.exe');
  Exe := ExpandConstant('{app}\wachtl-probe.exe');
  WizardForm.StatusLabel.Caption := 'Dienst wird eingerichtet …';

  if Mode() = ModeProxy then
    if RunHidden(Exe, 'configure --proxy ' + Quote(Trim(ProxyPage.Values[0])) + ' --out ' +
                 Quote(ExpandConstant('{tmp}\configure.ini'))) <> 0 then
    begin
      SetupError := 'Proxy konnte nicht gespeichert werden.';
      Exit;
    end;

  if not ServiceExists then
    if RunHidden(Sc, 'create ' + ServiceName + ' binPath= "\"' + Exe + '\"" start= delayed-auto obj= ' +
                 Quote(ServiceAccount) + ' DisplayName= "Wachtl Netzwerk-Probe"') <> 0 then
    begin
      SetupError := 'Der Dienst konnte nicht angelegt werden (sc create).';
      Exit;
    end;
  RunHidden(Sc, 'config ' + ServiceName + ' start= delayed-auto obj= ' + Quote(ServiceAccount));
  RunHidden(Sc, 'description ' + ServiceName + ' "Misst Latenz und Paketverlust und meldet sie an den Wachtl-Server."');
  RunHidden(Sc, 'failure ' + ServiceName + ' reset= 86400 actions= restart/10000/restart/30000/restart/60000');
  RunHidden(Sc, 'failureflag ' + ServiceName + ' 1');

  { Token und Puffer: nur SYSTEM, Administratoren und das Dienstkonto (SIDs = sprachunabhängig) }
  ForceDirectories(DataDir());
  RunHidden(ExpandConstant('{sys}\icacls.exe'), Quote(DataDir()) + ' /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F ' +
            '/grant:r *S-1-5-32-544:(OI)(CI)F /grant:r ' + Quote(ServiceAccount + ':(OI)(CI)M') + ' /C /Q');
  RunHidden(ExpandConstant('{sys}\icacls.exe'), Quote(DataDir() + '\*') + ' /reset /T /C /Q');

  WizardForm.StatusLabel.Caption := 'Dienst wird gestartet …';
  RunHidden(Sc, 'start ' + ServiceName);
  Code := 1;
  for I := 1 to 15 do
  begin
    Sleep(1000);
    Code := RunHidden(ExpandConstant('{cmd}'), '/C ' + Quote(Sc) + ' query ' + ServiceName + ' | find "RUNNING" >nul');
    if Code = 0 then
      Break;
  end;
  if Code <> 0 then
    SetupError := 'Der Dienst wurde eingerichtet, läuft aber nicht. Details: ' + DataDir() + '\logs'
  else
    SetupOk := True;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if WizardSilent() and not SilentEnroll() then
      Exit;
    if not IsEnrolled and not EnrollDone then
    begin
      SetupError := 'Die Probe ist nicht registriert.';
      Exit;
    end;
    InstallService();
    if (not SetupOk) and (not WizardSilent()) then
      MsgBox(SetupError, mbError, MB_OK);
    if not SetupOk then
      Log('Wachtl Probe: ' + SetupError);
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    if SetupOk then
    begin
      WizardForm.FinishedHeadingLabel.Caption := 'Wachtl Probe läuft';
      if Mode() = ModeNew then
        WizardForm.FinishedLabel.Caption := 'Die Probe „' + Trim(TokenPage.Values[1]) + '“ ist registriert' +
          ' und erscheint in den nächsten 30 Sekunden im Dashboard.' + #13#10#13#10 +
          'Welche Ziele sie misst, legt der Server zentral fest (Verwaltung › Checks).'
      else
        WizardForm.FinishedLabel.Caption := 'Die Probe wurde aktualisiert und läuft wieder.' + #13#10#13#10 +
          'Einstellungen ändern: Startmenü › Wachtl Probe – Einstellungen ändern.';
    end
    else
    begin
      WizardForm.FinishedHeadingLabel.Caption := 'Probe nicht gestartet';
      WizardForm.FinishedLabel.Caption := SetupError + #13#10#13#10 + 'Setup nach dem Beheben einfach erneut starten.';
    end;
    WizardForm.FinishedLabel.AdjustHeight();
  end;
end;

function GetCustomSetupExitCode(): Integer;
begin
  if SetupOk then
    Result := 0
  else
    Result := 10;
end;

{ ---------- Deinstallation ---------- }

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  Dir: String;
begin
  Dir := ExpandConstant('{commonappdata}\Wachtl');
  if (CurUninstallStep = usPostUninstall) and DirExists(Dir) and not UninstallSilent() then
    if MsgBox('Auch Registrierung, Puffer und Logdateien löschen?' + #13#10#13#10 + Dir + #13#10#13#10 +
              'Bei „Nein“ kann die Probe später ohne neuen Token wieder installiert werden.',
              mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      DelTree(Dir, True, True, True);
end;
