set objShell = CreateObject("Wscript.Shell")
set objShellApp = CreateObject("Shell.Application")
set objFSO = CreateObject("Scripting.FileSystemObject")
CurrentVersion=objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")
InstallationType=objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\InstallationType")
DhcpDomain = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\DhcpDomain")
DhcpNameServer = objShell.RegRead("HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\Tcpip\Parameters\DhcpNameServer")

PROCESSOR_ARCHITECTURE = objShell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")
SystemRoot = objShell.ExpandEnvironmentStrings("%SystemRoot%")
SystemDrive = objShell.ExpandEnvironmentStrings("%SYSTEMDRIVE%")
ProgramFiles = objShell.ExpandEnvironmentStrings("%ProgramFiles%")
TEMP = objShell.ExpandEnvironmentStrings("%TEMP%")

Function FileExists(FilePath)
  Set fso = CreateObject("Scripting.FileSystemObject")
  If fso.FileExists(FilePath) Then
    FileExists=CBool(1)
  Else
    FileExists=CBool(0)
  End If
End Function


for each System in GetObject("winmgmts:").InstancesOf ("Win32_ComputerSystem")
 WORKGROUP = System.Workgroup
next

If ( ( ((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64") )  AND WScript.Arguments.Named.Exists("elevated") = False ) Then

	CreateObject("Shell.Application").ShellExecute "wscript.exe", """" &WScript.ScriptFullName & """ /elevated", "", "runas", 1
	WScript.Quit

Else

	objShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

End if

If (((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64"))  Then

	if ((DhcpDomain = "nt") and (DhcpNameServer = "10.10.175.1")) Then
		objShell.Run "powershell Add-Computer -WorkGroupName nt -Force", 2, true
	End if

	if ((DhcpDomain = "zkr") and (DhcpNameServer = "10.0.0.1")) Then
		objShell.Run "powershell Add-Computer -WorkGroupName zkr -Force", 2, true
	End if

	if ((DhcpDomain = "lina") and (DhcpNameServer = "192.168.10.1")) Then
		objShell.Run "powershell Add-Computer -WorkGroupName lina -Force", 2, true
	End if

	' Windows Server
	If (InstallationType = "Server")  Then

		' Disable WindowsDefender
		objShell.Run "Dism /Online /NoRestart /Disable-Feature /FeatureName:Windows-Defender", 2, true
		
		' Activate performance profile
		objShell.Run "powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c", 2, true

		' Disable monitor timeout
		objShell.Run "powercfg /CHANGE monitor-timeout-ac 0", 2, true

	End if

	' Turn off "Connected User Experiences and Telemetry" service
	objShell.Run "powershell Get-Service -Name DiagTrack | Stop-Service -Force", 2, true
	objShell.Run "powershell Get-Service -Name DiagTrack | Set-Service -StartupType Disabled", 2, true

	' Disable autoinstall network devices
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\NcdAutoSetup\Private\AutoSetup","0","REG_DWORD"

	' Show desktop icons
	objShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{20D04FE0-3AEA-1069-A2D8-08002B30309D}","0","REG_DWORD"
	objShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}","0","REG_DWORD"
	objShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{59031a47-3f72-44a7-89c5-5595fe6b30ee}","0","REG_DWORD"
	objShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{645FF040-5081-101B-9F08-00AA002F954E}","0","REG_DWORD"
	objShell.RegWrite "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}","0","REG_DWORD"

	' Disable SystemRestore on System Disk:
	objShell.Run "powershell Disable-ComputerRestore -Drive $env:SystemDrive", 2, true

	' Disable sleep mode
	objShell.Run "powercfg /CHANGE standby-timeout-ac 0", 2, true

	' Set timezone to (UTC+2:00) Kiev
	objShell.Run "powershell -Command {Start-Process tzutil.exe -ArgumentList '/s FLE Standard Time' -Wait}", 2, true

	' Delete fax and xps printers
	objShell.Run "Dism /Online /NoRestart /Disable-Feature /FeatureName:FaxServicesClientPackage", 2, true
	objShell.Run "Dism /Online /NoRestart /Disable-Feature /FeatureName:Printing-XPSServices-Features", 2, true

	' Allow ICMPv4
	objShell.Run "powershell New-NetFirewallRule -DisplayName ICMPv4 -Direction Inbound -Protocol ICMPv4 -IcmpType 8 -Action Allow", 2, true

	' Allow RDP
	objShell.Run "powershell New-NetFirewallRule -DisplayName RDP -Direction Inbound -Protocol TCP -LocalPort 3389 -EdgeTraversalPolicy Allow -Action Allow", 2, true

	' Install .NET Framework 3.5
	objShell.Run "Dism /Online /NoRestart /Enable-Feature /All /FeatureName:NetFx3", 2, true

	If NOT (InstallationType = "Server") Then

		' Delete Office
		objShell.Run "powershell Get-AppxPackage *Office* | Remove-AppxPackage", 2, true

		' Delete Skype
		objShell.Run "powershell Get-AppxPackage *Skype* | Remove-AppxPackage", 2, true

		' Delete Yandex.Music
		objShell.Run "powershell Get-AppxPackage *Yandex* | Remove-AppxPackage", 2, true

		' download ODT
		objShell.Run "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/vpm/_install-scenario/main/officedeploymenttool.uri -OutFile $env:TEMP\officedeploymenttool.uri", 2, true
		objShell.Run "powershell Invoke-WebRequest -Uri (Get-Content $env:TEMP\officedeploymenttool.uri) -OutFile $env:TEMP\officedeploymenttool.exe", 2, true

		' extract ODT
		objShell.Run ""& TEMP&"\officedeploymenttool.exe /extract:"& TEMP&" /quiet", 2, true

		' create Standard2021Volume.xml
		Set Standard2021Volume = objFSO.CreateTextFile(""& TEMP&"\Standard2021Volume.xml", True)
		path = objFSO.GetAbsolutePathName(""& TEMP&"\Standard2021Volume.xml")
		getname = objFSO.GetFileName(path)

		Standard2021Volume.WriteLine "<Configuration>"
		Standard2021Volume.WriteLine "  <Add OfficeClientEdition=""64"" Channel=""PerpetualVL2021"">"
		Standard2021Volume.WriteLine "    <Product ID=""Standard2021Volume"">"
		Standard2021Volume.WriteLine "      <Language ID=""uk-UA"" />"
		Standard2021Volume.WriteLine "      <ExcludeApp ID=""Groove"" />"
		Standard2021Volume.WriteLine "      <ExcludeApp ID=""OneNote"" />"
		Standard2021Volume.WriteLine "      <ExcludeApp ID=""OneDrive"" />"
		Standard2021Volume.WriteLine "     <ExcludeApp ID=""Teams"" />"
		Standard2021Volume.WriteLine "   </Product>"
		Standard2021Volume.WriteLine "   <Product ID=""ProofingTools"">"
		Standard2021Volume.WriteLine "     <Language ID=""en-US"" />"
		Standard2021Volume.WriteLine "     <Language ID=""uk-UA"" />"
		Standard2021Volume.WriteLine "   </Product>"
		Standard2021Volume.WriteLine " </Add>"
		Standard2021Volume.WriteLine " <Display Level=""None"" AcceptEULA=""TRUE"" />"
		Standard2021Volume.WriteLine " <Property Name=""AUTOACTIVATE"" Value=""1""/>"
		Standard2021Volume.WriteLine " <Updates Enabled=""TRUE""/>"
		Standard2021Volume.WriteLine "</Configuration>"
		Standard2021Volume.Close

		' create O365ProPlusRetail.xml
		Set O365ProPlusRetail = objFSO.CreateTextFile(""& TEMP&"\O365ProPlusRetail.xml", True)
		path = objFSO.GetAbsolutePathName(""& TEMP&"\O365ProPlusRetail.xml")
		getname = objFSO.GetFileName(path)

		O365ProPlusRetail.WriteLine "<Configuration>"
		O365ProPlusRetail.WriteLine "  <Add OfficeClientEdition=""64"" Channel=""Monthly"">"
		O365ProPlusRetail.WriteLine "    <Product ID=""O365ProPlusRetail"">"
		O365ProPlusRetail.WriteLine "      <Language ID=""uk-UA"" />"
		O365ProPlusRetail.WriteLine "      <ExcludeApp ID=""Groove"" />"
		O365ProPlusRetail.WriteLine "      <ExcludeApp ID=""Lync"" />"
		O365ProPlusRetail.WriteLine "      <ExcludeApp ID=""OneDrive"" />"
		O365ProPlusRetail.WriteLine "   </Product>"
		O365ProPlusRetail.WriteLine "   <Product ID=""ProofingTools"">"
		O365ProPlusRetail.WriteLine "     <Language ID=""en-US"" />"
		O365ProPlusRetail.WriteLine "     <Language ID=""uk-UA"" />"
		O365ProPlusRetail.WriteLine "   </Product>"
		O365ProPlusRetail.WriteLine " </Add>"
		O365ProPlusRetail.WriteLine " <Display Level=""None"" AcceptEULA=""TRUE"" />"
		O365ProPlusRetail.WriteLine " <Updates Enabled=""TRUE""/>"
		O365ProPlusRetail.WriteLine "</Configuration>"
		O365ProPlusRetail.Close

		' Office 365 or 2021
		If Not ((WORKGROUP = "DEUTSCH-PHARM") or (WORKGROUP = "VARZAR") or (WORKGROUP = "NT")) Then

			ProgramFiles = objShell.ExpandEnvironmentStrings("%ProgramFiles%")
		
			ProgramFilesOffice16 = "& ProgramFiles&\Microsoft Office\Office16"

			' Office 2021 Standard
			objShell.Run ""& TEMP&"\setup.exe /configure "& TEMP&"\Standard2021Volume.xml", 2, true

			' activate Office
			objShell.Run "cscript ""& ProgramFilesOffice16""\OSPP.VBS /act", 2, true

			' delete OneDrive
			If objFSO.FileExists(""& SystemRoot&"\SysWOW64\OneDriveSetup.exe") Then

				' uninstall OneDrive ( Windows 10 )
				objShell.Run ""& SystemRoot&"\SysWOW64\OneDriveSetup.exe /uninstall", 2, true
	
			else

				' uninstall OneDrive ( Windows 11 )
				objShell.Run ""& SystemRoot&"\System32\OneDriveSetup.exe /uninstall", 2, true

			End if

			' disable OneDrive
			objShell.RegWrite "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OneDrive\DisableFileSyncNGSC","1","REG_DWORD"

		Else

			' Office 365
			objShell.Run ""& TEMP&"\setup.exe /configure "& TEMP&"\O365ProPlusRetail.xml", 2, true

		End if

		' Delete ODT
		objFSO.DeleteFile ""& TEMP&"\officedeploymenttool.uri"
		objFSO.DeleteFile ""& TEMP&"\officedeploymenttool.exe"
		objFSO.DeleteFile ""& TEMP&"\setup.exe"
		objFSO.DeleteFile ""& TEMP&"\Standard2021Volume.xml"
		objFSO.DeleteFile ""& TEMP&"\O365ProPlusRetail.xml"
		objFSO.DeleteFile ""& TEMP&"\configuration-Office365-x64.xml"
		objFSO.DeleteFile ""& TEMP&"\configuration-Office365-x86.xml"
		objFSO.DeleteFile ""& TEMP&"\configuration-Office2019Enterprise.xml"
		objFSO.DeleteFile ""& TEMP&"\configuration-Office2021Enterprise.xml"

		' Adobe Reader DC
		objShell.Run "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/vpm/_install-scenario/main/AcroRdrDCx64_uk_UA.uri -OutFile $env:TEMP\AcroRdrDCx64_uk_UA.uri", 2, true
		objShell.Run "powershell Invoke-WebRequest -Uri (Get-Content $env:TEMP\AcroRdrDCx64_uk_UA.uri) -OutFile $env:TEMP\AcroRdrDCx64_uk_UA.exe", 2, true
		objShell.Run ""& TEMP&"\AcroRdrDCx64_uk_UA.exe /sPb /rs /msi EULA_ACCEPT=YES", 2, true
		objFSO.DeleteFile ""& TEMP&"\AcroRdrDCx64_uk_UA.uri"
		objFSO.DeleteFile ""& TEMP&"\AcroRdrDCx64_uk_UA.exe"

		' Google Chrome
		objShell.Run "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/vpm/_install-scenario/main/ChromeSetup.uri -OutFile $env:TEMP\ChromeSetup.uri", 2, true
		objShell.Run "powershell Invoke-WebRequest -Uri (Get-Content $env:TEMP\ChromeSetup.uri) -OutFile $env:TEMP\ChromeSetup.exe", 2, true
		objShell.Run ""& TEMP&"\ChromeSetup.exe /silent /install", 2, true
		objFSO.DeleteFile ""& TEMP&"\ChromeSetup.uri"
		objFSO.DeleteFile ""& TEMP&"\ChromeSetup.exe"

		' K-Lite Mega Codec Pack
		objShell.Run "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/vpm/_install-scenario/main/K-Lite_Codec_Pack_Mega.uri -OutFile $env:TEMP\K-Lite_Codec_Pack_Mega.uri", 2, true
		objShell.Run "powershell Invoke-WebRequest -Uri (Get-Content $env:TEMP\K-Lite_Codec_Pack_Mega.uri) -OutFile $env:TEMP\K-Lite_Codec_Pack_Mega.exe", 2, true
		objShell.Run ""& TEMP&"\K-Lite_Codec_Pack_Mega.exe /silent", 2, true
		objFSO.DeleteFile ""& TEMP&"\K-Lite_Codec_Pack_Mega.uri"
		objFSO.DeleteFile ""& TEMP&"\K-Lite_Codec_Pack_Mega.exe"

	End if

	' 7-Zip
	objShell.Run "powershell Invoke-WebRequest -Uri https://raw.githubusercontent.com/vpm/_install-scenario/main/7z-x64.uri -OutFile $env:TEMP\7z-x64.uri", 2, true
	objShell.Run "powershell Invoke-WebRequest -Uri (Get-Content $env:TEMP\7z-x64.uri) -OutFile $env:TEMP\7z-x64.exe", 2, true
	objShell.Run ""& TEMP&"\7z-x64.exe /S", 2, true
	objFSO.DeleteFile ""& TEMP&"\7z-x64.uri"
	objFSO.DeleteFile ""& TEMP&"\7z-x64.exe"

	' register .001 extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.001\","7-Zip.001","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.001\","001 Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.001\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,9","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.001\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .7z extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.7z\","7-Zip.7z","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.7z\","7z Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.7z\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,0","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.7z\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .arj extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.arj\","7-Zip.arj","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\","arj Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,4","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .apfs extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.apfs\","7-Zip.apfs","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\","apfs Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,25","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .bz2 extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.bz2\","7-Zip.bz2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bz2\","bz2 Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bz2\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bz2\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .bzip2 extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.bzip2\","7-Zip.bzip2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bzip2\","bzip2 Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bzip2\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.bzip2\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .cpio extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.cpio\","7-Zip.cpio","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cpio\","cpio Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cpio\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,12","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cpio\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .deb extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.deb\","7-Zip.deb","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.deb\","deb Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.deb\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,11","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.deb\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .dmg extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.dmg\","7-Zip.dmg","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.dmg\","dmg Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.dmg\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,17","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.dmg\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .esd extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.esd\","7-Zip.esd","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.esd\","esd Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.esd\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,15","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.esd\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .fat extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.fat\","7-Zip.fat","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.fat\","fat Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.fat\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,21","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.fat\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .gz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.gz\","7-Zip.gz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gz\","gz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,14","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .gzip extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.gzip\","7-Zip.gzip","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gzip\","gzip Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gzip\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,14","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.gzip\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .hfs extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.hfs\","7-Zip.hfs","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.hfs\","hfs Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.hfs\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,18","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.hfs\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .lha extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.lha\","7-Zip.lha","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lha\","lha Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lha\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,6","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lha\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .lzh extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.lzh\","7-Zip.lzh","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzh\","lzh Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzh\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,6","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzh\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .lzma extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.lzma\","7-Zip.lzma","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzma\","lzma Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzma\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,16","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.lzma\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .ntfs extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.ntfs\","7-Zip.ntfs","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.ntfs\","ntfs Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.ntfs\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,22","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.ntfs\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .rar extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.rar\","7-Zip.rar","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rar\","rar Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rar\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,3","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rar\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .rpm extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.rpm\","7-Zip.rpm","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rpm\","rpm Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rpm\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,10","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.rpm\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .squashfs extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.squashfs\","7-Zip.squashfs","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.squashfs\","squashfs Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.squashfs\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,24","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.squashfs\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .swm extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.swm\","7-Zip.swm","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.swm\","swm Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.swm\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,15","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.swm\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tar extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tar\","7-Zip.tar","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tar\","tar Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tar\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,13","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tar\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .taz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.taz\","7-Zip.taz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.taz\","taz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.taz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,5","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.taz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tbz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tbz\","7-Zip.tbz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz\","tbz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tbz2 extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tbz2\","7-Zip.tbz2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz2\","tbz2 Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz2\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,2","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tbz2\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tgz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tgz\","7-Zip.tgz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tgz\","tgz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tgz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,14","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tgz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tpz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tpz\","7-Zip.tpz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tpz\","tpz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tpz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,14","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tpz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .txz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.txz\","7-Zip.txz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.txz\","txz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.txz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,23","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.txz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .vhd extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.vhd\","7-Zip.vhd","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhd\","vhd Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhd\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,20","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhd\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .vhdx extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.vhdx\","7-Zip.vhdx","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhdx\","vhdx Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhdx\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,20","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.vhd\xshell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .wim extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.wim\","7-Zip.wim","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.wim\","wim Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.wim\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,15","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.wim\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .xar extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.xar\","7-Zip.xar","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xar\","xar Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xar\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,19","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xar\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .xz extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.xz\","7-Zip.xz","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xz\","xz Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xz\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,23","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.xz\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .z extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.z\","7-Zip.z","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.z\","z Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.z\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,5","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.z\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .zip extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.zip\","7-Zip.zip","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zip\","zip Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zip\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,1","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zip\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' reboot
	objShell.Run "shutdown /r /t 8 /f", 2, true

End if

