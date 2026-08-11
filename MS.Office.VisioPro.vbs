set objShell = CreateObject("Wscript.Shell")
set objShellApp = CreateObject("Shell.Application")
set objFSO = CreateObject("Scripting.FileSystemObject")
CurrentVersion=objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")

PROCESSOR_ARCHITECTURE = objShell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")

If ( ( ((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64") )  AND WScript.Arguments.Named.Exists("elevated") = False ) Then

	CreateObject("Shell.Application").ShellExecute "wscript.exe", """" &WScript.ScriptFullName & """ /elevated", "", "runas", 1
	WScript.Quit

Else

	objShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

End if

' Upgrade winget
objShell.Run "winget upgrade winget --accept-package-agreements --accept-source-agreements --silent", 2, true

' Install ODT
objShell.Run "winget install Microsoft.OfficeDeploymentTool --accept-package-agreements --accept-source-agreements --silent", 2, true

' Create configuration-OfficeStandard-x64.xml
strProgFiles = objShell.ExpandEnvironmentStrings("%ProgramFiles%")

Dim fso, filePath, file
Set fso = CreateObject("Scripting.FileSystemObject")
filePath = strProgFiles & "\OfficeDeploymentTool\configuration-VisioPro-x64.xml"
Set file = fso.CreateTextFile(filePath, True)

file.WriteLine "<Configuration>"
file.WriteLine " <Add OfficeClientEdition=""64"" Channel=""PerpetualVL2024"">"
file.WriteLine "  <Product ID=""VisioPro2024Volume"">"
file.WriteLine "   <Language ID=""uk-UA"" />"
file.WriteLine "   <ExcludeApp ID=""Groove"" />"
file.WriteLine "   <ExcludeApp ID=""OneNote"" />"
file.WriteLine "   <ExcludeApp ID=""OneDrive"" />"
file.WriteLine "   <ExcludeApp ID=""Teams"" />"
file.WriteLine "  </Product>"
file.WriteLine "  <Product ID=""ProofingTools"">"
file.WriteLine "   <Language ID=""uk-UA"" />"
file.WriteLine "   <Language ID=""en-US"" />"
file.WriteLine "  </Product>"
file.WriteLine " </Add>"
file.WriteLine "<Display Level=""None"" AcceptEULA=""TRUE"" />"
file.WriteLine "<Property Name=""AUTOACTIVATE"" Value=""1"" />"
file.WriteLine "<Property Name=""FORCEAPPSHUTDOWN"" Value=""TRUE"" />"
file.WriteLine "<Updates Enabled=""TRUE"" />"
file.WriteLine "</Configuration>"
file.Close

' install Visio Pro
objShell.Run "powershell Start-Process -WindowStyle Minimized -Wait -WorkingDirectory ${env:ProgramFiles}\OfficeDeploymentTool -FilePath setup.exe -ArgumentList '/configure configuration-VisioPro-x64.xml'", 2, true

