set objShell = CreateObject("Wscript.Shell")

CurrentVersion = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")

PROCESSOR_ARCHITECTURE = objShell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")
TEMP = objShell.ExpandEnvironmentStrings("%TEMP%")

If ( ( ((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64") )  AND WScript.Arguments.Named.Exists("elevated") = False ) Then

	CreateObject("Shell.Application").ShellExecute "wscript.exe", """" &WScript.ScriptFullName & """ /elevated", "", "runas", 1
	WScript.Quit

Else

	objShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

End if

' Upgrade winget
objShell.Run "winget upgrade winget --accept-package-agreements --accept-source-agreements --silent", 2, true

' Install Adobe.Acrobat.Reader.64-bit
objShell.Run "winget install Adobe.Acrobat.Reader.64-bit --accept-package-agreements --accept-source-agreements --silent", 2, true




