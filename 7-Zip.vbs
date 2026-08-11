set objShell = CreateObject("Wscript.Shell")
CurrentVersion = objShell.RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CurrentVersion")
PROCESSOR_ARCHITECTURE = objShell.ExpandEnvironmentStrings("%PROCESSOR_ARCHITECTURE%")

If ( ( ((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64") )  AND WScript.Arguments.Named.Exists("elevated") = False ) Then

	CreateObject("Shell.Application").ShellExecute "wscript.exe", """" &WScript.ScriptFullName & """ /elevated", "", "runas", 1
	WScript.Quit

Else

	objShell.CurrentDirectory = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)

End if


If (((CurrentVersion = "6.3") Or (CurrentVersion = "6.4")) And (PROCESSOR_ARCHITECTURE = "AMD64"))  Then

	' Upgrade winget
	objShell.Run "winget upgrade winget --accept-package-agreements --accept-source-agreements --silent", 2, true

	' Install 7-Zip
	objShell.Run "winget install 7zip.7zip", 2, true

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

	' register .apfs extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.apfs\","7-Zip.apfs","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\","apfs Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,25","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.apfs\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .arj extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.arj\","7-Zip.arj","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\","arj Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,4","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.arj\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

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

	' register .cab extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.cab\","7-Zip.cab","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cab\","cab Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cab\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,7","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.cab\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

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

	' register .zst extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.zst\","7-Zip.zst","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zst\","zst Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zst\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,26","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.zst\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

	' register .tzst extention for 7-Zip 
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.tzst\","7-Zip.tzst","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tzst\","tzst Archive","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tzst\DefaultIcon\","C:\Program Files\7-Zip\7z.dll,26","REG_SZ"
	objShell.RegWrite "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\7-Zip.tzst\shell\open\command\","""C:\Program Files\7-Zip\7zFM.exe"" ""%1"" ","REG_SZ"

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

End if


