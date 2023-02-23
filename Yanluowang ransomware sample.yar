Yara rule:
{
  meta:
    description = "PDB path found in Yanluowang ransomware samples"
author = "EchoCTI Team"
created= "08/12/2022 12:00:00"

  strings:
    $ = "C:\Users\111\Desktop\wifi\project\ConsoleApplication2\Release\ConsoleApplication2.pdb"
    $ = "C:\Windows\System32\msiexec.exe /i C:\Users[USERNAME]\Pictures\LogMeIn.msi"
    $x4 = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe /v Debugger /t REG_SZ /d C:\windows\system32\cmd.exe /f"
  condition:
    all of them
}
