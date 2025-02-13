rule Worm_Win32_SillyShareCopy_A_2147595756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.A"
        threat_id = "2147595756"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "width=0 height=0></IfrAmE>" ascii //weight: 1
        $x_1_2 = "HijackThis.exe" ascii //weight: 1
        $x_1_3 = "KAV32.exe" ascii //weight: 1
        $x_1_4 = "RavTask.exe" ascii //weight: 1
        $x_1_5 = "DisableRegistryTools" ascii //weight: 1
        $x_1_6 = "if exist \"%s\" goto try" ascii //weight: 1
        $x_1_7 = "DisableWindowsUpdateAccess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_B_2147595873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.B"
        threat_id = "2147595873"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_2 = "\\autorun.inf" wide //weight: 1
        $x_1_3 = "DeleteFile" wide //weight: 1
        $x_1_4 = "[autorun]" wide //weight: 1
        $x_1_5 = "RegWrite" wide //weight: 1
        $x_1_6 = "/F /IM explorer.exe" wide //weight: 1
        $x_1_7 = "taskkill" wide //weight: 1
        $x_1_8 = "GetLogicalDrives" wide //weight: 1
        $x_1_9 = "shell\\1\\Command=" wide //weight: 1
        $x_1_10 = "MICROSOFT\\WINDOWS\\CURRENTVERSION\\RUN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Worm_Win32_SillyShareCopy_C_2147596558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.C"
        threat_id = "2147596558"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept-Language: zh-cn" ascii //weight: 1
        $x_1_2 = "\\Alwil Software\\" ascii //weight: 1
        $x_1_3 = "\\Prevx1\\" ascii //weight: 1
        $x_1_4 = "Norton SystemWorks" ascii //weight: 1
        $x_1_5 = "FTCleanerShell" ascii //weight: 1
        $x_1_6 = "\\Explorer\\Browser Helper Objects\\" ascii //weight: 1
        $x_1_7 = "NoDriveTypeAutoRun" ascii //weight: 1
        $x_1_8 = "AutoRun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Worm_Win32_SillyShareCopy_D_2147597367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.D"
        threat_id = "2147597367"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 20
        $x_8_2 = "LoadResource" ascii //weight: 8
        $x_8_3 = "GetWindowsDirectoryA" ascii //weight: 8
        $x_8_4 = "CreateMutexA" ascii //weight: 8
        $x_1_5 = "ShowSuperHidden" ascii //weight: 1
        $x_1_6 = "CurrentVersion\\Policies\\Explorer\\Run" ascii //weight: 1
        $x_1_7 = "[AutoRun]" ascii //weight: 1
        $x_1_8 = "shell\\open\\Command=" ascii //weight: 1
        $x_1_9 = "autorun.inf" ascii //weight: 1
        $x_1_10 = "net.exe" ascii //weight: 1
        $x_1_11 = {2e 73 6d 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_8_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_E_2147597688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.E"
        threat_id = "2147597688"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2e 00 63 00 6f 00 6d 00 00 00 00 00 08 00 00 00 2e 00 73 00 63 00 72 00 00 00 00 00 18 00}  //weight: 3, accuracy: High
        $x_3_2 = "Echo 81" wide //weight: 3
        $x_3_3 = {6f 00 62 00 6a 00 65 00 63 00 74 00 00 00 00 00 67 00 65 00 74 00 64 00 72 00 69 00 76 00 65 00}  //weight: 3, accuracy: High
        $x_1_4 = "HKEY_CLASSES_ROOT\\scrfile" wide //weight: 1
        $x_1_5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\" wide //weight: 1
        $x_1_6 = "[Autorun]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_F_2147598418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.F"
        threat_id = "2147598418"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_2_2 = {4b 41 56 33 32 2e 65 78 65 00 00 00 ff ff ff ff 09 00 00 00 4b 41 56 44 58 2e 65 78 65 00}  //weight: 2, accuracy: High
        $x_2_3 = {41 75 74 6f 52 75 6e 2e 69 6e 66 00 ff ff ff ff 10 00 00 00 5b 41 75 74 6f 52 75 6e 5d 0d 0a}  //weight: 2, accuracy: High
        $x_1_4 = "downurl=http:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_G_2147598451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.G"
        threat_id = "2147598451"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist \"" ascii //weight: 1
        $x_1_2 = "TOOLTIPS_CLASS32" ascii //weight: 1
        $x_1_3 = {61 76 70 2e 65 78 65 00 64 65 6c 20 25 30 0d 0a}  //weight: 1, accuracy: High
        $x_1_4 = {67 6f 74 6f 20 3a 73 65 6c 66 6b 69 6c 6c 0d 0a}  //weight: 1, accuracy: High
        $x_1_5 = {25 63 3a 5c 00 00 00 00 2e 44 4c 4c}  //weight: 1, accuracy: High
        $x_5_6 = "WriteProcessMemory" ascii //weight: 5
        $x_5_7 = "CreateRemoteThread" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_H_2147598714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.H"
        threat_id = "2147598714"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AutoRun]" wide //weight: 1
        $x_1_2 = "shell\\Auto\\command=" wide //weight: 1
        $x_1_3 = "msnote" wide //weight: 1
        $x_1_4 = "ua_account order by cAcc_id" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL" wide //weight: 1
        $x_1_6 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_7 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_8 = "GetLogicalDriveStringsA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_I_2147598715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.I"
        threat_id = "2147598715"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AUTORUN]" ascii //weight: 1
        $x_1_2 = "txtfile\\shell\\open\\command" ascii //weight: 1
        $x_1_3 = "RecvFile over!" ascii //weight: 1
        $x_1_4 = "Subject: %s" ascii //weight: 1
        $x_1_5 = "Number: %d:Hardware" ascii //weight: 1
        $x_1_6 = "Screen: %d*%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_J_2147598717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.J"
        threat_id = "2147598717"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zeluR maeTCP" wide //weight: 1
        $x_1_2 = {00 00 3a 00 5c 00 41 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: High
        $x_1_3 = "shellexecute = RECYCLER.exe" wide //weight: 1
        $x_1_4 = "Explorer\\Advanced\\ShowSuperHidden" wide //weight: 1
        $x_1_5 = "ren C:\\WINDOWS\\explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_K_2147598894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.K"
        threat_id = "2147598894"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Periferico Conectado!" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "[Autorun]" ascii //weight: 1
        $x_1_4 = {00 3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_L_2147598895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.L"
        threat_id = "2147598895"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NoDriveTypeAutoRun" wide //weight: 1
        $x_1_2 = "autorun.inf" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer" wide //weight: 1
        $x_1_4 = "C:\\Windows\\service.exe" wide //weight: 1
        $x_5_5 = "GetLogicalDrives" ascii //weight: 5
        $x_5_6 = "CopyFileA" ascii //weight: 5
        $x_5_7 = "SearchTreeForFile" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_N_2147598896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.N"
        threat_id = "2147598896"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe /c net stop sharedaccess" wide //weight: 1
        $x_1_2 = "cmd /c route print|find \"Default" wide //weight: 1
        $x_1_3 = "NT$\">>%windir%\\1.inf&" wide //weight: 1
        $x_1_4 = "mctskshd.exe" wide //weight: 1
        $x_1_5 = "mcupdmgr.exe" wide //weight: 1
        $x_1_6 = "rtvscan.exe" wide //weight: 1
        $x_1_7 = "Autorun.inf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_O_2147599145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.O"
        threat_id = "2147599145"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "goto err >nul" wide //weight: 1
        $x_1_2 = "RAM disk" wide //weight: 1
        $x_1_3 = "No root directory" wide //weight: 1
        $x_1_4 = "GetDriveTypeA" wide //weight: 1
        $x_1_5 = "\\secpol.exe" wide //weight: 1
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_7 = ":\\UFO.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_P_2147599146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.P"
        threat_id = "2147599146"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wscript.Shell" wide //weight: 1
        $x_1_2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Rundll" wide //weight: 1
        $x_1_3 = "regwrite" wide //weight: 1
        $x_1_4 = "[autorun]" wide //weight: 1
        $x_1_5 = "shell\\open\\Command=rundll.exe" wide //weight: 1
        $x_1_6 = "\\Autorun.inf" wide //weight: 1
        $x_1_7 = "DriveLetter" wide //weight: 1
        $x_1_8 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_9 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_Q_2147599147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.Q"
        threat_id = "2147599147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "39"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "MSVBVM60.DLL" wide //weight: 20
        $x_1_2 = "Settings\\All Users\\Start Menu\\Programs\\Startup" wide //weight: 1
        $x_1_3 = "Floppy (A:)" wide //weight: 1
        $x_1_4 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_5 = "NOD32" wide //weight: 1
        $x_1_6 = "Norman" wide //weight: 1
        $x_1_7 = "select name from Win32_Process where name=" wide //weight: 1
        $x_1_8 = "Explorer\\Advanced\\Hidden" wide //weight: 1
        $x_5_9 = ":\\autorun.inf" wide //weight: 5
        $x_5_10 = "[AutoRun]" wide //weight: 5
        $x_5_11 = "open=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 3 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_R_2147599148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.R"
        threat_id = "2147599148"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[AutoRun]" wide //weight: 1
        $x_1_2 = "open=" wide //weight: 1
        $x_1_3 = "shellexecute=" wide //weight: 1
        $x_1_4 = "select cAcc_Id from ua_account" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_S_2147602567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.S"
        threat_id = "2147602567"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "autorun.inf" wide //weight: 1
        $x_1_2 = "PRIVMSG" wide //weight: 1
        $x_1_3 = "UMODE -Mm" wide //weight: 1
        $x_2_4 = "!<set|bot|channel|cmd" wide //weight: 2
        $x_2_5 = "|identd|pass|fullname|login" wide //weight: 2
        $x_1_6 = "\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_T_2147607565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.T"
        threat_id = "2147607565"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "filesetattrib,+SAHR,%tmpth%" ascii //weight: 1
        $x_1_2 = "Run,%comspec% /c echo [autoRun]" ascii //weight: 1
        $x_1_3 = "if infline != [autorun]" ascii //weight: 1
        $x_1_4 = "filesetattrib,-SHR,E:\\autorun.inf" ascii //weight: 1
        $x_1_5 = "#singleinstance,force" ascii //weight: 1
        $x_1_6 = "run,%comspec% /c tskill iexplorer,,hide useerrorlevel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Worm_Win32_SillyShareCopy_U_2147608147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.U"
        threat_id = "2147608147"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[Autorun]" wide //weight: 2
        $x_2_2 = "open=JoniEzz.exe" wide //weight: 2
        $x_1_3 = "prop:FileDescription;Size" wide //weight: 1
        $x_1_4 = "Policies\\System\\DisableCMD" wide //weight: 1
        $x_1_5 = "showSuperHidden" wide //weight: 1
        $x_1_6 = "shutdown -s -f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_V_2147608407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.V"
        threat_id = "2147608407"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill.exe" wide //weight: 1
        $x_1_2 = "DisableCMD" wide //weight: 1
        $x_2_3 = "A:\\Passwords.scr" wide //weight: 2
        $x_1_4 = "\\Folder\\Hidden\\NOHIDDEN" wide //weight: 1
        $x_1_5 = "KillApp" ascii //weight: 1
        $x_1_6 = "beatremovable" ascii //weight: 1
        $x_1_7 = "hiddenfolder" ascii //weight: 1
        $x_1_8 = "raradded" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_W_2147608411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.W"
        threat_id = "2147608411"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_2 = "[AUTORUN]" wide //weight: 1
        $x_1_3 = "CODEBASE='index/homedata.EXE" wide //weight: 1
        $x_1_4 = "autorun.inf" wide //weight: 1
        $x_1_5 = {6b 00 69 00 6c 00 6c 00 20 00 70 00 72 00 6f 00 63 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "MonitorMission" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_AK_2147633111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.AK"
        threat_id = "2147633111"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Assignment.exe" ascii //weight: 1
        $x_1_2 = "\\msagent.pif" ascii //weight: 1
        $x_2_3 = {63 3a 00 64 3a 00 65 3a 00 66 3a 00 67 3a 00 68 3a 00 69 3a 00 6a 3a}  //weight: 2, accuracy: High
        $x_1_4 = "DisableTaskMgr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_AL_2147633396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.AL"
        threat_id = "2147633396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "F:\\Sys\\wjr\\VB\\" wide //weight: 2
        $x_1_2 = "[InternetShortcut]" wide //weight: 1
        $x_2_3 = "PPS Accelerator" wide //weight: 2
        $x_1_4 = "ShowSuperHidden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_SillyShareCopy_AQ_2147657444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.AQ"
        threat_id = "2147657444"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shellexecute=" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "open\\command=" wide //weight: 1
        $x_1_4 = "mcisendstringa" ascii //weight: 1
        $x_1_5 = "Khoa" wide //weight: 1
        $x_1_6 = "spersk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_SillyShareCopy_AS_2147666949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/SillyShareCopy.AS"
        threat_id = "2147666949"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "SillyShareCopy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 61 00 76 00 69 [0-256] 2e 00 65 00 78 00 65}  //weight: 10, accuracy: Low
        $x_10_2 = {2e 00 6a 00 70 00 65 00 67 [0-256] 2e 00 65 00 78 00 65}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 6d 00 70 00 33 [0-256] 2e 00 65 00 78 00 65}  //weight: 10, accuracy: Low
        $x_1_4 = "BearshareSpreader" wide //weight: 1
        $x_1_5 = "Edonkey2000Spreader" wide //weight: 1
        $x_1_6 = "EmuleSpreader" wide //weight: 1
        $x_1_7 = "GroksterSpreader" wide //weight: 1
        $x_1_8 = "ICQSpreader" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

