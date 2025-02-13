rule PWS_Win32_Steam_B_2147596575_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.B"
        threat_id = "2147596575"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\PassStealer 3.0\\Projekt1.vbp" wide //weight: 10
        $x_10_2 = "steam.exe /start >steam.exetemp.txt" wide //weight: 10
        $x_10_3 = "\\steam.exetemp.bat" wide //weight: 10
        $x_1_4 = "ShowSteamLogin" ascii //weight: 1
        $x_1_5 = "ShellExecuteA" ascii //weight: 1
        $x_1_6 = "ShellExecAndWait" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Steam_C_2147596739_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.C"
        threat_id = "2147596739"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Dokumente und Einstellungen\\Admin\\Desktop\\Projekte\\Steam Steal0r" wide //weight: 1
        $x_1_2 = "SHDocVwCtl.WebBrowser" ascii //weight: 1
        $x_1_3 = "?info=Steam Steal0r v2 by -=Player=-&acc=" wide //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\shdocvw.oca" ascii //weight: 1
        $x_1_5 = "c:\\error_log.exe" wide //weight: 1
        $x_1_6 = "F-A7EBProject1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule PWS_Win32_Steam_E_2147604955_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.E"
        threat_id = "2147604955"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableTaskMgr" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\DisableRegistryTools" wide //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System\\DisableCMD" wide //weight: 1
        $x_1_4 = "cmd.exe /c net stop SharedAccess" wide //weight: 1
        $x_1_5 = "cmd.exe /c reg add " wide //weight: 1
        $x_1_6 = "Wscript.shell" wide //weight: 1
        $x_1_7 = "Desktop\\Steam" wide //weight: 1
        $x_1_8 = "RegisterServiceProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Steam_F_2147605150_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.F"
        threat_id = "2147605150"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "steamcrack" ascii //weight: 1
        $x_1_2 = "Steam Game Cracker" ascii //weight: 1
        $x_1_3 = "Desktop\\Steam Phishing" wide //weight: 1
        $x_1_4 = "Cracked_Account_Info.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Steam_I_2147650293_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.I"
        threat_id = "2147650293"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 74 65 61 6d 00 53 74 65 61 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "Steam Account Hacker" ascii //weight: 1
        $x_1_3 = "Steam Stealer : Steam Login" wide //weight: 1
        $x_1_4 = "Steam Stealer : Email login" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Steam_J_2147688207_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.J"
        threat_id = "2147688207"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/crypt.php?d=1" ascii //weight: 1
        $x_1_2 = "82.146.53.11" ascii //weight: 1
        $x_1_3 = "_desktop.com" ascii //weight: 1
        $x_1_4 = "domain=%s&count=1&fname_1=%ls&fcont_1=%s" ascii //weight: 1
        $x_1_5 = "\\ssfn*" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Steam_P_2147734237_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.P!bit"
        threat_id = "2147734237"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SteamHook\\new\\SteamGhost\\Release\\Injection.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Steam_Q_2147734903_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Steam.Q!bit"
        threat_id = "2147734903"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Steam"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "43.248.186.95:90/jieshousteam.php" ascii //weight: 1
        $x_1_2 = "steamclient.dll" ascii //weight: 1
        $x_1_3 = "#in_password" ascii //weight: 1
        $x_1_4 = "#mb_critical" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

