rule PWS_Win32_Yahoopass_E_2147605654_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahoopass.E"
        threat_id = "2147605654"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahoopass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" wide //weight: 1
        $x_1_2 = "C*\\AJ:\\Yakoza v3.5\\server\\Server.vbp" wide //weight: 1
        $x_1_3 = "L$_RasDefaultCredentials#0" wide //weight: 1
        $x_1_4 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_5 = "CreateRemoteThread" ascii //weight: 1
        $x_1_6 = "WriteProcessMemory" ascii //weight: 1
        $x_1_7 = "YahooBuddyMain" wide //weight: 1
        $x_1_8 = "CIEPasswords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yahoopass_F_2147605655_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahoopass.F"
        threat_id = "2147605655"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahoopass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKCU\\software\\microsoft\\windows\\currentversion\\policies\\system\\disableregistrytools" wide //weight: 1
        $x_1_2 = "HKCU\\software\\microsoft\\windows\\currentversion\\policies\\system\\DisableTaskMgr" wide //weight: 1
        $x_1_3 = "Microsoft\\Network\\Connections\\pbk\\rasphone.pbk" wide //weight: 1
        $x_1_4 = "HKCU\\software\\Yahoo\\Pager\\Save Password" wide //weight: 1
        $x_1_5 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_6 = "L$_RasDefaultCredentials#0" wide //weight: 1
        $x_1_7 = "FtpSetCurrentDirectoryA" ascii //weight: 1
        $x_1_8 = "LsaRetrievePrivateData" ascii //weight: 1
        $x_1_9 = "YahooBuddyMain" wide //weight: 1
        $x_1_10 = "ShellExecuteA" ascii //weight: 1
        $x_1_11 = "wscript.shell" wide //weight: 1
        $x_1_12 = "YTopWindow" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yahoopass_G_2147607810_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahoopass.G"
        threat_id = "2147607810"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahoopass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server]" wide //weight: 1
        $x_1_2 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\ShowSuperHidden" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Active Setup\\Installed Components" wide //weight: 1
        $x_1_4 = "Program Files\\Yahoo!\\Messenger\\Profiles\\" wide //weight: 1
        $x_1_5 = "HKCU\\software\\Yahoo\\Pager\\Save Password" wide //weight: 1
        $x_1_6 = "InternetExplorerPassword" wide //weight: 1
        $x_1_7 = "DialUp Password From Yakoza" wide //weight: 1
        $x_1_8 = "Yahoo Password From Yakoza" wide //weight: 1
        $x_1_9 = "Yahoo Archive From Yakoza" wide //weight: 1
        $x_1_10 = "YahooBuddyMain" wide //weight: 1
        $x_1_11 = "wscript.shell" wide //weight: 1
        $x_1_12 = "Scripting.FileSystemObject" wide //weight: 1
        $x_1_13 = "YTopWindow" wide //weight: 1
        $x_1_14 = "YLoginWnd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Yahoopass_H_2147614088_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahoopass.H"
        threat_id = "2147614088"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahoopass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 6c 61 63 69 61 6c 20 44 72 61 63 6f 6e 00 00 2d 00 00 00 25 73}  //weight: 2, accuracy: High
        $x_2_2 = {65 6d 62 65 64 64 69 6e 67 [0-2] 73 6f 6c [0-4] 73 68 75 74 64 6f 77 6e [0-4] 2d 73}  //weight: 2, accuracy: Low
        $x_2_3 = {25 53 59 53 54 45 4d 52 4f 4f 54 25 [0-2] 2f 46 20 63 3a 5c 2a 2e 2a [0-4] 64 65 6c 20 2f 41 3a 53 20 2f 51 20 [0-4] 63 3a 5c 6e 74 6c 64 72 2e 62 61 74}  //weight: 2, accuracy: Low
        $x_2_4 = {61 2e 30 36 [0-2] 67 6f 6f 67 6c 65 [0-3] 2e 64 6c 6c [0-4] 5c 67 6f 6f 67 6c 65 3f 3f 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_5 = {68 00 00 00 40 05 60 01 00 00 50 ff 15 ac 10 80 67 8b d8 83 fb ff 74 4e 39 75 f0 74 42 56 8d 45 0c 50 ff 75 e8 e8 bb 03 00 00 8b 35 58 10 80 67 59 40 50 ff 75 e8 53 ff d6 8b 7d ec 2b 7d f0 68 40 12 80 67 57 ff 75 f0 e8 61 11 00 00 83 c4 0c 6a 00 8d 45 0c 50 57 ff 75 f0 53 ff d6 33 f6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule PWS_Win32_Yahoopass_J_2147624525_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Yahoopass.J"
        threat_id = "2147624525"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahoopass"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\MY Project\\Viros\\Yahoo Pass & dail\\SenMail.vbp" wide //weight: 1
        $x_1_2 = "HAck Password Yahoo % Acc Net" ascii //weight: 1
        $x_1_3 = {5c 76 69 72 6f 73 5c 79 61 68 6f 6f 20 70 61 73 01 00}  //weight: 1, accuracy: High
        $x_1_4 = "YAHOO MESSNEGER" wide //weight: 1
        $x_1_5 = "VicMst IP System :" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

