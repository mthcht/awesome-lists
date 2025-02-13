rule Trojan_Win32_Wysotot_A_2147683975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.A"
        threat_id = "2147683975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "up.soft365.com/Gdp/finish" wide //weight: 1
        $x_1_2 = "Begin Start ShortcutMon" wide //weight: 1
        $x_1_3 = ".?AVCeGdpSvcShortcutMon@" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\eSafeSecControl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wysotot_B_2147684065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.B"
        threat_id = "2147684065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 17 6a 00 ff d6 6a 01 6a 00 53 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0c 30 02 c8 40 3b c7 72 f6 b0 01 c3}  //weight: 1, accuracy: High
        $x_1_3 = {74 09 3c 5a 74 05 34 5a 88 04 11 41 3b ce 72 eb}  //weight: 1, accuracy: High
        $x_1_4 = {44 50 72 6f 74 65 63 74 53 76 63 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Wysotot_C_2147684192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.C"
        threat_id = "2147684192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\eGdp\\bin\\win32\\Release\\eGdpSvc.pdb" ascii //weight: 1
        $x_1_2 = {57 00 73 00 79 00 73 00 53 00 76 00 63}  //weight: 1, accuracy: High
        $x_1_3 = {65 00 53 00 61 00 66 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 6f}  //weight: 1, accuracy: High
        $x_1_4 = {75 00 6e 00 73 00 76 00 63 00 00 00 72 00 75 00 6e 00 00 00 6b 00 69 00 6c 00 6c 00 00 00 00 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 00 64 00 6d 00 2e 00 73 00 6f 00 66 00 74 00 33 00 36 00 35 00 2e 00 63 00 6f 00 6d 00 2f 00 67 00 64 00 70 00 2f 00 73 00 6f 00 66 00 74 00 75 00 70 00 64 00 61 00 74 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Wysotot_A_2147685050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.gen!A"
        threat_id = "2147685050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00 00 [0-4] 6f 00 70 00 65 00 72 00 61 00 2e 00 65 00 78 00 65 00 00 [0-4] 66 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 74 00 61 00 72 00 74 00 4d 00 65 00 6e 00 75 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 00 [0-4] 73 00 68 00 65 00 6c 00 6c 00 5c 00 6f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = "e:\\labs\\out\\v9home_tools\\Release\\v9ht.pdb" ascii //weight: 1
        $x_1_4 = ".?AVCV9home_toolsApp" ascii //weight: 1
        $x_1_5 = ".lnk" wide //weight: 1
        $x_1_6 = {68 6f 6d 65 70 61 67 65 00 [0-48] 68 6f 6d 65 70 61 67 65 5f 63 68 61 6e 67 65 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Wysotot_2147685615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot"
        threat_id = "2147685615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "SOFTWARE\\Updater" wide //weight: 5
        $x_5_2 = "www.osdsoft.com/download2/WindowsUpdater.exe#" wide //weight: 5
        $x_5_3 = "54.214.246.97/log/" wide //weight: 5
        $x_1_4 = "_updater/" wide //weight: 1
        $x_1_5 = "logUrl=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wysotot_E_2147685978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.E"
        threat_id = "2147685978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "43"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "WilSys Control" wide //weight: 10
        $x_10_2 = "%s Browser Protecter" wide //weight: 10
        $x_10_3 = "xa.xingcloud.com" wide //weight: 10
        $x_10_4 = "/C taskkill /F /IM firefox.exe" wide //weight: 10
        $x_1_5 = "v9.com" wide //weight: 1
        $x_1_6 = "onmylike.com" wide //weight: 1
        $x_1_7 = "22apple.com" wide //weight: 1
        $x_1_8 = "qvo6.com" wide //weight: 1
        $x_1_9 = "portaldosites.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wysotot_F_2147687888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wysotot.F"
        threat_id = "2147687888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wysotot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "eXQ Control" wide //weight: 10
        $x_10_2 = "%s Browser Protecter" wide //weight: 10
        $x_10_3 = "/C taskkill /F /IM firefox.exe" wide //weight: 10
        $x_10_4 = {5c 00 5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 25 00 64 00 00 00 65 6c 65 78 00}  //weight: 10, accuracy: High
        $x_1_5 = "xa.xingcloud.com" wide //weight: 1
        $x_1_6 = "v9.com" wide //weight: 1
        $x_1_7 = "onmylike.com" wide //weight: 1
        $x_1_8 = "22apple.com" wide //weight: 1
        $x_1_9 = "qvo6.com" wide //weight: 1
        $x_1_10 = "portaldosites.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

