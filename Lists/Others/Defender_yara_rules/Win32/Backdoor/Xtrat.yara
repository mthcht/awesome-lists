rule Backdoor_Win32_Xtrat_A_2147645657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.A"
        threat_id = "2147645657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "frgkmjgtmklgtlrglt" wide //weight: 1
        $x_1_2 = "XTREME" wide //weight: 1
        $x_1_3 = "SOFTWARE\\FakeMessage" wide //weight: 1
        $x_1_4 = "UnitKeylogger" ascii //weight: 1
        $x_1_5 = "UnitInjectServer" ascii //weight: 1
        $x_1_6 = "UnitInjectProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_A_2147645657_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.A"
        threat_id = "2147645657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XTREME" wide //weight: 1
        $x_1_2 = "UnitInjectServer" ascii //weight: 1
        $x_1_3 = "TUnitInfectUSB" ascii //weight: 1
        $x_1_4 = "TServerKeylogger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_A_2147645657_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.A"
        threat_id = "2147645657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qualquercoisarsrsr" wide //weight: 1
        $x_1_2 = "STARTSERVERBUFFER" wide //weight: 1
        $x_2_3 = "XtremeKeylogger" wide //weight: 2
        $x_2_4 = "TUSBSpreader" ascii //weight: 2
        $x_2_5 = "ServerKeyloggerU" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Xtrat_A_2147645657_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.A"
        threat_id = "2147645657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--((Mutex))--PERSIST" wide //weight: 1
        $x_1_2 = "[Process]" wide //weight: 1
        $x_1_3 = "[Clipboard End]" wide //weight: 1
        $x_1_4 = "STARTSERVERBUFFER" wide //weight: 1
        $x_2_5 = "XtremeKeylogger" wide //weight: 2
        $x_2_6 = "TServerKeylogger" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Xtrat_A_2147645657_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.A"
        threat_id = "2147645657"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\XtremeRAT" wide //weight: 1
        $x_1_2 = "SOFTWARE\\FakeMessage" wide //weight: 1
        $x_1_3 = "UnitGetServer" ascii //weight: 1
        $x_1_4 = "UnitKeylogger" ascii //weight: 1
        $x_1_5 = "UnitCryptString" ascii //weight: 1
        $x_1_6 = "UnitInstallServer" ascii //weight: 1
        $x_1_7 = "UnitInjectServer" ascii //weight: 1
        $x_1_8 = "UnitInjectProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_B_2147652515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.B"
        threat_id = "2147652515"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xtreme RAT" wide //weight: 1
        $x_1_2 = "XTREMEBINDER" wide //weight: 1
        $x_1_3 = "XtremeKeylogger" wide //weight: 1
        $x_1_4 = "SOFTWARE\\FakeMessage" wide //weight: 1
        $x_1_5 = "SOFTWARE\\XtremeRAT" wide //weight: 1
        $x_1_6 = "NOINJECT%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Xtrat_C_2147654732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.C"
        threat_id = "2147654732"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 ff d3 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 54 1a ff 33 d7 88 54 18 ff 8d 45 f4}  //weight: 1, accuracy: High
        $x_1_3 = {53 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_D_2147656725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.D"
        threat_id = "2147656725"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Xtreme RAT" wide //weight: 1
        $x_1_2 = "COFTWARE\\XtremeRAT" wide //weight: 1
        $x_1_3 = "Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_4 = {8b 12 83 ea 1e a1 ?? ?? ?? ?? 8b 00 e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_G_2147662540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.G"
        threat_id = "2147662540"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xtreme RAT" wide //weight: 1
        $x_1_2 = "XtremeKeylogger" wide //weight: 1
        $x_1_3 = "XTREMEBINDER" wide //weight: 1
        $x_1_4 = "SOFTWARE\\FakeMessage" wide //weight: 1
        $x_1_5 = "%DEFAULTBROWSER%" wide //weight: 1
        $x_1_6 = ".xtr" wide //weight: 1
        $x_1_7 = "nitKeylogger" ascii //weight: 1
        $x_1_8 = "nitInjectServer" ascii //weight: 1
        $x_1_9 = "server.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Backdoor_Win32_Xtrat_H_2147665364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.H"
        threat_id = "2147665364"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XTREMEBINDER" wide //weight: 1
        $x_1_2 = "NOINJECT%" wide //weight: 1
        $x_1_3 = "[Backspace]" wide //weight: 1
        $x_1_4 = "[Process]" wide //weight: 1
        $x_1_5 = "SOFTWARE\\FakeMessage" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Xtrat_L_2147680028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.L"
        threat_id = "2147680028"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Xtreme" wide //weight: 1
        $x_1_2 = "EBINDER" wide //weight: 1
        $x_1_3 = "unitKeylogger" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\FakeMessage" wide //weight: 1
        $x_1_5 = "[CLIPBOARD] --" wide //weight: 1
        $x_1_6 = "NOINJECT%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_Win32_Xtrat_2147687552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat"
        threat_id = "2147687552"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 00 83 f0 ?? 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01}  //weight: 10, accuracy: Low
        $x_1_2 = "cgl-bin/Crpq2.cgi" ascii //weight: 1
        $x_1_3 = "cgl-bin/Clnpp5.cgi" ascii //weight: 1
        $x_1_4 = "cgl-bin/Rwpq1.cgi" ascii //weight: 1
        $x_1_5 = "cgm-bin/dieosn83.cgi" ascii //weight: 1
        $x_1_6 = "cgl-bin/Dwpq3ll.cgi" ascii //weight: 1
        $x_1_7 = "JesusMadonna" ascii //weight: 1
        $x_1_8 = "seiow32.exe" ascii //weight: 1
        $x_1_9 = "aq0211" ascii //weight: 1
        $x_1_10 = "delay.ygto.com/trandocs/mm/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Xtrat_P_2147706837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Xtrat.P"
        threat_id = "2147706837"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Xtrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\Windows Error Reporting\" /v DontShowUI /t REG_DWORD /d 1 /f" wide //weight: 1
        $x_1_2 = "upnp.exe" wide //weight: 1
        $x_1_3 = "VB5 Setup Toolkit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

