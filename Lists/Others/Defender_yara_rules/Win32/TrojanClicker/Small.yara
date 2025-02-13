rule TrojanClicker_Win32_Small_E_2147583509_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Small.E"
        threat_id = "2147583509"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "winsta0\\default" ascii //weight: 10
        $x_10_2 = "\\\\.\\pipe" ascii //weight: 10
        $x_1_3 = "Program Files\\Internet Explorer\\iexplore.exe drefus.org/fr/?id=us" ascii //weight: 1
        $x_1_4 = "Program Files\\Internet Explorer\\iexplore.exe nwframe.net/fr/?id=us" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanClicker_Win32_Small_JD_2147602507_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Small.JD"
        threat_id = "2147602507"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\KasperskyLab\\protected\\AVP7\\profiles\\AVService\\settings\\Excludes\\0000\\VerdictPath" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\KasperskyLab\\protected\\AVP7\\profiles\\AVService\\settings\\Excludes\\0000\\TaskList" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\KasperskyLab\\protected\\AVP7\\profiles\\AVService\\settings\\Excludes\\0000\\Object" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "KeServiceDescriptorTable" ascii //weight: 1
        $x_1_7 = "\\drivers\\etc\\hosts" ascii //weight: 1
        $x_1_8 = "\\\\.\\RESSDTDOS" ascii //weight: 1
        $x_1_9 = "http://www.google.cn/search?complete=1&hl=zh-CN&inlang=zh-CN&newwindow=1&q=" ascii //weight: 1
        $x_1_10 = "DisableRegistryTools" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Small_JE_2147630297_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Small.JE"
        threat_id = "2147630297"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d 08 00 74 2f 83 65 fc 00 8d 45 fc 50 b8 00 01 00 00 2b c6 50 8b 45 0c 03 c6 50 ff 75 08}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 8b 4d fc 75 04 33 c9 85 c0 0f 95 c0 eb 02 32 c0 84 c0 74 08 85 c9 74 04 03 f1 eb bd 8b c6 5e c9}  //weight: 1, accuracy: High
        $x_1_3 = "http://festival23234.com/flash.php?mode=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Small_AAR_2147745754_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Small.AAR!eml"
        threat_id = "2147745754"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Small"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "75"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {33 d2 b9 1d f3 01 00 f7 f1 8b c8 b8 a7 41 00 00 f7 e2 8b d1 8b c8 b8 14 0b 00 00 f7 e2 2b c8 33 d2 8b c1 89 0d ?? ?? ?? ?? f7 75 08 8b c2 59 5a}  //weight: 40, accuracy: Low
        $x_5_2 = {63 00 72 00 61 00 63 00 6b 00 73 00 70 00 6c 00 61 00 6e 00 65 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 65 00 61 00 64 00 65 00 78 00 65 00 2e 00 68 00 74 00 6d 00 6c 00 28 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00}  //weight: 5, accuracy: Low
        $x_5_3 = {63 72 61 63 6b 73 70 6c 61 6e 65 74 2e 63 6f 6d 2f 72 65 61 64 65 78 65 2e 68 74 6d 6c 28 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 5, accuracy: Low
        $x_5_4 = {63 00 72 00 61 00 63 00 6b 00 64 00 62 00 2e 00 63 00 6f 00 6d 00 0f 00 77 00 77 00 77 00 2e 00}  //weight: 5, accuracy: Low
        $x_5_5 = {63 72 61 63 6b 64 62 2e 63 6f 6d 0f 00 77 77 77 2e}  //weight: 5, accuracy: Low
        $x_10_6 = "ShellExecuteA" ascii //weight: 10
        $x_10_7 = "WriteFile" ascii //weight: 10
        $x_10_8 = "WinExec" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 2 of ($x_10_*) and 3 of ($x_5_*))) or
            ((1 of ($x_40_*) and 3 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

