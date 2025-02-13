rule Rogue_Win32_Rudoct_154222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Rudoct"
        threat_id = "154222"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudoct"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 43 44 65 66 65 6e 64 65 72 53 69 6c 65 6e 74 53 65 74 75 70 2e 6d 73 69 22 0d 0a 66 69 6c 65 5f 54 6f 5f 44 6f 6e 77 6c 6f 61 64 20 3d 20 22 22 20 26 20 72 6e 64 53 74 72 20 26 20 22 2e 6d 73 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Rudoct_154222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Rudoct"
        threat_id = "154222"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudoct"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "securityLevelShield" wide //weight: 1
        $x_1_2 = "securityDiv_virusProtection" wide //weight: 1
        $x_1_3 = "settingsStartWithWindows" wide //weight: 1
        $x_1_4 = "The serial number is wrong!" wide //weight: 1
        $x_1_5 = "numberOfThreatsFound" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_Rudoct_154222_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Rudoct"
        threat_id = "154222"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudoct"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s%s.dll" wide //weight: 2
        $x_2_2 = "SPIDER.GIF" wide //weight: 2
        $x_2_3 = "lastUpdateTime" wide //weight: 2
        $x_3_4 = "lastScanResults" wide //weight: 3
        $x_3_5 = "lastScanTime" wide //weight: 3
        $x_6_6 = "BSOD.CUR" wide //weight: 6
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_Rudoct_154222_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/Rudoct"
        threat_id = "154222"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "Rudoct"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exception unknown software exception (0x000000" wide //weight: 1
        $x_1_2 = {73 00 74 00 61 00 72 00 74 00 57 00 69 00 74 00 68 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "/im prockill32.exe /im prockill64.exe /f" wide //weight: 1
        $x_1_4 = "_count_buys.vbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

