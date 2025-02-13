rule Trojan_Win32_ZetaNile_A_2147831332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZetaNile.A"
        threat_id = "2147831332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c1 48 c1 e9 02 f3 ab [0-58] c7 44 24 04 ?? ?? ?? 00 89 ?? 24 e8 ?? ?? 00 00 89 c3 e8 ?? ?? ff ff c7 44 24 18 14 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {b9 00 16 00 00 [0-64] 2c ee 4a 54 66 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_3 = {b9 00 16 00 00 [0-64] ac 5d c9 fd 66 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_1_4 = "Software\\9bis.com\\KiTTY" wide //weight: 1
        $x_1_5 = "Software\\SimonTatham\\PuTTY" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ZetaNile_M_2147832401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZetaNile.M!dha"
        threat_id = "2147832401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZetaNile"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ISSetupPrerequisites\\setup64.exe" ascii //weight: 1
        $x_1_2 = "c:\\colorctrl\\colorui.dll" ascii //weight: 1
        $x_1_3 = "c:\\colorctrl\\colorcpl.exe C3A9B30B6A313F289297C9A36730DB6D" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

