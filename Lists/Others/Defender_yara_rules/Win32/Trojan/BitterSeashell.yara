rule Trojan_Win32_BitterSeashell_B_2147955334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BitterSeashell.B!dha"
        threat_id = "2147955334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BitterSeashell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 15 b0 02 45 e8 28 04 39 8b ?? ?? 41 89 ?? ?? 81 f9}  //weight: 1, accuracy: Low
        $x_5_2 = {6a 04 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 ff d0}  //weight: 5, accuracy: Low
        $x_1_3 = {30 0a 00 00 31 0a 00 00 32 0a 00 00 33 0a 00 00 34 0a 00 00 35 0a 00 00 36 0a 00 00 37 0a 00 00 38 0a 00 00 38 38 38 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

