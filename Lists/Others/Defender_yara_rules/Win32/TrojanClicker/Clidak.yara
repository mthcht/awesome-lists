rule TrojanClicker_Win32_Clidak_A_2147654429_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Clidak.A"
        threat_id = "2147654429"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Clidak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 c6 41 03 23 8b 55 f8 c6 42 02 23 8b 45 f8 c6 40 01 23}  //weight: 1, accuracy: High
        $x_10_2 = {77 69 6e 64 6f 77 2e 73 68 6f 77 4d 6f 64 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 77 69 6e 64 6f 77 2e 6f 70 65 6e 3d 6e 75 6c 6c 3b [0-48] 00 73 63 72 69 70 74 00 00 74}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 01 6a 07 6a 01 6a 06 6a 01 6a 05 6a 01 6a 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

