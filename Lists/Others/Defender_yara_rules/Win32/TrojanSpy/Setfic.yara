rule TrojanSpy_Win32_Setfic_A_2147627909_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Setfic.A"
        threat_id = "2147627909"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Setfic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fc 51 ad 03 c5 50 ff b5 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? ff d0 ab 59 e2 e9 8d 85 ?? ?? ?? ?? 50 68 01 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {74 07 3d 48 45 41 44 75 37 2b d2 ac 42 3c 20}  //weight: 1, accuracy: High
        $x_1_3 = {81 3e 55 53 45 52 75 6e 83 f8 6e 74 69 a1 ?? ?? ?? ?? 50 c1 e0 02}  //weight: 1, accuracy: Low
        $x_1_4 = {50 72 78 52 75 6e 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

