rule Trojan_Win64_Slingshot_A_2147726434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Slingshot.A!dha"
        threat_id = "2147726434"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Slingshot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LineRecs" ascii //weight: 1
        $x_1_2 = "CRT1N1T" ascii //weight: 1
        $x_2_3 = {68 fe ca 0d 0f 48 83 ec 30 90 e8 ?? ?? ?? ?? 48 89 dc 5b 8b 05 ?? ?? ?? ?? 83 e0 20 74 ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 74}  //weight: 2, accuracy: Low
        $x_1_4 = {48 83 e7 fc 8b 0d ?? ?? ?? ?? 81 c1 [0-16] c1 e9 02 31 c0 f3 ab 5f 58 48 8d 0d ?? ?? ?? ?? 48 31 d2 41 b8 00 80 00 00 ff e0}  //weight: 1, accuracy: Low
        $x_1_5 = {75 0a b8 39 01 00 c0 e9 ?? ?? 00 00 8b 93 ?? ?? 00 00 33 c9 41 b8 00 10 00 00 44 8d 49 04 ff d0 48 89 83 ?? ?? 00 00 48 85 c0 75 1e 65 8b 04 25 ?? ?? 00 00 b9 17 00 00 c0 ba 04 06 00 c0 3d 77 06 00 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 8b 51 10 c7 45 ?? 6c 00 2e 00 c7 45 ?? 64 00 6c 00 c7 45 ?? 6c 00 00 00}  //weight: 1, accuracy: Low
        $x_2_7 = {e8 89 ca a0 c7 45 ?? b7 d7 ca a2 c7 45 ?? b0 bb e5 d1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

