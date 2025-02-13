rule Virus_Win32_Pidgeon_A_2147649040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Pidgeon.A"
        threat_id = "2147649040"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Pidgeon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 62 32 33 31 32 [0-32] 3d 3f 67 62 32 33 31 32 3f 42 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {62 6f 75 6e 64 61 72 79 3d 22 23 42 4f 55 4e 44 41 52 59 23 22 [0-16] 52 65 70 6c 79 2d 54 6f 3a 20 25 73 [0-16] 46 72 6f 6d 3a 20 25 73 [0-16] 54 6f 3a 20 25 73 [0-16] 53 75 62 6a 65 63 74 3a 20 25 73}  //weight: 1, accuracy: Low
        $x_2_3 = {6a 00 ff 74 24 ?? 6a 00 ff 74 24 ?? ff 71 04 ff 15 ?? ?? ?? 00 85 c0 75 ?? 50 ff 15 ?? ?? ?? 00 50 e8 ?? ?? ?? 00 c2 ?? 00 6a 00 ff 74 24 ?? 6a 00 ff 74 24 ?? ff 71 04 ff 15 ?? ?? ?? 00 85 c0 75 ?? 50 ff 15 ?? ?? ?? 00 50 e8 ?? ?? ?? 00 c2 ?? 00 56 8b f1 6a 00 8b 06 ff 74 24 ?? ff 50 ?? ff 76 04 ff 15 ?? ?? ?? 00 85 c0 5e 75 ?? 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_4 = {68 06 00 00 00 e8 ?? ?? ?? 00 83 c4 04 85 c0 0f 84 ?? ?? ?? 00 c7 45 f4 01 00 00 00 e9 ?? ?? 00 00 83 7d ?? 09 0f 85 ?? ?? 00 00 89 65 ?? 68 04 01 00 00 ff 75 ?? b8 10 00 00 00 e8 ?? ?? ?? 00 39 65 ?? 74 ?? 68 06 00 00 00 e8}  //weight: 2, accuracy: Low
        $x_2_5 = {bb 01 00 00 00 8b 84 24 60 01 00 00 8b 30 83 fb 01 75 ?? 85 f6 74 ?? 8d 4c 24 10 51 56 ff 15 ?? ?? ?? 00 8b f8 eb ?? 85 f6 74 ?? 56 ff 15 ?? ?? ?? 00 8d 54 24 10 52 57 ff 15 ?? ?? ?? 00 8b f0 83 fe ff 75 ?? 33 f6 33 ff eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

