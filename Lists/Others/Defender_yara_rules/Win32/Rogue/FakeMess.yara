rule Rogue_Win32_FakeMess_149554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeMess"
        threat_id = "149554"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeMess"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 06 83 3e 00 75 06 c7 06 01 00 00 00 83 3e 01 75 0c 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3e 02}  //weight: 3, accuracy: Low
        $x_3_2 = {8b f0 b8 09 00 00 00 e8 ?? ?? ?? ?? 03 f0 8b d6 8b c3 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 80 ?? ?? 00 00 e8 ?? ?? ?? ?? 83 f8 64 7d}  //weight: 3, accuracy: Low
        $x_1_3 = {50 61 63 6b 65 64 2e 57 69 6e 33 32 2e 4b 61 74 75 73 68 61 2e 6a 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 65 74 2d 57 6f 72 6d 2e 57 69 6e 33 32 2e 4b 6f 6c 61 62 2e 68 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 32 50 2d 57 6f 72 6d 2e 57 69 6e 33 32 2e 50 61 6c 65 76 6f 2e 61 63 73 61 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 73 65 63 75 72 69 74 79 5f 65 73 73 65 6e 74 69 61 6c 73 2f 3f 6d 6b 74 3d 72 75 2d 72 75 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

