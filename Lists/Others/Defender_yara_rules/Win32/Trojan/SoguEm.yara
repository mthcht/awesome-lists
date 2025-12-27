rule Trojan_Win32_SoguEm_A_2147957201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SoguEm.A!dha"
        threat_id = "2147957201"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SoguEm"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ba ff 00 00 00 8b 74 24 ?? 89 0c 24 21 d1 21 d5 0f b6 04 08 01 c5 89 ef 21 d7 8b 54 24 ?? 8a 14 3a 88 14 0e 88 04 3e 8b 54 24 ?? 8a 0c 0e 00 c1 0f b6 c1 8b 4c 24 ?? 8a 0c 19 32 0c 06 8b 44 24 ?? 88 0c 1a 8b 1c 24 39 d8}  //weight: 10, accuracy: Low
        $x_9_2 = {31 c9 89 c8 99 f7 ff 8a 04 13 30 44 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f af c2 83 e0 01}  //weight: 9, accuracy: Low
        $x_1_3 = {3f 43 6f 6d 70 61 72 65 46 69 6c 65 4d 6f 64 69 54 69 6d 65 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_4 = {3f 45 6e 75 6d 44 69 72 ?? 43 58 55 73 62 40 40 43 41 58 50 41 5f 57 5f 4e 4b 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_5 = {3f 4c 6f 63 61 6c 43 6f 70 79 46 69 6c 65 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_6 = {3f 55 73 62 43 6f 70 79 46 69 6c 65 50 72 6f 63 ?? 43 58 55 73 62 40 40 43 41 48 50 41 5f 57 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_7 = {3f 55 73 62 43 6f 70 79 46 69 6c 65 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 30 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_8 = {3f 45 6e 63 6f 64 65 4e 61 6d 65 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_9 = {3f 45 6e 63 6f 64 65 42 75 66 66 65 72 ?? 43 58 55 73 62 40 40 43 41 48 50 41 45 48 4b 40 5a}  //weight: 1, accuracy: Low
        $x_1_10 = {3f 55 73 62 44 61 74 45 6e 63 6f 64 65 54 68 72 65 61 64 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 30 40 5a}  //weight: 1, accuracy: Low
        $x_1_11 = {3f 52 65 61 64 44 65 73 6b 46 69 6c 65 ?? 43 58 55 73 62 40 40 43 41 4b 50 41 5f 57 40 5a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_9_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

