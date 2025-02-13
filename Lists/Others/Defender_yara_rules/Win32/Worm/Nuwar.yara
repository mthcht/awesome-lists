rule Worm_Win32_Nuwar_JZ_2147604907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nuwar.JZ"
        threat_id = "2147604907"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8b 40 14 89 45 d4 8b 45 f8 8b 40 10 89 45 d8 [0-64] 83 7d d4 00 75 [0-96] c7 45 ec b9 79 37 9e [0-64] 69 c0 b9 79 37 9e}  //weight: 1, accuracy: Low
        $x_10_2 = {8b 45 e4 c1 e8 05 8b 4d f0 c1 e1 02 33 c1 8b 4d f0 c1 e9 03 8b 55 e4 c1 e2 04 33 ca 03 c1 8b 4d e0 33 4d f0 8b 55 f4 83 e2 03 33 55 dc 8b 75 f8 8b 14 96 33 55 e4 03 ca 33 c1 8b 4d f4 8b 55 d8 8b 0c 8a 2b c8 8b 45 f4 8b 55 d8 89 0c 82 8b 45 f4 8b 4d d8 8b 04 81 89 45 f0}  //weight: 10, accuracy: High
        $x_1_3 = {42 01 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 00 55 02 4c 6f 61 64 4c 69 62 72 61 72 79 57 00 00 a0 01 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 7f 01 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Nuwar_KA_2147605144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nuwar.KA"
        threat_id = "2147605144"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec [0-240] 8b 45 ?? 8b 40 ?? 89 45 ?? 8b 45 ?? 8b 40 ?? 89 45 [0-64] 83 7d ?? 00 75 90 00 [0-80] c7 45 ?? b9 79 37 9e [0-24] 6a 34 58 99 [0-40] 69 c0 b9 79 37 9e}  //weight: 1, accuracy: Low
        $x_2_2 = {c1 e8 05 8b 4d ?? c1 e1 02 33 c1 8b 4d ?? c1 e9 03 8b 55 ?? c1 e2 04 33 ca 03 c1 8b 4d ?? 33 4d ?? 8b 55 ?? 83 e2 03 33 55 ?? 8b 75 ?? 8b 14 96 33 55 ?? 03 ca 33 c1 8b 4d [0-72] e9 ?? ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Nuwar_KC_2147606530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Nuwar.KC"
        threat_id = "2147606530"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 28 20 42 00 ff [0-40] 68 34 20 42 00 ff [0-56] 6a 02 58 e9 ?? ?? 00 00 [0-232] 8b ?? ?? 00 20 42 00 [0-112] e8 ?? ?? 00 00 5f 5e 5b c9 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 00 63 61 6c 63 2e 65 78 65 00 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

