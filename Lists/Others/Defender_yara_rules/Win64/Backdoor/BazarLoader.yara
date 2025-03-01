rule Backdoor_Win64_Bazarloader_STA_2147767122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarloader.STA"
        threat_id = "2147767122"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 00 00 00 00 59 [0-32] b9 05 00 00 00 [0-10] 83 e4 f0 ?? 83 ec 30 c7 ?? ?? ?? 01 00 00 00 e8 05 00 00 00}  //weight: 10, accuracy: Low
        $x_3_2 = {05 62 61 7a 61 72 00}  //weight: 3, accuracy: High
        $x_3_3 = {2e 62 61 7a 61 72 00}  //weight: 3, accuracy: High
        $x_3_4 = {2e 64 6c 6c 00 53 74 61 72 74 46 75 6e 63 00}  //weight: 3, accuracy: High
        $x_3_5 = {77 73 32 5f 33 32 64 6c 6c 00 6e 74 64 6c 6c 2e 64 6c 6c 00 73 68 65 6c 6c 33 32 2e 64 6c 6c 00 77 69 6e 69 6e 65 74 2e 64 6c 6c 00 75 72 6c 6d 6f 6e 2e 64 6c 6c}  //weight: 3, accuracy: High
        $x_1_6 = {b9 49 f7 02 78 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_7 = {b9 58 a4 53 e5 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_8 = {b9 10 e1 8a c3 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_9 = {b9 af b1 5c 94 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_10 = {b9 33 00 9e 95 [0-8] e8}  //weight: 1, accuracy: Low
        $x_1_11 = {48 8b 00 48 b9 00 00 00 00 ff ff ff ff 48 8b 40 30 48 23 c1 48 89 ?? ?? ?? 48 8b ?? ?? ?? 8b 40 08 48 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 4 of ($x_1_*))) or
            ((4 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Bazarloader_SSA_2147787444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Bazarloader.SSA"
        threat_id = "2147787444"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Bazarloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 55 41 54 57 56 53 48 83 ec 50 48 b8 [0-8] 8b 9c 24 a8 00 00 00 8b b4 24 b0 00 00 00 48 8b bc 24 b8 00 00 00 48 89 44 24 40 45 89 c5 45 89 c8 49 89 d4}  //weight: 5, accuracy: Low
        $x_5_2 = {c7 44 24 3c [0-4] 4c 8b 8c 24 a0 00 00 00 c7 44 24 48 [0-4] c6 44 24 4c 00 48 89 44 24 34 31 c0}  //weight: 5, accuracy: Low
        $x_5_3 = {4c 8b 4c 24 28 44 89 ea 4c 89 e1 44 8b 44 24 24 48 89 bc 24 b0 00 00 00 89 b4 24 a8 00 00 00 89 9c 24 a0 00 00 00 48 83 c4 50 5b 5e 5f 41 5c 41 5d 48 ff e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

