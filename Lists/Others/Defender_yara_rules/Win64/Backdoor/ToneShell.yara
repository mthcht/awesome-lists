rule Backdoor_Win64_ToneShell_A_2147957206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ToneShell.A!dha"
        threat_id = "2147957206"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 c0 31 cb 44 4e 8d 52 01 0f be c9 03 c1 8a 0a 84 c9}  //weight: 10, accuracy: High
        $x_10_2 = {69 c0 31 5e c8 00 8d 52 01 0f be c9 03 c1 8a 0a 84 c9}  //weight: 10, accuracy: High
        $x_10_3 = {69 ff 31 5e c8 00 0f be c0 03 f8 43 8a 03 84 c0}  //weight: 10, accuracy: High
        $x_1_4 = {8d 43 20 8d 53 bf 0f b6 c8 0f b6 c3 8d 7f 02 80 fa 19 0f 47 c8 0f b7 07 69 f6 31 5e c8 00 8a d8 0f be c9 03 f1 66 85 c0}  //weight: 1, accuracy: High
        $x_1_5 = {8d 48 20 8d 58 bf 0f b6 d1 0f b6 c8 8d 76 02 80 fb 19 0f 47 d1 0f b7 0e 69 ff 31 5e c8 00 8a c1 0f be d2 03 fa 66 85 c9}  //weight: 1, accuracy: High
        $x_1_6 = {8d 43 20 8d 53 bf 0f b6 c8 80 fa 19 0f b6 c3 8d 76 02 0f 47 c8 69 ff 31 5e c8 00 0f be c9 03 f9 0f b7 0e 8a d9 66 85 c9}  //weight: 1, accuracy: High
        $x_1_7 = {8d 50 bf 8d 48 20 80 fa 19 0f b6 c9 8d 7f 02 0f b6 c0 0f 47 c8 69 db 31 cb 44 4e 0f be c9 03 d9 0f b7 0f 8a c1 66 85 c9}  //weight: 1, accuracy: High
        $x_1_8 = {8d 50 bf 8d 48 20 80 fa 19 0f b6 c9 8d 76 02 0f b6 c0 0f 47 c8 69 c3 31 5e c8 00 0f be c9 8d 1c 08 0f b7 0e 8a c1 66 85 c9}  //weight: 1, accuracy: High
        $x_1_9 = {8a 1f 8d 7f 02 8d 43 20 8d 53 bf 0f b6 c8 80 fa 19 0f b6 c3 0f 47 c8 69 45 fc 31 5e c8 00 0f be c9 03 c8 89 4d fc 66 39 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_ToneShell_B_2147957207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ToneShell.B!dha"
        threat_id = "2147957207"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 76 63 68 c7 45 ?? 79 73 74 65 c7 45 ?? 43 3a 5c 57 c7 45 ?? 65 78 65 00 c7 45 ?? 57 53 5c 73 c7 45 ?? 49 4e 44 4f c7 45 ?? 6d 33 32 5c c7 45 ?? 6f 73 74 2e}  //weight: 1, accuracy: Low
        $x_1_2 = {74 61 5c 62 c7 45 ?? 72 65 2e 74 c7 45 ?? 6d 69 74 69 c7 45 ?? 43 3a 5c 50 c7 45 ?? 72 6f 67 72 c7 45 ?? 63 72 79 70 c7 45 ?? 61 6d 44 61 c7 45 ?? 62 69 00 00 c7 45 ?? 76 65 2e 61 c7 45 ?? 74 70 72 69}  //weight: 1, accuracy: Low
        $x_1_3 = {69 c8 f1 00 02 00 [0-10] 69 c0 e1 e2 c4 03 69 ff c1 09 9a 77 [0-20] 69 c0 d1 95 1b 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win64_ToneShell_D_2147957208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/ToneShell.D!dha"
        threat_id = "2147957208"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "ToneShell"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 8d 14 19 43 8a 04 08 30 82 00 01 00 00 8b 86 fc 04 00 00 2d 00 01 00 00 3b d8}  //weight: 1, accuracy: High
        $x_1_2 = {fd 43 03 00 8b ?? ?? ?? ?? ?? 81 ?? c3 9e 26 00 89 ?? ?? ?? ?? ?? 88 ?? ?? 69 ?? ?? ?? ?? ?? fd 43 03 00 8b ?? ?? ?? ?? ?? 81 ?? c3 9e 26 00 89 ?? ?? ?? ?? ?? 88 ?? ?? ?? 69 ?? ?? ?? ?? ?? fd 43 03 00 8b ?? ?? ?? ?? ?? 81 ?? c3 9e 26 00 89 ?? ?? ?? ?? ?? 88 ?? ?? ?? 69 ?? ?? ?? ?? ?? fd 43 03 00}  //weight: 1, accuracy: Low
        $x_1_3 = {33 ff 0f b7 45 fc 89 ?? ?? ?? ?? ?? 66 c7 45 f8 01 bb 66 89 ?? ?? ?? ?? ?? 0f b7 45 f8 c7 ?? ?? ?? ?? ?? 02 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

