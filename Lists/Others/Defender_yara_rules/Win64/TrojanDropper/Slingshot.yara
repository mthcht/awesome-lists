rule TrojanDropper_Win64_Slingshot_A_2147726430_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Slingshot.A.dll!dha"
        threat_id = "2147726430"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Slingshot"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 53 6c 69 6e 67 73 68 6f 74 00}  //weight: 1, accuracy: High
        $x_1_2 = "LineRecs" ascii //weight: 1
        $x_1_3 = {00 50 45 4d 43 52 54 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 61 6e 64 72 61 00}  //weight: 1, accuracy: High
        $x_1_5 = "-1000\\$RWR7EMB.tmp" ascii //weight: 1
        $x_2_6 = {53 00 73 00 20 00 2d 00 61 00 20 00 [0-16] 20 00 2d 00 73 00 20 00 [0-16] 20 00 2d 00 6f 00}  //weight: 2, accuracy: Low
        $x_2_7 = {53 73 20 2d 61 20 [0-16] 20 2d 73 20 [0-16] 20 2d 6f}  //weight: 2, accuracy: Low
        $x_2_8 = {68 fe ca 0d 0f 48 83 ec 30 90 e8 ?? ?? ?? ?? 48 89 dc 5b 8b 05 ?? ?? ?? ?? 83 e0 20 74 ?? 48 8b 05 ?? ?? ?? ?? 48 85 c0 74}  //weight: 2, accuracy: Low
        $x_1_9 = {48 83 e7 fc 8b 0d ?? ?? ?? ?? 81 c1 [0-16] c1 e9 02 31 c0 f3 ab 5f 58 48 8d 0d ?? ?? ?? ?? 48 31 d2 41 b8 00 80 00 00 ff e0}  //weight: 1, accuracy: Low
        $x_2_10 = {41 80 38 50 75 26 41 80 78 01 45 75 1f 41 80 78 02 4d 75 18 41 80 78 03 43 75 11 41 80 78 04 52 75 0a 41 80 78 05 54 75 03 4d 89 11 4d 85 d2 75 07 b8 17 00 00 c0}  //weight: 2, accuracy: High
        $x_1_11 = {74 2a 4b 89 04 37 48 ff c7 4c 8b ff 48 89 7c 24 50 49 c1 e7 03 4b 8d 04 27 48 83 38 00 0f 85 7a ff ff ff 48 83 c3 14 e9 20 ff ff ff b8 39 01 00 c0 eb 09 b8 6f 03 00 c0 eb 02}  //weight: 1, accuracy: High
        $x_2_12 = {41 0f b7 04 08 66 83 c8 20 66 39 01 75 ?? ff c2 48 83 c1 02 83 fa 0c 7c e7 48 8b 7f 30 b8 4d 5a 00 00 66 3b 07 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

