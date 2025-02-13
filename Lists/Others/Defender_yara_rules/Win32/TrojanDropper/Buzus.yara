rule TrojanDropper_Win32_Buzus_A_2147603255_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Buzus.gen!A"
        threat_id = "2147603255"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "112"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {00 00 00 00 2c 02 52 65 73 75 6d 65 54 68 72 65 61 64 00 00 83 02 53 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00 c4 02 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 45 78 00 00 e9 02 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 bc 02 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 00 3e 01 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00 00 c2 01 4c 6f 61 64 4c 69 62 72 61 72 79 41 00 00 1c 02 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 67 01 47 65 74 54 68 72 65 61 64 43 6f 6e 74 65 78 74 00 00 44 00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 ca 00 47 65 74}  //weight: 50, accuracy: High
        $x_50_2 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00 00 ca 00 47 65 74 43 6f 6d 6d 61 6e 64 4c 69 6e 65 41 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 fd 00 47 65 74 44 43 00 55 53 45 52 33 32 2e 64 6c 6c 00 00 69 01 47 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 f3 01 53 65 74 54 65 78 74 43 6f 6c 6f 72 00 00 47 44 49 33 32 2e 64 6c 6c 00 00 00 00}  //weight: 50, accuracy: High
        $x_10_3 = {8d 54 24 4c 52 50 e8 ?? ?? ff ff 8b ?? f4 8b ?? f8 83 c4 04 50 8b 44 24 ?? 51 8b 4c 24 ?? 03 d1 52 50 ff 15 ?? ?? 10 00 33 c9 45 66 8b ?? 06 83 ?? 28 3b e9 72 a9 8b 84 24 38 01 00 00 8b 4c 24 ?? 6a 00 8d 54 24 ?? 6a 04 83 c0 08 52 50 51 ff d3 8b ?? ?? 8b 7c 24 ?? 8b 4c 24 ?? 8d 84 24 94 00 00 00 03 d7 50 51 89 94 24 4c 01 00 00 ff 15 ?? ?? 10 00 8b 54 24 ?? 52 ff 15 ?? ?? 10 00 5f 5e 5d 33 c0 5b 81 c4 50 03 00 00 c3}  //weight: 10, accuracy: Low
        $x_1_4 = {81 ec 50 03 00 00 53 55 56 57 [0-64] 8d 44 24 38 8d 4c 24 50 50 51 6a 00 6a 00 6a 04 6a 00 6a 00 6a 00 ff 15 ?? ?? 10 00 50 6a 00 ff 15 ?? ?? 10 00}  //weight: 1, accuracy: Low
        $x_2_5 = {10 00 8b 44 24 3c 8d 94 24 94 00 00 00 52 50 ff 15 ?? ?? 10 00 8b 94 24 38 01 00 00 8b 44 24 38 6a 00 8d 4c 24 4c 6a 04 83 c2 08 51 52 50 ff 15 ?? ?? 10 00 56 [0-48] c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24 ?? ?? c6 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_50_*) and 1 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Buzus_A_2147609458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Buzus.A"
        threat_id = "2147609458"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Buzus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec ba 00 2d 40 00 e8 dc f0 ff ff 75 07 33 c0 e8 a3 ee ff ff e8 32 f8 ff ff 3c 01 75 07 33 c0 e8 93 ee ff ff e8 7a f9 ff ff e8 5d fc ff ff ?? ?? 5a 59 59 64 89 10 68 f0 2c 40 00 8d 45 ec e8 8c ee ff ff c3}  //weight: 1, accuracy: Low
        $x_1_2 = {53 56 8b f0 6a 0a 52 a1 6c 46 40 00 50 e8 56 fd ff ff 8b d8 53 a1 6c 46 40 00 50 e8 70 fd ff ff 89 06 53 a1 6c 46 40 00 50 e8 52 fd ff ff 8b d8 53 e8 52 fd ff ff 8b f0 85 f6 74 06 53 e8 2e fd ff ff 8b c6 5e 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

