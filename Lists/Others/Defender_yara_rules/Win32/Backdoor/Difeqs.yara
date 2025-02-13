rule Backdoor_Win32_Difeqs_2147572063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Difeqs"
        threat_id = "2147572063"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Difeqs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 ec 08 02 00 00 33 c0 b1 ?? 8a ?? ?? 10 40 00 32 d1 88 ?? ?? 10 40 00 40 3d 00 a4 00 00 72 ea 56 68}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 4c 24 04 33 c0 85 c9 74 0c 51 e8 ?? ff ff ff 8b 40 3c 83 c4 04 c3}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 44 24 04 56 50 33 f6 e8 ?? ff ff ff 83 c4 04 85 c0 74 0a 8b 4c 24 0c 5e 8b 44 c8 78 c3 8b c6}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 53 14 8b 7b 0c 8b 6c 24 20 2b d7 03 d6 33 c9 03 d5 33 f6 66 8b 4a 0e 66 8b 72 0c 03 ce 8d 6a 10 85 c9 7e ?? 89 4c 24 20 83 7d 00 03}  //weight: 2, accuracy: Low
        $x_3_5 = {7e 18 03 fd 8b 44 24 14 8a 04 01 30 04 32 41 3b cf 7c 02 8b cd 42 3b d3 7c ea 8b 4c 24 28 85 c9}  //weight: 3, accuracy: High
        $x_3_6 = {00 8b f8 83 c4 04 b9 25 00 00 00 b8 72 00 00 00 66 83 ff 0b 66 89 4c 24 14 66 c7 44 24 16 74}  //weight: 3, accuracy: High
        $x_3_7 = {b9 25 00 00 00 b8 77 00 00 00 bb 73 00 00 00 33 f6 66 83 ff 09 66 89 4c 24 14 66 89 44 24 16 66}  //weight: 3, accuracy: High
        $x_2_8 = {8b 44 24 04 85 c0 74 06 c7 00 ?? ?? 00 10 b8 ?? ?? 00 10 c3}  //weight: 2, accuracy: Low
        $x_3_9 = {89 5c 24 14 6a 40 68 00 10 00 00 57 6a 00 56 ff d5 6a 40 68 00 10 00 00 53 6a 00 56 89 44 24 24 ff d5 6a 04 68 00 10 00 00 68 1c 02 00 00 6a 00}  //weight: 3, accuracy: High
        $x_2_10 = {99 51 52 50 e8 ?? ?? 00 00 8b 7c 24 24 8b 5c 24 18 8b 6c 24 1c 8b f3 8b 0f 2b f1 8b cd 1b 4f 04 3b ca 72 18}  //weight: 2, accuracy: Low
        $x_2_11 = {0f be 44 24 1b 83 e8 00 0f ?? ?? 01 00 00 48 0f ?? ?? 02 00 00 0f be 44 24 13 48 83 f8 06 0f ?? ?? 02 00 00 ff 24 85 ?? ?? 00 10 8b ?? 24 14 66}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_2_*))) or
            ((2 of ($x_3_*) and 3 of ($x_2_*))) or
            ((3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

