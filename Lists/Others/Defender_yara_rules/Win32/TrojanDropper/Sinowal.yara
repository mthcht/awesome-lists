rule TrojanDropper_Win32_Sinowal_2147572020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sinowal"
        threat_id = "2147572020"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {51 51 0f 01 4c 24 00 8b 44 24 02 59 59 c3}  //weight: 3, accuracy: High
        $x_3_2 = {25 00 00 00 ff 33 c9 3d 00 00 00 80 0f 95 c1 8b c1 c3}  //weight: 3, accuracy: High
        $x_3_3 = {8b 44 24 08 83 f8 01 7e 90 01 01 8b 4c 24 04 53 56 57 8d 78 fe d1 ef 8d 71 01 47 83 3d 10 30 40 00 00}  //weight: 3, accuracy: High
        $x_3_4 = {6a 20 59 56 8b c1 99 6a 10 5e f7 fe 8b c2 83 f8 01 74 0e 83 c1 20 81 f9 a0 0c 00 00 7c e6 33 c0 40}  //weight: 3, accuracy: High
        $x_3_5 = {83 ec 10 8d 45 f0 50 ff 15 ?? ?? 40 00 33 c0 8a 45 f1 2c 74}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Sinowal_2147572020_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Sinowal"
        threat_id = "2147572020"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Sinowal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9d 83 7d c4 ff 9c}  //weight: 10, accuracy: High
        $x_10_2 = {83 c4 10 85 c0 9c 05 00 e8}  //weight: 10, accuracy: Low
        $x_1_3 = {9c 50 66 a1 ?? ?? 40 00 [0-16] 66 3d ?? ?? [0-16] 58 [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_4 = {9c 51 66 8b 0d ?? ?? 40 00 [0-16] 66 81 f9 ?? ?? [0-16] 59 [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_5 = {9c 52 66 8b 15 ?? ?? 40 00 [0-16] 66 81 fa ?? ?? [0-16] 5a [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_6 = {9c 53 66 8b 1d ?? ?? 40 00 [0-16] 66 81 fb ?? ?? [0-16] 5b [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_7 = {9c 55 66 8b 2d ?? ?? 40 00 [0-16] 66 81 fd ?? ?? [0-16] 5d [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_8 = {9c 56 66 8b 35 ?? ?? 40 00 [0-16] 66 81 fe ?? ?? [0-16] 5e [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
        $x_1_9 = {9c 57 66 8b 3d ?? ?? 40 00 [0-16] 66 81 ff ?? ?? [0-16] 5f [0-16] 74 00 00 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

