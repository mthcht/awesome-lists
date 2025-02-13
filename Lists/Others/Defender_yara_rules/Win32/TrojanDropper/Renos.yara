rule TrojanDropper_Win32_Renos_HH_2147804070_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Renos.HH"
        threat_id = "2147804070"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1c 40 3d 00 01 00 00 72 f4 [0-16] 68 ff ff ?? ?? 68 ff ff}  //weight: 5, accuracy: Low
        $x_2_2 = {40 00 68 ff ff ?? ?? 68 ff ff}  //weight: 2, accuracy: Low
        $x_1_3 = {68 82 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {6a 02 57 6a fc 56 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 72 65 61 74 65 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00}  //weight: 1, accuracy: High
        $x_1_9 = {44 65 6c 65 74 65 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_11 = {57 49 4e 49 4e 45 54 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_12 = {4d 53 56 43 50 36 30 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 10 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Renos_H_2147804103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Renos.H"
        threat_id = "2147804103"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Renos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 50 ff 15 04 00 ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 [0-122] 68 ff ff [0-48] 68 ff ff ?? ?? [0-112] 68 ff ff ?? ?? [0-48] 68 ff ff ?? ?? [0-7] e8 ?? ?? ff ff [0-80] (40|40 00) [0-32] 81 ec (04|08) 04 00 00}  //weight: 10, accuracy: Low
        $x_2_2 = "VVj%V" ascii //weight: 2
        $x_2_3 = {83 7d f0 04 75 02 00 74}  //weight: 2, accuracy: Low
        $x_2_4 = {40 00 00 66 05 00 66 83 3d}  //weight: 2, accuracy: Low
        $x_2_5 = {40 00 68 ff ff ?? ?? 68 ff ff}  //weight: 2, accuracy: Low
        $x_2_6 = {fb ff ff c1 ?? 02 03 00 8d ?? c8}  //weight: 2, accuracy: Low
        $x_1_7 = {00 62 69 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 82 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {6a 02 57 6a fc 56 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_10 = {43 72 65 61 74 65 54 68 72 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_11 = {53 69 7a 65 6f 66 52 65 73 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_1_12 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00}  //weight: 1, accuracy: High
        $x_1_13 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 00}  //weight: 1, accuracy: High
        $x_1_14 = {44 65 6c 65 74 65 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_15 = {53 65 74 46 69 6c 65 50 6f 69 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_16 = {57 49 4e 49 4e 45 54 2e 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_17 = {4d 53 56 43 50 36 30 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 10 of ($x_1_*))) or
            ((5 of ($x_2_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

