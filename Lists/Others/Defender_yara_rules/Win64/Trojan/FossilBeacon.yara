rule Trojan_Win64_FossilBeacon_A_2147964825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FossilBeacon.A!dha"
        threat_id = "2147964825"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FossilBeacon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "# Node settings" wide //weight: 1
        $x_1_2 = "# Parent settings" wide //weight: 1
        $x_1_3 = "# Connections" wide //weight: 1
        $x_1_4 = {4c 61 6e 64 ?? 69 6e 65 53 65 72 76 69 63 65}  //weight: 1, accuracy: Low
        $x_1_5 = {53 72 76 46 ?? 6c 6c}  //weight: 1, accuracy: Low
        $x_1_6 = {4c 69 73 74 65 6e 65 ?? 41 72 67 75 6d 65 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_7 = {4f 77 6e 65 72 ?? 43 6f 72 65 2e 4e 6f 64 65}  //weight: 1, accuracy: Low
        $x_1_8 = {4f 77 6e 65 72 ?? 43 6f 72 65 2e 49 6e 74 65 72 6d 65 64 69 61 74 65 73}  //weight: 1, accuracy: Low
        $x_1_9 = {47 65 74 4d 6f ?? 75 6c 65 52 65 71 75 65 73 74 65 64 4e 6f 64 65 73}  //weight: 1, accuracy: Low
        $x_1_10 = {53 74 61 72 74 49 6e ?? 74 72 75 63 74 69 6f 6e 65 72}  //weight: 1, accuracy: Low
        $x_1_11 = {53 65 74 50 ?? 72 72 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_12 = {53 65 74 4e ?? 69 67 68 62 6f 72 4e 6f 64 65 53 74 61 74 75 73}  //weight: 1, accuracy: Low
        $x_2_13 = {53 74 72 75 63 74 75 72 65 ?? 43 6f 6e 6e 65 63 74 69 6f 6e 73}  //weight: 2, accuracy: Low
        $x_2_14 = {53 74 72 75 63 74 75 72 65 ?? 4d 65 73 73 61 67 65}  //weight: 2, accuracy: Low
        $x_1_15 = {52 65 76 65 ?? 73 65 45 6e 64 50 6f 69 6e 74}  //weight: 1, accuracy: Low
        $x_1_16 = {52 65 71 75 ?? 73 74 50 61 63 6b 65 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_FossilBeacon_C_2147965830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/FossilBeacon.C!dha"
        threat_id = "2147965830"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "FossilBeacon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 00 45 00 46 00 4c 00 52 00 55 00 39 00 58 00 54 00 67 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {56 45 46 4c 52 55 39 58 54 67 [0-2] 2f}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 33 00 6c 00 7a 00 64 00 47 00 56 00 74 00 63 00 6d 00 56 00 7a 00 64 00 47 00 39 00 79 00 5a 00 51 00 [0-2] 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {63 33 6c 7a 64 47 56 74 63 6d 56 7a 64 47 39 79 5a 51 [0-2] 2f}  //weight: 1, accuracy: Low
        $x_1_5 = {52 00 65 00 6d 00 6f 00 76 00 65 00 2d 00 57 00 42 00 42 00 61 00 63 00 6b 00 75 00 70 00 53 00 65 00 74 00 20 00 20 00 2d 00 46 00 [0-2] 72 00 63 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 65 6d 6f 76 65 2d 57 42 42 61 63 6b 75 70 53 65 74 20 20 2d 46 [0-2] 72 63 65}  //weight: 1, accuracy: Low
        $x_1_7 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 73 00 74 00 61 00 74 00 65 00 [0-2] 61 00 63 00 6b 00 75 00 70 00 20 00 2d 00 6b 00 65 00 65 00 70 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 73 00 3a 00 30 00}  //weight: 1, accuracy: Low
        $x_1_8 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 79 73 74 65 6d 73 74 61 74 65 [0-2] 61 63 6b 75 70 20 2d 6b 65 65 70 76 65 72 73 69 6f 6e 73 3a 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

