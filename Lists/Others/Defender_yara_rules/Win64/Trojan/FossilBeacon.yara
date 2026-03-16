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

