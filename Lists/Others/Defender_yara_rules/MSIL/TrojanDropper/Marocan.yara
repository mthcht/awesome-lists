rule TrojanDropper_MSIL_Marocan_A_2147725134_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Marocan.A!bit"
        threat_id = "2147725134"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marocan"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 5d 94 13 10 02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 08 11 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 26 12 00 28 ?? 00 00 0a 06 17 da 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {46 69 6c 65 4f 70 65 6e 00 4c 4f 46 00 53 74 72 69 6e 67 73 00 53 70 61 63 65 00 46 69 6c 65 47 65 74 00 49 6e 74 33 32 00 46 69 6c 65 43 6c 6f 73 65 00 43 6f 6d 70 61 72 65 4d 65 74 68 6f 64 00 53 70 6c 69 74 00 43 6f 6e 63 61 74 00 46 69 6c 65 50 75 74 00 50 72 6f 63 65 73 73 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 74 72 69 6e 67 42 75 69 6c 64 65 72 00 45 6d 70 74 79 00 67 65 74 5f 4c 65 6e 67 74 68 00 53 75 62 73 74 72 69 6e 67 00 54 6f 43 68 61 72 41 72 72 61 79 00 41 73 63 00 49 6e 74 65 72 6c 6f 63 6b 65 64 00 49 6e 63 72 65 6d 65 6e 74 00 4d 61 74 68 00 4d 61 78 00 43 68 72 00 41 70 70 65 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_MSIL_Marocan_B_2147725265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Marocan.B!bit"
        threat_id = "2147725265"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Marocan"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 02 11 04 91 ?? 8e b7 03 8e b7 5d da 03 ?? 91 da ?? d6 28 ?? 00 00 0a 9c ?? 17 d6 b5}  //weight: 1, accuracy: Low
        $x_1_2 = {28 26 00 00 0a 02 28 1e 00 00 0a 28 26 00 00 0a 03 6f 27 00 00 0a 28 14 00 00 06 6f 28 00 00 0a 0a}  //weight: 1, accuracy: High
        $x_1_3 = {00 43 6f 6e 63 61 74 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 50 72 6f 63 65 73 73 00 53 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 45 6e 76 69 72 6f 6e 6d 65 6e 74 00 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 00 47 65 74 46 6f 6c 64 65 72 50 61 74 68 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

