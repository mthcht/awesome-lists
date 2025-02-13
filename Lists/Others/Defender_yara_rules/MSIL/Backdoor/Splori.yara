rule Backdoor_MSIL_Splori_A_2147689105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Splori.A"
        threat_id = "2147689105"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Splori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 00 72 00 6f 00 63 00 4d 00 6f 00 6e 00 00 00 00 00 0a 6d 00 69 00 6e 00 65 00 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {50 00 72 00 6f 00 63 00 4d 00 6f 00 6e 00 00 00 00 00 10 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 69 00 6e 00 65 00 72 00 00 00 00 00 0e 50 00 72 00 6f 00 63 00 4d 00 6f 00 6e 00}  //weight: 1, accuracy: High
        $x_50_4 = "YlZJ8o45TDwkRo/+vjt/1CAvWJ38we04" ascii //weight: 50
        $x_5_5 = {5f 00 66 69 6c 65 53 79 73 74 65 6d 57 61 74 63 68 65 72 5f 30 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f}  //weight: 5, accuracy: High
        $x_5_6 = {2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 5f 5f 00 5f 5f 5f 00 5f 5f 5f 5f 00 5f 5f 5f 5f 5f 00 5f 5f 5f 5f 5f 5f 00 5f 5f 5f 5f 5f 5f 5f 00 5f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Splori_A_2147689105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Splori.A"
        threat_id = "2147689105"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Splori"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 13 1a 08 0b 1d 0e 19 20 31 15 1f 0e 13 0f 13 1a 08 20 2b 15 12 18 13 0b 0f 20 3f 09 0e 0e 19 12 08 2a 19 0e 0f 15 13 12 20 2e 09 12}  //weight: 1, accuracy: High
        $x_1_2 = {3d 5c 3e 1d 12 18 0b 15 18 08 14 5c 3a 10 13 13 18 5c 3d 08 08 1d 1f 17 5c 15 0f 5c 3d 10 0e 19 1d 18 05 5c 2e 09 12 12 15 12 1b 5c 13 12}  //weight: 1, accuracy: High
        $x_1_3 = "vXEE^vyOI_XC^SiOD^OX" ascii //weight: 1
        $x_1_4 = {e9 d6 d5 cd d6 d5 c8 d3 c9 9a fb ce ce db d9 d1 9a d3 c9 9a fb d6 c8 df db de c3 9a e8 cf d4 d4 d3 d4 dd 9a d5 d4}  //weight: 1, accuracy: High
        $x_1_5 = {7f 63 63 67 17 67 78 64 63 17 76 43 43 56 54 5c 17 58 59}  //weight: 1, accuracy: High
        $x_1_6 = {33 11 0c 02 00 17 0a 15 06 43 21 0c 17 43 28 0a 0f 0f 06 11 43 0a 10 43 02 0f 11 06 02 07 1a 43 26 0d 02 01 0f 06 07 42}  //weight: 1, accuracy: High
        $x_1_7 = {17 3a 21 1e 3c 39 39 30 27 6f 75 05 27 3a 36 30 26 26 30 26 75 1e 3c 39 39 30 31 6f}  //weight: 1, accuracy: High
        $x_1_8 = {15 3a 3f 36 73 21 36 35 3f 36 30 27 36 37 73 3a 3d 27 3c 73 00 36 3f 35 73 00 26 30 30 36 20 20 35 26 3f 3f 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

