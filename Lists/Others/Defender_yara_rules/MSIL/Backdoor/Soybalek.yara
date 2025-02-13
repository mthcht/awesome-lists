rule Backdoor_MSIL_Soybalek_A_2147707012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Soybalek.A!dha"
        threat_id = "2147707012"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Soybalek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 ?? ?? 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 ?? ?? ?? ?? 7b 00 30 00 7d 00 09 00 7b 00 31 00 7d 00 09 00 7b 00 32 00 7d 00 09 00 7b 00 33 00 7d 00 09 00 7b 00 34 00 7d 00 09 00 7b 00 35 00 7d 00}  //weight: 2, accuracy: Low
        $x_1_2 = {02 7b 01 00 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0a 02 7b 01 00 00 04 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0b 06}  //weight: 1, accuracy: Low
        $x_1_3 = {18 08 a2 11 08 19 06 a2 11 08 1a 07 a2 11 08 1b 09 a2 11 08 28 ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {02 72 01 00 00 70 7d 02 00 00 04 02 72 ?? 00 00 70 7d 03 00 00 04 02 72 ?? 00 00 70 7d 04 00 00 04 02 [0-12] 03 7d 01 00 00 04 02 7b 01 00 00 04 02 fe 06 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Soybalek_2147707013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Soybalek!dha"
        threat_id = "2147707013"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Soybalek"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 77 61 41 75 74 68 2e 64 6c 6c 00 53 65 63 75 72 69 74 79 00 4d 69 63 72 6f 73 6f 66 74 2e 45 78 63 68 61 6e 67 65 2e 43 6c 69 65 6e 74 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 00 15 63 00 3a 00 5c 00 6c 00 6f 00 67 00 2e 00 74 00 78 00 74 00 00 11 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 11 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 01 00 2f 7b 00}  //weight: 1, accuracy: High
        $x_2_3 = {5c 53 79 62 65 72 53 70 61 63 65 5c 44 65 73 6b 74 6f 70 5c 6f 77 61 5c 48 74 74 70 73 45 78 74 73 5c 48 74 74 70 73 45 78 74 73 5c 48 74 74 70 73 45 78 74 73 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4f 77 61 41 75 74 68 2e 70 64 62 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

