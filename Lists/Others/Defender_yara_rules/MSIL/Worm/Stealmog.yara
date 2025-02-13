rule Worm_MSIL_Stealmog_A_2147637807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Stealmog.A"
        threat_id = "2147637807"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealmog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 65 62 73 69 74 65 42 6c 6f 63 6b 65 72 46 75 6e 63 74 00}  //weight: 2, accuracy: High
        $x_2_2 = {4b 65 79 6c 6f 67 4f 6e 6c 79 53 65 6e 64 4d 61 69 6c 43 6f 6e 66 69 72 6d 61 74 69 6f 6e 00}  //weight: 2, accuracy: High
        $x_1_3 = {55 53 42 53 70 72 65 61 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 73 49 74 49 6e 66 65 63 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 65 74 5f 4a 70 65 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

