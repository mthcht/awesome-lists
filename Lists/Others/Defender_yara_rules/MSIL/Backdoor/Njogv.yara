rule Backdoor_MSIL_Njogv_A_2147688681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Njogv.A"
        threat_id = "2147688681"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njogv"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 6e 73 74 4d 61 6e 61 67 65 72 00}  //weight: 5, accuracy: High
        $x_5_2 = {44 65 74 61 74 74 63 68 46 72 6f 6d 45 76 65 6e 74 00}  //weight: 5, accuracy: High
        $x_1_3 = {5f 6d 69 43 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 65 69 4f 6e 45 72 72 6f 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 65 69 4f 6e 43 6f 6d 6d 61 6e 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {5f 65 69 4f 6e 46 69 6e 69 73 68 65 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {5f 72 65 6d 6f 74 65 43 6c 65 61 6e 65 64 00}  //weight: 1, accuracy: High
        $x_1_8 = {72 65 6d 6f 76 65 5f 4f 6e 46 69 6e 69 73 68 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

