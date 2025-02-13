rule Backdoor_MSIL_Moidirat_A_2147689426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Moidirat.A"
        threat_id = "2147689426"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Moidirat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 6e 69 6e 6a 61 00 73 6b 68 6f 75 6e 61 00 6e 4c 6f 67 4f 66 66 00 6e 52 65 62 6f 6f 74 00 6e 46 6f 72 63 65 4c 6f 67 4f 66 66 00 6e 46 6f 72 63 65 52 65 62 6f 6f 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 4c 61 73 74 41 56 00 4c 61 73 74 41 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 61 74 6d 00 4d 6f 44 69 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 65 74 65 63 74 69 6f 6e 00 4f 66 4d 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 75 6e 46 69 6c 65 00 75 66 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 74 69 6e 61 34 00 64 63 00 66 6f 69 73 00 64 6c 00 64 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 57 52 4b 00 41 73 73 65 6d 62 6c 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

