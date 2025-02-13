rule Backdoor_MSIL_Calierot_A_2147685540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Calierot.A"
        threat_id = "2147685540"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Calierot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 77 65 62 63 61 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 76 69 73 69 66 6f 72 6d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6f 66 6b 6c 6f 63 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 65 6e 64 6d 69 6e 69 74 68 75 6d 62 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4f 70 65 72 61 52 65 63 6f 76 65 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 46 69 72 65 77 61 6c 6c 00 41 6e 74 69 76 69 72 75 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6c 6f 67 69 6e 69 6e 66 6f 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 53 68 6f 69 74 5a 69 6c 6c 61 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 66 69 6e 64 61 6e 64 6b 69 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 73 65 6e 64 64 72 69 76 65 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 73 74 6f 70 6b 65 79 62 64 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 73 74 61 72 74 66 69 6c 65 64 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 73 69 6e 67 6d 70 72 6f 63 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 73 65 6e 64 61 6c 6c 70 61 73 73 77 6f 72 64 73 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 6b 69 6c 6c 6d 70 72 6f 63 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

