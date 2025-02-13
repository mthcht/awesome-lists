rule Backdoor_MSIL_LimeRAT_A_2147735914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/LimeRAT.A!bit"
        threat_id = "2147735914"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LimeRAT"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "LimeRAT" ascii //weight: 2
        $x_1_2 = {00 46 69 6c 65 5f 44 65 63 00}  //weight: 1, accuracy: High
        $x_1_3 = "Rans-Status" wide //weight: 1
        $x_1_4 = {00 53 70 6c 69 74 42 79 57 6f 72 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 50 61 73 74 65 62 69 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 42 4f 54 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 53 50 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

