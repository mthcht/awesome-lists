rule Worm_MSIL_Sendecor_A_2147695333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Sendecor.A"
        threat_id = "2147695333"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sendecor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 6f 67 46 69 6c 65 53 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 6d 72 53 65 6e 64 4c 6f 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {48 44 44 65 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 65 74 44 65 74 65 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 53 75 70 64 61 74 65 2e 4d 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

