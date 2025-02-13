rule Backdoor_MSIL_Dalatar_A_2147695152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Dalatar.A"
        threat_id = "2147695152"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dalatar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 42 00 73 00 42 53 00 41 72 72 61 79 00 66 78 00 57 52 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 73 42 75 7a 79 00}  //weight: 1, accuracy: High
        $x_1_3 = {59 79 00 48 4f 53 54 00 70 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 6e 6e 65 63 74 00 68 00 70 00 53 50 4c 00 44 69 73 43 6f 6e 6e 65 63 74 00 53 65 6e 64 00 52 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

