rule Backdoor_MSIL_Powlistel_A_2147695747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Powlistel.A"
        threat_id = "2147695747"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Powlistel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c5 9e 69 66 72 65 20 4c 69 73 74 65 6c 65 6d 65}  //weight: 1, accuracy: High
        $x_1_2 = "Black Power Sourceler" ascii //weight: 1
        $x_1_3 = "ifreleri Kaydet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

