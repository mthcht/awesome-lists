rule Ransom_MSIL_Birbware_A_2147729938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Birbware.A"
        threat_id = "2147729938"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Birbware"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 62 00 69 00 72 00 62 00 2e 00 70 00 6e 00 67}  //weight: 1, accuracy: High
        $x_1_2 = "\\ransom.pdb" ascii //weight: 1
        $x_1_3 = {61 00 70 00 61 00 6f 00 77 00 6a 00 64 00 73 00 6f 00 64 00 69 00 75 00 6a 00 39 00 28 00 2f 00 29 00 3d 00 28 00 2f 00 31 00 34 00 6a 00 6c 00 71 00 6b 00 73 00 6a 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

