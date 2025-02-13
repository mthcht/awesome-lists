rule Worm_MSIL_Remrochor_A_2147658319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Remrochor.A"
        threat_id = "2147658319"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Remrochor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chromer.resources" ascii //weight: 1
        $x_1_2 = {61 6e 74 69 53 61 6e 64 62 6f 78 69 65 00 61 6e 74 69 41 6e 75 62 69 73}  //weight: 1, accuracy: High
        $x_1_3 = {53 70 72 65 61 64 00 47 65 74 44 65 63 72 79 70 74 65 64 44 61 74 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

