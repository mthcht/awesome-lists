rule Worm_MSIL_Vonriamt_A_2147686548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Vonriamt.A"
        threat_id = "2147686548"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vonriamt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VanToMRAT" ascii //weight: 2
        $x_2_2 = "njLogger" ascii //weight: 2
        $x_1_3 = {55 53 42 00 45 00 63 61 6d 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 52 44 50 00 43 52 44 50 31 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

