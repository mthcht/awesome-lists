rule Worm_MSIL_Pesdear_A_2147644028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Pesdear.A"
        threat_id = "2147644028"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pesdear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 57 6f 72 6d 5c 57 6f 72 6d 5c 6f 62 6a 5c (44 65 62|52 65 6c 65 61) 5c [0-8] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {55 53 42 49 6e 66 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {50 32 50 73 70 72 65 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

