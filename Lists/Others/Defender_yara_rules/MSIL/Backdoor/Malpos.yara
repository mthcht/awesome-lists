rule Backdoor_MSIL_Malpos_A_2147706620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Malpos.A"
        threat_id = "2147706620"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malpos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 44 00 45 00 56 00 2d 00 50 00 4f 00 49 00 4e 00 54 01 09 30 2d 39 41 2d 5a 61 2d 7a 01 00 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
        $x_1_2 = {44 45 56 2d 50 4f 49 4e 54 01 09 30 2d 39 41 2d 5a 61 2d 7a 01 00 01 09 30 2d 39 41 2d 5a 61 2d 7a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

