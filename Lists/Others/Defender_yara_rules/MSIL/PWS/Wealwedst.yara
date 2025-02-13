rule PWS_MSIL_Wealwedst_A_2147648258_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Wealwedst.A"
        threat_id = "2147648258"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wealwedst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 53 00 74 00 65 00 61 00 6c 00 65 00 72 00 20 00 62 00 79 00 20 00 57 00 33 00 33 00 44 00 59}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 2f 00 54 00 69 00 6d 00 65 00 3a 00 20 00 00 13 50 00 43 00 20 00 4e 00 61 00 6d 00 65 00 3a 00 20 00 00 09 49 00 50}  //weight: 1, accuracy: High
        $x_1_3 = {73 69 67 6e 6f 6e 00 49 50 41 64 72 65 73 73 65 00 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

