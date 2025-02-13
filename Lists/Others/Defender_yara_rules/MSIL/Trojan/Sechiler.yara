rule Trojan_MSIL_Sechiler_A_2147705808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sechiler.A"
        threat_id = "2147705808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sechiler"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 65 63 75 72 69 74 79 5f 73 63 61 6e 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 73 65 63 75 72 (65|69) 5f 73 63 61 6e 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {5b 00 42 00 69 00 74 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5d 00 [0-32] 5b 00 4b 00 61 00 73 00 70 00 65 00 72 00 73 00 6b 00 79 00 5d 00 [0-80] 5b 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 45 00 73 00 73 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

