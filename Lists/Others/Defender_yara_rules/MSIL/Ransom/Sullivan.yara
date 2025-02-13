rule Ransom_MSIL_Sullivan_B_2147835754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Sullivan.B"
        threat_id = "2147835754"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sullivan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {48 00 6f 00 6c 00 64 00 20 00 79 00 6f 00 75 00 72 ?? 20 00 68 00 6f 00 72 00 73 00 65 00 73 00 3a 00}  //weight: 100, accuracy: Low
        $x_10_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 ?? 20 00 74 00 6f 00 6f 00 6b 00 3a 00}  //weight: 10, accuracy: Low
        $x_1_3 = {43 00 72 00 65 00 61 00 74 00 65 00 41 00 65 00 73 00 46 00 69 ?? 6c 00 65 00 20 00 66 00 61 00 69 00 6c 00 65 00 64 00 21 00}  //weight: 1, accuracy: Low
        $x_1_4 = {43 00 72 00 65 00 61 00 74 00 65 00 41 00 65 00 73 00 46 00 69 00 6c ?? 65 00 20 00 2d 00 20 00 46 00 61 00 69 00 6c 00 75 00 72 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

