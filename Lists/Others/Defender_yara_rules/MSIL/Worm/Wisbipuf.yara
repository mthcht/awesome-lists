rule Worm_MSIL_Wisbipuf_B_2147694962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Wisbipuf.B"
        threat_id = "2147694962"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wisbipuf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 6e 66 65 63 74 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 66 65 63 74 5f 6d 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 68 65 63 6b 73 68 6f 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 6e 6a 65 63 74 49 63 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 65 6d 6f 76 65 46 75 6e 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {69 6e 66 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {67 65 6e 65 72 61 74 65 64 5f 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_8 = {75 70 64 61 74 65 63 68 65 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

