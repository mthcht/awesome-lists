rule Trojan_MSIL_Kuhaname_A_2147720535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kuhaname.A"
        threat_id = "2147720535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kuhaname"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 6a 65 63 74 00 24 49 52 36 2d 31 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f}  //weight: 1, accuracy: High
        $x_1_2 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f}  //weight: 1, accuracy: High
        $x_1_3 = {44 65 73 69 67 6e 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f}  //weight: 1, accuracy: High
        $x_1_4 = {4d 79 47 72 6f 75 70 43 6f 6c 6c 65 63 74 69 6f 6e 41 74 74 72 69 62 75 74 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

