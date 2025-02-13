rule Trojan_MSIL_Sixxpack_A_2147740310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sixxpack.A!ibt"
        threat_id = "2147740310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sixxpack"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 73 74 75 6e 74 2e 64 6c 6c 00 73 74 75 62 00 73 74 75 6e 74 70 69 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 68 75 68 75 75 2e 64 6c 6c 00 73 74 75 62 00 68 75 68 75 68 75 68 75 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 61 63 74 6d 70 2e 64 6c 6c 00 73 74 75 62 00 53 69 78 78 70 61 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 21 01 00 00 78 70 61 63 6b 21 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6d 65 74 65 72 2e 64 6c 6c 00 73 74 75 62 00 6d 65 74 65 72 63 72 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 68 61 78 6f 72 2e 64 6c 6c 00 73 74 75 62 00 68 61 78 78 6f 72 72 72 00}  //weight: 1, accuracy: High
        $x_6_7 = {00 08 b7 7a 5c 56 19 34 e0 89 02 06 08 05}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

