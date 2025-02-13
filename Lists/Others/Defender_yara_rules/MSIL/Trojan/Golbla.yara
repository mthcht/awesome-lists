rule Trojan_MSIL_Golbla_B_2147707474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Golbla.B"
        threat_id = "2147707474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Golbla"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {41 6e 74 69 53 61 6e 64 69 65 00 4d 61 6e 75 61 6c 52 65 73 65 74 45 76 65 6e 74 00 41 76 61 73 74}  //weight: 4, accuracy: High
        $x_2_2 = {5f 72 75 6e 00 5f 6b 69 6c 6c 00 4d 65 73 73 65 6e 67 65 72}  //weight: 2, accuracy: High
        $x_2_3 = {5f 66 69 6c 65 44 61 74 61 00 5f 69 6e 6a 65 63 74 69 6f 6e 50 61 74 68}  //weight: 2, accuracy: High
        $x_2_4 = {56 6d 52 75 6e 6e 69 6e 67 00 46 69 78 65 73}  //weight: 2, accuracy: High
        $x_2_5 = "get_dotnetshit" ascii //weight: 2
        $x_2_6 = {61 64 64 5f 50 6f 6e 67 00 76 61 6c 75 65 00 52 65 6d 6f 76 65 00 72 65 6d 6f 76 65 5f 50 6f 6e 67}  //weight: 2, accuracy: High
        $x_1_7 = {5f 73 74 61 72 74 75 70 50 61 74 68 00 5f 6d 6f 6e 69 74 6f 72 50 61 74 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

