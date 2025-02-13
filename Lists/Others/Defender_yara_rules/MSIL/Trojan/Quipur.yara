rule Trojan_MSIL_Quipur_A_2147697221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quipur.A"
        threat_id = "2147697221"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quipur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 00 43 00 6f 00 6f 00 70 00 65 00 72 00 2f 00 [0-16] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {67 65 74 5f 6c 69 6e 6b [0-16] 73 65 74 5f 6c 69 6e 6b}  //weight: 1, accuracy: Low
        $x_1_4 = "get_internetkontrol" ascii //weight: 1
        $x_1_5 = {48 69 64 65 00 53 65 72 76 65 72 43 6f 6d 70 75 74 65 72}  //weight: 1, accuracy: High
        $x_1_6 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 00 50 72 6f 63 65 73 73 00 53 74 61 72 74 00 67 65 74 5f 45 78 65 63 75 74 61 62 6c 65 50 61 74 68 00 43 6f 70 79 46 69 6c 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

