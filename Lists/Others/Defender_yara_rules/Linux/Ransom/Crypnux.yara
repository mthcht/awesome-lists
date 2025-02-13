rule Ransom_Linux_Crypnux_A_2147707485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Crypnux.A"
        threat_id = "2147707485"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Crypnux"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 72 65 61 64 6d 65 2e 63 72 79 70 74 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {2f 69 6e 64 65 78 2e 63 72 79 70 74 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 65 64 74 6c 73 5f 70 6b 5f 65 6e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 61 72 74 20 65 6e 63 72 79 70 74 69 6e 67 2e 2e 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {52 45 41 44 4d 45 5f 46 4f 52 5f 44 45 43 52 59 50 54 2e 74 78 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

