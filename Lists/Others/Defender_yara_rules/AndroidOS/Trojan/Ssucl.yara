rule Trojan_AndroidOS_Ssucl_A_2147679139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Ssucl.A"
        threat_id = "2147679139"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Ssucl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6c 61 63 6f 2e 6b 69 63 6b 73 2d 61 73 73 2e 6e 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 70 70 5f 64 61 74 61 2f 73 76 63 68 6f 73 74 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 61 6e 64 6c 65 5f 75 70 6c 6f 61 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 69 6c 61 62 2e 6d 73 6e 2e 53 4d 53 5f 53 45 4e 54 00}  //weight: 1, accuracy: High
        $x_1_5 = {7c 4e 45 57 5f 48 45 4c 4c 4f 57 7c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

