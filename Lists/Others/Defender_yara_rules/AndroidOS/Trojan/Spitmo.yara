rule Trojan_AndroidOS_Spitmo_A_2147649508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Spitmo.A"
        threat_id = "2147649508"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Spitmo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 72 65 63 65 69 76 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = {26 74 65 78 74 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {32 35 31 33 34 30 00}  //weight: 1, accuracy: High
        $x_1_4 = {33 32 35 30 30 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 69 6e 69 74 3e 00}  //weight: 1, accuracy: High
        $x_1_6 = {3f 73 65 6e 64 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 41 53 53 57 4f 52 44 5f 4e 55 4d 42 45 52 00}  //weight: 1, accuracy: High
        $x_1_8 = {50 48 4f 4e 45 5f 4e 55 4d 42 45 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

