rule Trojan_AndroidOS_Perkele_2147709818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Perkele"
        threat_id = "2147709818"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Perkele"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 65 73 74 61 72 74 5f 73 72 76 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 79 6c 6f 67 5f 6d 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 79 6c 6f 67 5f 6e 65 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4d 53 20 53 45 4e 44 20 45 52 52 4f 52 3a 20 4e 4f 20 54 45 58 54 2e 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 65 77 4b 65 79 67 75 61 72 64 4c 6f 63 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

