rule Backdoor_AndroidOS_Chuli_A_2147680040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Chuli.A"
        threat_id = "2147680040"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Chuli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 61 6e 64 72 6f 69 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {39 39 39 2e 39 25 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 6f 6f 6b 5f 66 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 79 70 6f 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {36 34 2e 37 38 2e 31 36 31 2e 31 33 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

