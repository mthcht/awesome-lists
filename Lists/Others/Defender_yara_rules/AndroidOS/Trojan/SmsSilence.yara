rule Trojan_AndroidOS_SmsSilence_A_2147679546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSilence.A"
        threat_id = "2147679546"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSilence"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 61 74 63 68 73 6d 73 32 2e 6a 61 76 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 61 74 63 68 73 70 61 6d 2f 63 61 74 63 68 73 6d 73 32 3b 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 74 37 39 38 30 2e 63 6f 6d 2f 41 6e 64 72 6f 69 64 5f 53 4d 53 2f (72 65 63 65|69 6e 73 74 61) 69 6e 67 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_4 = {73 74 61 72 62 75 67 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_AndroidOS_SmsSilence_B_2147681405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SmsSilence.B"
        threat_id = "2147681405"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SmsSilence"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 72 38 38 39 2e 63 6f 6d 2f 41 6e 64 72 6f 69 64 5f 53 4d 53 2f (69 6e 73 74 61 6c 6c 69|72 65 63 65 69 76 69) 2e 70 68 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {63 61 74 63 68 73 6d 73 32 2e 6a 61 76 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 67 7a 7a 67 2e 63 6f 6d 2f 6d 73 2e 61 70 6b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

