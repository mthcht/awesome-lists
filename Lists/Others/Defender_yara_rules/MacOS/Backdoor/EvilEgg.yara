rule Backdoor_MacOS_EvilEgg_A_2147734463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/EvilEgg.A"
        threat_id = "2147734463"
        type = "Backdoor"
        platform = "MacOS: "
        family = "EvilEgg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 6b 20 31 31 31 31 31 31 71 71 3b 20 70 79 74 68 6f 6e 20 2f 74 6d 70 2f 2e 69 6e 66 6f 2e 70 79 00 2f 2e 65 73 70 6c 2e 70 6c 69 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 63 70 2f 39 34 2e 31 35 36 2e 31 38 39 2e 37 37 2f 32 32 38 30 20 30 3e 26 31 00 66 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {69 6e 73 74 61 6c 6c 50 65 72 73 69 73 74 65 6e 63 65 00 69 6e 73 74 61 6c 6c 45 76 69 6c 00 70 72 65 66 65 72 65 6e 63 65 73 00 73 65 74 50 72 65 66 65 72 65 6e 63 65 73 3a 00 73 74 61 74 75 73 4d 65 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

