rule Backdoor_AndroidOS_Crisis_A_2147696911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/Crisis.A"
        threat_id = "2147696911"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "Crisis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 6e 63 6f 6d 69 6e 67 5f 6e 75 6d 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 6c 69 73 74 65 6e 65 72 2f 42 72 6f 61 64 63 61 73 74 4d 6f 6e 69 74 6f 72 41 63 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = {61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 6c 69 73 74 65 6e 65 72 2f 42 72 6f 61 64 63 61 73 74 4d 6f 6e 69 74 6f 72 43 61 6c 6c 3b 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 6c 69 73 74 65 6e 65 72 2f 42 72 6f 61 64 63 61 73 74 4d 6f 6e 69 74 6f 72 53 6d 73 3b 00}  //weight: 1, accuracy: High
        $x_1_6 = {61 6e 64 72 6f 69 64 2f 73 65 72 76 69 63 65 2f 6c 69 73 74 65 6e 65 72 2f 42 72 6f 61 64 63 61 73 74 4d 6f 6e 69 74 6f 72 53 74 61 6e 64 62 79 3b 00}  //weight: 1, accuracy: High
        $x_1_7 = {63 6f 6e 74 61 63 74 5f 69 64 20 3d 20 3f 20 41 4e 44 20 6d 69 6d 65 74 79 70 65 20 3d 20 3f 20 00}  //weight: 1, accuracy: High
        $x_1_8 = "android/service/ServiceCore;" ascii //weight: 1
        $x_1_9 = {63 6f 6d 2e 61 6e 64 72 6f 69 64 2e 73 65 72 76 69 63 65 2e 61 70 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

