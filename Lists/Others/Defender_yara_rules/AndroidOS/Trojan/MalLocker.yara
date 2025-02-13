rule Trojan_AndroidOS_MalLocker_A_2147740117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MalLocker.A"
        threat_id = "2147740117"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MalLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {63 6f 6d 2e 6c 6f 6c 6f 6c 6f 2e 4c 6f 63 6b 53 65 72 76 69 63 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {22 4c 63 6f 6d 2f 6c 6f 6c 6f 6c 6f 2f 4c 6f 63 6b 53 65 72 76 69 63 65 24 31 30 30 30 30 30 30 30 30 3b 00}  //weight: 1, accuracy: High
        $x_1_3 = {29 4c 61 6e 64 72 6f 69 64 2f 76 69 65 77 2f 57 69 6e 64 6f 77 4d 61 6e 61 67 65 72 24 4c 61 79 6f 75 74 50 61 72 61 6d 73 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = {22 63 6f 6d 2e 61 69 64 65 2e 72 75 6e 74 69 6d 65 2e 56 49 45 57 5f 4c 4f 47 43 41 54 5f 45 4e 54 52 59 00}  //weight: 1, accuracy: High
        $x_1_5 = {61 64 64 56 69 65 77 00}  //weight: 1, accuracy: High
        $x_1_6 = {72 65 6d 6f 76 65 56 69 65 77 00}  //weight: 1, accuracy: High
        $x_1_7 = {4c 63 6f 6d 2f 6c 6f 6c 6f 6c 6f 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 3b 00}  //weight: 1, accuracy: High
        $x_1_8 = {6c 61 79 6f 75 74 5f 69 6e 66 6c 61 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

