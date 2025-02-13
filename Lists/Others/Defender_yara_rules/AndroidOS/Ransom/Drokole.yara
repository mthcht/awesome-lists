rule Ransom_AndroidOS_Drokole_A_2147688668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Drokole.A"
        threat_id = "2147688668"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Drokole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 56 69 72 75 73 53 65 61 72 63 68 65 72 3b 00}  //weight: 1, accuracy: High
        $x_1_2 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 42 61 63 6b 67 72 6f 75 6e 64 53 65 72 76 69 63 65 3b 00}  //weight: 1, accuracy: High
        $x_1_3 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 3b 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b 00}  //weight: 1, accuracy: High
        $x_1_5 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 53 65 6e 64 65 72 41 63 74 69 76 69 74 79 3b 00}  //weight: 1, accuracy: High
        $x_1_6 = "is locked due to the violation of the federal laws of the United States of America:" ascii //weight: 1
        $x_1_7 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 3b 00}  //weight: 1, accuracy: High
        $x_1_8 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 4c 6f 77 4c 65 76 65 6c 00}  //weight: 1, accuracy: High
        $x_1_9 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 52 65 71 75 65 73 74 53 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_10 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

