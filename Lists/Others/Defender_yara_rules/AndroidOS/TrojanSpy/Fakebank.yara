rule TrojanSpy_AndroidOS_Fakebank_A_2147685179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakebank.A"
        threat_id = "2147685179"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakebank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "80"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1e 63 6f 6d 2e 73 68 69 6e 68 61 6e 2e 61 6e 64 72 6f 69 64 2e 73 68 69 6e 68 61 6e 2e 73 68 00}  //weight: 5, accuracy: High
        $x_5_2 = {2a 63 6f 6d 2e 68 61 6e 61 62 61 6e 6b 2e 65 62 6b 2e 63 68 61 6e 6e 65 6c 2e 61 6e 64 72 6f 69 64 2e 68 61 6e 61 6e 62 61 6e 6b 00}  //weight: 5, accuracy: High
        $x_5_3 = {15 63 6f 6d 2e 41 54 73 6f 6c 75 74 69 6f 6e 2e 4b 42 62 61 6e 6b 00}  //weight: 5, accuracy: High
        $x_10_4 = {53 6d 73 20 75 70 6c 6f 61 64 20 72 65 73 75 6c 74 2d 2d 2d 3e 00}  //weight: 10, accuracy: High
        $x_10_5 = {0a 57 4f 4f 52 49 5f 44 4f 57 4e 00}  //weight: 10, accuracy: High
        $x_50_6 = {2f 77 65 62 6d 61 73 74 65 72 2f 61 63 74 69 6f 6e 2f 63 74 2e 70 68 70 00 [0-47] 19 2f 77 65 62 6d 61 73 74 65 72 2f 61 63 74 69 6f 6e 2f 6e 65 77 2e 70 68 70 00}  //weight: 50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Fakebank_B_2147686811_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakebank.B"
        threat_id = "2147686811"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakebank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 6d 64 5f 70 68 6f 6e 65 5f 69 6e 74 65 72 63 65 70 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 6d 64 5f 73 74 61 72 74 5f 62 61 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6d 64 5f 62 61 6e 6b 5f 49 6e 74 65 72 63 65 70 74 00}  //weight: 1, accuracy: High
        $x_2_4 = {2d 2d 64 77 6f 6e 20 66 69 6e 69 73 68 65 64 2d 2d 00}  //weight: 2, accuracy: High
        $x_2_5 = {3a 38 38 38 38 2f 68 61 6e 61 2e 61 70 6b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Fakebank_C_2147686825_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Fakebank.C"
        threat_id = "2147686825"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Fakebank"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 70 6c 6f 61 64 42 61 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 63 63 6f 75 6e 74 50 73 77 00}  //weight: 1, accuracy: High
        $x_1_4 = "Reseting:" ascii //weight: 1
        $x_1_5 = "moveto ACTIVITY_CREATED:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

