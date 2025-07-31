rule Ransom_Win64_KaWaLocker_A_2147947000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KaWaLocker.A"
        threat_id = "2147947000"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KaWaLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 00 69 00 6c 00 6c 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00 00 00 00 00 00 00 76 00 61 00 6c 00 75 00 65 00 00 00 00 00 00 00 6b 00 69 00 6c 00 6c 00 5f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "KaWaLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_KaWaLocker_B_2147947952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KaWaLocker.B"
        threat_id = "2147947952"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KaWaLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 6b 00 69 00 70 00 5f 00 65 00 78 00 74 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {73 00 6b 00 69 00 70 00 5f 00 66 00 69 00 6c 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 00 6b 00 69 00 70 00 5f 00 64 00 69 00 72 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 70 00 65 00 63 00 69 00 66 00 79 00 5f 00 64 00 69 00 72 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {6b 00 69 00 6c 00 6c 00 5f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {6b 00 69 00 6c 00 6c 00 5f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {73 00 65 00 6c 00 66 00 5f 00 64 00 65 00 6c 00 65 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {74 00 68 00 72 00 65 00 61 00 64 00 5f 00 6e 00 75 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 00 6d 00 64 00 5f 00 70 00 6f 00 73 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {2d 64 3d 64 69 72 65 63 74 6f 72 79 0a 00}  //weight: 1, accuracy: High
        $x_1_11 = {2d 64 75 6d 70 20 5b 6f 70 74 69 6f 6e 61 6c 5d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Ransom_Win64_KaWaLocker_C_2147947953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/KaWaLocker.C"
        threat_id = "2147947953"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "KaWaLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 41 59 5f 48 49 5f 32 30 32 35 00}  //weight: 1, accuracy: High
        $x_1_2 = {61 6e 6f 74 68 65 72 20 69 6e 73 74 61 6e 63 65 20 61 6c 72 65 61 64 79 20 72 75 6e 6e 69 6e 67 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 61 62 6c 65 20 64 65 62 75 67 20 70 72 69 76 69 6c 65 67 65 20 66 61 69 6c 65 64 2e 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 6e 69 74 20 66 61 69 6c 65 64 2e 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

