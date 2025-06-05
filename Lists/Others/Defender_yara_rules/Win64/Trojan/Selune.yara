rule Trojan_Win64_Selune_A_2147942874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Selune.A"
        threat_id = "2147942874"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Selune"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 54 68 65 20 6e 75 6d 62 65 72 20 69 73 3a 20 25 6c 6c 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 66 61 69 6c 65 64 20 74 6f 20 72 65 61 64 20 66 69 6c 65 21 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 64 65 63 72 79 70 74 20 66 61 69 6c 65 64 3a 20 25 73 0a 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 61 76 75 70 64 61 74 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 57 43 42 43 63 62 74 63 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 56 42 6f 78 53 65 72 76 69 63 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 56 42 6f 78 54 72 61 79 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

