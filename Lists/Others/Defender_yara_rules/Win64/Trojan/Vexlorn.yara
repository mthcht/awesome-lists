rule Trojan_Win64_Vexlorn_A_2147978165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Vexlorn.A"
        threat_id = "2147978165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Vexlorn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 61 69 6e 2e 47 65 74 43 6f 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {6d 61 69 6e 2e 52 75 6e 44 4c 4c 4d 69 4d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {6d 61 69 6e 2e 47 65 74 43 6f 6e 66 69 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {6d 61 69 6e 2e 73 65 6e 64 43 6f 6d 70 61 74 69 62 69 6c 69 74 79 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 61 69 6e 2e 44 65 63 72 79 70 74 00 6d 61 69 6e 2e 49 73 45 00}  //weight: 1, accuracy: High
        $x_1_6 = {6d 61 69 6e 2e 52 75 6e 4d 65 45 6c 65 76 61 74 65 64 00 6d 61 69 6e 2e 69 73 45 6c 65 76 61 74 65 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

