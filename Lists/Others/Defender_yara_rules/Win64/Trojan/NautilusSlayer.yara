rule Trojan_Win64_NautilusSlayer_A_2147962423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NautilusSlayer.A"
        threat_id = "2147962423"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NautilusSlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 72 72 6f 72 3a 20 46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 66 69 6c 65 21 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 68 69 73 49 73 4d 79 4b 65 79 48 61 48 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 72 72 6f 72 3a 20 46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 74 6f 20 66 69 6c 65 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {64 72 6f 70 20 64 72 69 76 65 72 20 73 75 63 63 65 73 73 66 75 6c 6c 79 3a 20 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 21 5d 20 43 6f 6e 6e 65 63 74 69 6f 6e 20 74 6f 20 74 68 65 20 64 72 69 76 65 72 20 66 61 69 6c 65 64 20 5b 21 5d 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

