rule Trojan_Win64_VerdantIsland_A_2147981395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VerdantIsland.A"
        threat_id = "2147981395"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VerdantIsland"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 52 5f 55 4e 49 51 55 45 5f 4b 45 59 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 53 79 73 74 65 6d 49 6e 66 6f 43 6f 6c 6c 65 63 74 6f 72 52 65 71 75 65 73 74 5d 20 43 72 65 61 74 65 20 61 63 63 65 73 73 20 74 6f 6b 65 6e 20 72 65 71 75 65 73 74 20 66 69 6c 65 64 20 73 65 6e 64 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 75 63 63 65 73 73 20 73 65 6e 64 20 75 70 64 61 74 65 20 73 74 61 74 75 73 3a 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {46 61 69 6c 20 67 65 74 20 68 77 69 64 56 6f 6c 75 6d 65 53 65 72 69 61 6c 4e 75 6d 62 65 72 0a 00}  //weight: 1, accuracy: High
        $x_1_5 = {5b 53 79 73 74 65 6d 49 6e 66 6f 43 6f 6c 6c 65 63 74 6f 72 52 65 71 75 65 73 74 5d 20 53 79 73 74 65 6d 20 69 6e 66 6f 20 63 6f 6c 6c 65 63 74 6f 72 20 72 65 71 75 65 73 74 20 66 61 69 6c 65 64 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

