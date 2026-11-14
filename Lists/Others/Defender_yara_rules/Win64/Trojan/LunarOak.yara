rule Trojan_Win64_LunarOak_A_2147982141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LunarOak.A"
        threat_id = "2147982141"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LunarOak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 00 6c 00 73 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 65 00 6e 00 70 00 6f 00 72 00 74 00 76 00 2e 00 73 00 79 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 6e 00 50 00 6f 00 72 00 74 00 76 00 20 00 42 00 59 00 4f 00 56 00 44 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 2d 00 6e 00 20 00 32 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 6e 00 75 00 6c 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 6c 00 73 00 22 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 6f 70 68 6f 73 20 46 69 6c 65 20 53 63 61 6e 6e 65 72 20 53 65 72 76 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 6f 70 68 6f 73 20 4e 65 74 77 6f 72 6b 20 54 68 72 65 61 74 20 50 72 6f 74 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_6 = {46 2d 53 65 63 75 72 65 20 47 61 74 65 6b 65 65 70 65 72 20 48 61 6e 64 6c 65 72 20 53 74 61 72 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

