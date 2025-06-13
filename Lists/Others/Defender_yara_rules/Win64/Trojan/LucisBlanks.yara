rule Trojan_Win64_LucisBlanks_AA_2147943611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucisBlanks.AA"
        threat_id = "2147943611"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucisBlanks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 7b 22 6e 61 6d 65 22 3a 20 22 25 73 22 2c 20 22 62 75 69 6c 64 5f 64 61 74 65 22 3a 20 22 25 73 20 25 73 22 2c 20 22 61 72 63 68 22 3a 20 22 77 69 6e 64 6f 77 73 22 2c 20 22 69 64 22 3a 20 22 25 73 22 2c 20 22 75 73 65 72 6e 61 6d 65 22 3a 20 22 25 73 22 2c 20 22 70 69 64 22 3a 20 22 25 64 22 20 7d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 43 4f 4d 50 55 54 45 52 4e 41 4d 45 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 55 53 45 52 4e 41 4d 45 00}  //weight: 1, accuracy: High
        $x_1_4 = {70 72 6f 78 79 2e 6c 6f 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LucisBlanks_AB_2147943612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LucisBlanks.AB"
        threat_id = "2147943612"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LucisBlanks"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 5b 2b 5d 20 5b 54 43 50 43 6c 69 65 6e 74 5d 5b 53 65 6e 64 5d 20 73 65 6e 64 69 6e 67 20 64 61 74 61 3a 20 25 73 2c 20 6c 65 6e 3a 20 25 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 5b 2b 5d 20 52 43 56 20 43 4d 44 20 4b 49 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5b 2b 5d 20 52 45 43 56 20 63 66 67 20 73 74 61 72 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 5b 2b 5d 20 53 6f 63 6b 73 34 41 3a 20 69 64 65 6e 74 3a 25 73 3b 20 64 6f 6d 61 69 6e 3a 25 73 3b 20 74 68 72 65 61 64 3d 25 6c 6c 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5b 2b 5d 20 53 6f 63 6b 73 34 3a 20 63 6f 6e 6e 65 63 74 20 62 79 20 69 70 20 26 20 70 6f 72 74 20 74 68 72 65 61 64 3d 25 6c 6c 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

