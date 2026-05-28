rule Trojan_Win64_SteelScuttle_A_2147970377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SteelScuttle.A"
        threat_id = "2147970377"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SteelScuttle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 59 53 54 45 4d 5f 49 4e 46 4f 7c 43 6f 6d 70 75 74 65 72 3a 25 73 7c 4f 53 3a 25 73 7c 44 6f 6d 61 69 6e 3a 25 73 7c 55 73 65 72 3a 25 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {57 53 41 53 74 61 72 74 75 70 20 66 61 69 6c 65 64 3a 20 00}  //weight: 1, accuracy: High
        $x_1_3 = {46 61 69 6c 65 64 20 74 6f 20 63 72 65 61 74 65 20 73 6f 63 6b 65 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {55 6e 6b 6e 6f 77 6e 20 4f 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

