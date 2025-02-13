rule Trojan_Win64_GoldMax_A_2147775899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoldMax.A!dha"
        threat_id = "2147775899"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoldMax"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 2e 64 65 6c 65 74 ?? 5f 65 6d 70 74 79 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6d 61 69 6e 2e 73 61 76 65 5f 69 6e 74 ?? 72 6e 61 6c 5f 73 65 74 74 69 6e 67 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 61 69 6e 2e 64 65 66 69 6e 65 5f 69 6e 74 65 ?? 6e 61 6c 5f 73 65 74 74 69 6e 67 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6d 61 69 6e 2e 77 67 65 74 5f 66 ?? 6c 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {6d 61 69 6e 2e 62 65 61 63 ?? 6e 69 6e 67 00}  //weight: 1, accuracy: Low
        $x_1_6 = {6d 61 69 6e 2e 72 65 71 75 65 73 74 5f 73 65 ?? 73 69 6f 6e 5f 6b 65 79 00}  //weight: 1, accuracy: Low
        $x_1_7 = {6d 61 69 6e 2e 72 65 74 72 69 65 76 65 5f 73 65 ?? 73 69 6f 6e 5f 6b 65 79 00}  //weight: 1, accuracy: Low
        $x_1_8 = {6d 61 69 6e 2e 72 65 73 6f 6c 76 65 5f 63 6f ?? 6d 61 6e 64 00}  //weight: 1, accuracy: Low
        $x_1_9 = {6d 61 69 6e 2e 73 65 6e 64 5f 66 ?? 6c 65 5f 70 61 72 74 00}  //weight: 1, accuracy: Low
        $x_1_10 = {6d 61 69 6e 2e 73 65 6e 64 5f 63 6f ?? 6d 61 6e 64 5f 72 65 73 75 6c 74 00}  //weight: 1, accuracy: Low
        $x_1_11 = {6d 61 69 6e 2e 66 61 6c 73 65 5f 72 65 71 ?? 65 73 74 69 6e 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

