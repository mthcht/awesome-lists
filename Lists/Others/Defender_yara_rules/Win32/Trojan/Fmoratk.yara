rule Trojan_Win32_Fmoratk_A_2147684227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fmoratk.A"
        threat_id = "2147684227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fmoratk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 6f 72 6d 61 74 20 64 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 6f 72 6d 61 74 20 65 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 6f 72 6d 61 74 20 66 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {66 6f 72 6d 61 74 20 67 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {66 6f 72 6d 61 74 20 68 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {66 6f 72 6d 61 74 20 69 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_7 = {66 6f 72 6d 61 74 20 6a 3a 20 2f 71 20 2f 79 0d 0a 65 78 69 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 3a 5c 74 65 6d 70 5c 64 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 3a 5c 74 65 6d 70 5c 65 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {63 3a 5c 74 65 6d 70 5c 66 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {63 3a 5c 74 65 6d 70 5c 67 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_12 = {63 3a 5c 74 65 6d 70 5c 68 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_13 = {63 3a 5c 74 65 6d 70 5c 69 2e 62 61 74 00}  //weight: 1, accuracy: High
        $x_1_14 = {63 3a 5c 74 65 6d 70 5c 6a 2e 62 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

