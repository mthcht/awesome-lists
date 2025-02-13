rule Trojan_Win32_Delkrom_A_2147718003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Delkrom.A"
        threat_id = "2147718003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Delkrom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 f8 ba 02 00 00 00 e8 ?? ?? ?? ?? c3 e9 ?? ?? ?? ?? eb eb 5e 5b 59 59 5d 05 00 68}  //weight: 10, accuracy: Low
        $x_1_2 = {00 73 63 20 64 65 6c 65 74 65 20 22 67 75 70 64 61 74 65 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 73 63 20 64 65 6c 65 74 65 20 22 67 75 70 64 61 74 65 6d 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 73 63 20 64 65 6c 65 74 65 20 22 67 75 73 76 63 22 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 55 41 22 20 2f 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 73 63 68 74 61 73 6b 73 20 2f 65 6e 64 20 2f 74 6e 20 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 22 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 22 47 6f 6f 67 6c 65 55 70 64 61 74 65 54 61 73 6b 4d 61 63 68 69 6e 65 43 6f 72 65 22 20 2f 66 00}  //weight: 1, accuracy: High
        $x_1_8 = {20 64 65 6c 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 47 6f 6f 67 6c 65 5c 55 70 64 61 74 65 22 20 2f 66 20 2f 73 20 2f 71 00}  //weight: 1, accuracy: High
        $x_1_9 = {20 64 65 6c 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 47 6f 6f 67 6c 65 5c 43 6f 6d 6d 6f 6e 5c 47 6f 6f 67 6c 65 20 55 70 64 61 74 65 72 22 20 2f 66 20 2f 73 20 2f 71 00}  //weight: 1, accuracy: High
        $x_1_10 = {20 64 65 6c 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 28 78 38 36 29 25 5c 47 6f 6f 67 6c 65 5c 55 70 64 61 74 65 22 20 2f 66 20 2f 73 20 2f 71 00}  //weight: 1, accuracy: High
        $x_1_11 = {20 64 65 6c 20 22 25 50 72 6f 67 72 61 6d 46 69 6c 65 73 28 78 38 36 29 25 5c 47 6f 6f 67 6c 65 5c 43 6f 6d 6d 6f 6e 5c 47 6f 6f 67 6c 65 20 55 70 64 61 74 65 72 22 20 2f 66 20 2f 73 20 2f 71 00}  //weight: 1, accuracy: High
        $x_1_12 = {20 64 65 6c 20 22 25 61 70 70 64 61 74 61 25 5c 47 6f 6f 67 6c 65 5c 55 70 64 61 74 65 22 20 2f 66 20 2f 73 20 2f 71 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

