rule TrojanClicker_Win32_Zeriest_A_2147637742_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zeriest.A"
        threat_id = "2147637742"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeriest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 6c 6e 6b 00 [0-16] 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 [0-16] 50 52 4f 47 52 41 4d 46 49 4c 45 53 00 [0-16] 5c 73 79 73 74 65 6d 5c 33 36 30 2e 69 63 6f 00 [0-16] 43 4f 4d 4d 4f 4e 50 52 4f 47 52 41 4d 46 49 4c 45 53}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 31 6e 6b 00 [0-16] 5c 73 79 73 74 65 6d 5c 74 61 6f 62 61 6f 2e 69 63 6f 00 [0-37] 68}  //weight: 1, accuracy: Low
        $x_1_3 = {54 42 46 49 4c 45 53 00 [0-16] 2e 75 72 31 00 [0-16] 49 45 46 49 4c 45 53 00 [0-16] 2e 69 65 00 [0-16] 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 2e 69 65 00 [0-32] 2e 75 72 31 00 [0-32] 2e 31 6e 6b 00 [0-16] 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 51 75 69 63 6b 20 4c 61 75 6e 63 68 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Zeriest_B_2147655215_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zeriest.B"
        threat_id = "2147655215"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeriest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 31 00 6e 00 6b 00 00 [0-16] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 61 00 78 00 74 00 68 00 6f 00 6e 00 32 00}  //weight: 1, accuracy: Low
        $x_1_2 = "taskkill /f /im ZhuDongFangyu.exe" wide //weight: 1
        $x_1_3 = "\\Internet Explorer.IE" wide //weight: 1
        $x_1_4 = {2e 00 6f 00 70 00 65 00 00 [0-16] 5c 00 4f 00 70 00 65 00 72 00 61 00 2e 00 6f 00 70 00 65 00 00 00 [0-16] 2e 00 69 00 63 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 75 00 72 00 31 00 00 [0-42] 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 46 00 69 00 6c 00 65 00 73 00 5c 00 33 00 36 00 30 00 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

