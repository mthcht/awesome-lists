rule TrojanClicker_Win32_Tolouge_A_2147681410_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Tolouge.A"
        threat_id = "2147681410"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Tolouge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 68 61 63 65 72 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 75 00 73 00 75 00 61 00 72 00 69 00 6f 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 66 00 61 00 62 00 72 00 65 00 5c 00 61 00 75 00 74 00 6f 00 43 00 6c 00 69 00 63 00 6b 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8d 4e 44 88 46 50 66 89 5e 34 ff 15 ?? ?? ?? ?? 66 c7 46 3a 73 00 66 c7 46 3c 9b 00 66 c7 46 3e 0a 00 66 c7 46 40 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_Win32_Tolouge_2147682319_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Tolouge"
        threat_id = "2147682319"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Tolouge"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 61 00 75 00 74 00 6f 00 43 00 6c 00 69 00 63 00 6b 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {66 72 6d 4d 61 69 6e 00 66 72 6d 41 64 00 00 00 6d 6f 64 53 6c 65 65 70 00 00 00 00 6d 6f 64 4d 6f 75 73 65 45 76 65 6e 74 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 61 63 65 72 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 00 61 00 72 00 67 00 61 00 6e 00 64 00 6f 00 20 00 77 00 65 00 62 00 3a 00 20 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "Web Cargada" wide //weight: 1
        $x_1_6 = {43 00 6c 00 69 00 63 00 6b 00 20 00 65 00 6e 00 20 00 65 00 6c 00 20 00 62 00 61 00 6e 00 6e 00 65 00 72 00 3a 00 20 00 48 00 65 00 63 00 68 00 6f 00 20 00 65 00 6e 00 20 00 6c 00 61 00 20 00 70 00 6f 00 73 00 69 00 63 00 69 00 6f 00 6e 00 20 00 58 00 3a 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 00 61 00 72 00 67 00 61 00 6e 00 64 00 6f 00 20 00 50 00 75 00 62 00 6c 00 69 00 63 00 69 00 64 00 61 00 64 00 2e 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {42 00 61 00 6e 00 6e 00 65 00 72 00 20 00 63 00 61 00 72 00 67 00 61 00 6e 00 64 00 6f 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 61 00 6d 00 65 00 6e 00 74 00 65 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 00 69 00 6d 00 65 00 72 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

