rule Backdoor_Win32_Scieron_B_2147691613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Scieron.B!dha"
        threat_id = "2147691613"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Scieron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b7 01 66 83 f8 2c 74 0c 66 83 f8 3b 74 06 66 83 f8 7c}  //weight: 10, accuracy: High
        $x_10_2 = {0f b7 08 66 83 f9 2c 74 0c 66 83 f9 3b 74 06 66 83 f9 7c}  //weight: 10, accuracy: High
        $x_10_3 = {6a 02 88 46 05 58 66 89 7e 06 5b 66 0f b6 0c 30 66 01 0e 40 83 f8 0c}  //weight: 10, accuracy: High
        $x_10_4 = {6a 03 ff b6 0c 02 00 00 ff b6 08 02 00 00 50 ff b6 00 02 00 00 ff b6 14 02 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {8d 46 03 99 83 e2 03 03 c2 c1 f8 02 83 f8 02}  //weight: 10, accuracy: High
        $x_10_6 = {88 46 04 88 4e 05 89 56 08 66 89 7e 06 66 0f b6 56 02 66 01 16 0f b7 0e 66 0f b6 46 03 66 03 c1 66 89 06 66 0f b6 4e 04 66 03 c8}  //weight: 10, accuracy: High
        $x_10_7 = {88 47 04 88 4f 05 89 57 08 66 89 6f 06 66 0f b6 57 02 66 01 17 0f b7 0f 66 0f b6 47 03 66 03 c1 66 89 07 66 0f b6 4f 04 66 03 c8}  //weight: 10, accuracy: High
        $x_10_8 = "explorer.exe" wide //weight: 10
        $x_10_9 = "httpsapi_dll_5_1" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Scieron_A_2147691614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Scieron.A!dha"
        threat_id = "2147691614"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Scieron"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 04 20 6d 3b ?? ff 15}  //weight: 3, accuracy: Low
        $x_1_2 = {6d 00 73 00 68 00 74 00 74 00 70 00 5f 00 64 00 6c 00 6c 00 5f 00 35 00 5f 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 5c 00 2e 00 5c 00 49 00 70 00 6e 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {69 00 70 00 6e 00 65 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 00 4f 00 52 00 54 00 5f 00 4e 00 55 00 4d 00 00 00 50 00 4f 00 52 00 54 00 5f 00 4e 00 55 00 4d 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {49 00 50 00 5f 00 50 00 41 00 44 00 44 00 49 00 4e 00 47 00 5f 00 44 00 41 00 54 00 41 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {48 00 54 00 43 00 6c 00 69 00 65 00 6e 00 74 00 3b 00 20 00 25 00 73 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {25 00 75 00 00 00 00 00 50 00 4f 00 53 00 54 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

