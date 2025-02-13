rule Backdoor_Win32_Lukicsel_C_2147626935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lukicsel.C"
        threat_id = "2147626935"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 02 6a 02 e8 ?? ?? ?? ?? 8b d8 83 fb ff 74 ?? 66 c7 84 24 ?? ?? ?? ?? 02 00 6a 07 e8 ?? ?? ?? ?? 66 89 84 24}  //weight: 2, accuracy: Low
        $x_2_2 = {32 06 88 07 46 47 4b 75 ?? 5f 5e}  //weight: 2, accuracy: Low
        $x_2_3 = {eb 07 6a 0a e8 ?? ?? ?? ?? 80 3b 00 74 f4 b2 01 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 06 eb 07}  //weight: 2, accuracy: Low
        $x_1_4 = {8b 5d 08 8b c3 8b 10 ff 12 c6 43 0c 01 8b c3 8b 10 ff 52 04 b2 01 8b c3 8b 08 ff 51 fc 6a 00}  //weight: 1, accuracy: High
        $x_1_5 = {e8 00 00 00 00 59 83 c1 ?? c1 (e0|e8) 03 01 c1 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Lukicsel_A_2147626996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lukicsel.A"
        threat_id = "2147626996"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 8a 09 32 ca 8b 5d f8 88 0b ff 45 fc ff 45 f8 48 75 eb}  //weight: 2, accuracy: High
        $x_2_2 = {7c 19 43 e8 ?? ?? ?? ?? 8b 55 fc 32 02 8b 55 f8 88 02 ff 45 fc ff 45 f8 4b 75 e8}  //weight: 2, accuracy: Low
        $x_2_3 = {b8 b8 88 00 00 e8 ?? ?? ?? ?? 66 05 88 13 50 e8}  //weight: 2, accuracy: Low
        $x_2_4 = {48 0f 85 c0 00 00 00 8d 45 e4 b9 02 00 00 00 ba 01 00 00 00 e8 ?? ?? ?? ?? 8d 45 e0 50 8b 55 e4 b8 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_2_5 = {6e 65 74 3d 67 6e 75 74 65 6c 6c 61 00 00 00 00 ff ff ff ff 05 00 00 00 67 65 74 3d 31 00 00 00 ff ff ff ff 0f 00 00 00 63 6c 69 65 6e 74 3d 6c 69 6d 65 77 69 72 65 00 ff ff ff ff 02 00 00 00 48 7c 00}  //weight: 2, accuracy: High
        $x_1_6 = "/skulls.php" ascii //weight: 1
        $x_1_7 = "/gwc.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Lukicsel_B_2147626998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lukicsel.B"
        threat_id = "2147626998"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lukicsel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 0f 43 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {49 50 31 00 ff ff ff ff 05 00 00 00 50 6f 72 74 31 00}  //weight: 1, accuracy: High
        $x_1_3 = {49 50 32 00 ff ff ff ff 05 00 00 00 50 6f 72 74 32 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 41 63 74 69 76 65 20 53 65 74 75 70 5c 44 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

