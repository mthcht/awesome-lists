rule TrojanDownloader_Win32_Peguese_D_2147653902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Peguese.D"
        threat_id = "2147653902"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Peguese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 85 18 fe ff ff 89 85 1c fe ff ff c6 85 20 fe ff ff 0b 8d 85 1c fe ff ff 50 8d 95 14 fe ff ff b8}  //weight: 1, accuracy: High
        $x_1_2 = {68 e8 03 00 00 e8 ?? ?? ?? ff 33 c0 55 68 ?? ?? ?? 00 64 ff 30 64 89 20 8d 55 94 b8}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 95 08 fb ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 08 fb ff ff e8 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 95 b8 fa ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 b8 fa ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 76 07}  //weight: 1, accuracy: Low
        $x_1_5 = {8d 95 f4 fa ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 85 f4 fa ff ff e8 ?? ?? ?? ?? 50 6a 00 e8 ?? ?? ?? ?? 85 c0 76 07}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 95 a8 fa ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 8b 85 a8 fa ff ff e8 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 1, accuracy: Low
        $x_1_7 = {8d 95 e4 fa ff ff b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 8b 85 e4 fa ff ff e8 ?? ?? ?? ?? 50 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Peguese_J_2147661762_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Peguese.J"
        threat_id = "2147661762"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Peguese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2e 63 70 6c 00 43 50 6c 41 70 70 6c 65 74 00}  //weight: 5, accuracy: High
        $x_5_2 = {06 74 6d 72 49 6e 69 fc 02}  //weight: 5, accuracy: High
        $x_5_3 = {0c 74 6d 72 42 6c 6f 71 54 69 6d 65 72 12}  //weight: 5, accuracy: High
        $x_5_4 = {0a 74 6d 72 46 32 54 69 6d 65 72 11}  //weight: 5, accuracy: High
        $x_5_5 = {0b 74 6d 72 45 73 63 54 69 6d 65 72}  //weight: 5, accuracy: High
        $x_1_6 = {8b 08 ff 51 1c 8b 85 ?? ?? ff ff 50 8d 95 ?? ?? ff ff b8 ?? ?? ?? 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

