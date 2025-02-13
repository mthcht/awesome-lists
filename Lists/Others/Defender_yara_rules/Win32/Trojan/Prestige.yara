rule Trojan_Win32_Prestige_SB_2147913040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Prestige.SB"
        threat_id = "2147913040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Prestige"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 46 48 8b 7a 4c 89 7e 4c 83 7a 4c 10 77 06}  //weight: 1, accuracy: High
        $x_1_2 = {03 f3 c7 06 65 2b 30 30 8d 46 04 33 d2 e9 ?? ?? ?? ?? 8b d1 c7 45 c4 09 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 f8 26 76 03 6a 26 58 0f b6 0c 85 be 53 47 00 0f b6 34 85 bf 53 47 00}  //weight: 1, accuracy: High
        $x_1_4 = {b9 fe 02 00 00 3b c1 0f 4f c1 8d 8d ec fc ff ff 50 89 85 e8 fc ff ff e8}  //weight: 1, accuracy: High
        $x_1_5 = {3b f0 73 0a 8b c6 89 74 24 10 89 7c 24 14 50 ff 75 08}  //weight: 1, accuracy: High
        $x_1_6 = {8d 45 fc 50 8b d6 e8 ?? ?? ?? ?? 8b 75 08 8b f8 59}  //weight: 1, accuracy: Low
        $x_1_7 = {8b f2 57 8b f9 8d 4e 02 66 8b 06 83 c6 02 66 85 c0}  //weight: 1, accuracy: High
        $x_1_8 = {85 c0 74 0c 8d 43 2c 89 45 f8 8b 00}  //weight: 1, accuracy: High
        $x_1_9 = {89 45 d8 8b 45 e8 5e 13 ce f7 65 e0 6a 00 89 45 ec}  //weight: 1, accuracy: High
        $x_1_10 = {59 c3 8b 4c 24 0c 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 0c 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

