rule Trojan_Win32_Yayih_A_2147647757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yayih.A"
        threat_id = "2147647757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yayih"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 84 48 f9 ff ff 56 6a 08 8d 8d f0 fe ff ff 56 51 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b f8 83 c4 10 3b fe 75 0a 56 56 56 6a 08 e9}  //weight: 1, accuracy: High
        $x_1_3 = {85 c0 74 07 eb cb 6a 02 58 eb 09 56 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 14 83 7d c0 0a 74 09 83}  //weight: 1, accuracy: High
        $x_2_5 = {89 4d 08 d1 f8 d1 e0 78 28 57 8d 75 ?? 8d 7d ?? 83 c0 02 2b f3 2b fb 8b cb d1 e8 8a 51 01 88 14 0e 8a 11 fe ca 88 14 0f 41 41 48 75}  //weight: 2, accuracy: Low
        $x_2_6 = {85 c0 7e 17 8b 45 fc 80 04 08 7a 03 c1 8b 45 fc 80 34 08 ?? 03 c1 41 3b 0a 7c e9}  //weight: 2, accuracy: Low
        $x_2_7 = {85 ff 89 4d 08 7e 11 8a 15 ?? ?? ?? ?? 30 14 08 8b 7d ?? 40 3b c7 7c ef 83 65 ?? 00 8b c7 99 8b 75 0c 2b c2 d1 f8}  //weight: 2, accuracy: Low
        $x_1_8 = {85 c0 7e 12 8d 4c 38 ff 8a 11 fe ca 88 54 35 ?? 46 49 3b f0 7c f2 8d 45 00 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_9 = {5c 61 75 6d 4c 69 62 2e 69 6e 69 00}  //weight: 1, accuracy: High
        $x_1_10 = {2f 62 62 73 2f 69 6e 66 6f 2e 61 73 70 00}  //weight: 1, accuracy: High
        $x_1_11 = {41 70 70 6d 74 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

