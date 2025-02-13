rule Trojan_Win32_Hsow_A_2147595270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hsow.gen!A"
        threat_id = "2147595270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hsow"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 63 6f 6d 6d 61 6e 64 00 53 65 44 65 62 75 67}  //weight: 1, accuracy: High
        $x_1_2 = {0b c0 74 2a 89 45 f8 8d 45 dc 50 6a 01 ff 75 f8 e8}  //weight: 1, accuracy: High
        $x_1_3 = {68 3f 00 0f 00 53 53 e8}  //weight: 1, accuracy: High
        $x_3_4 = {c7 45 e4 01 00 00 00 8d 75 f4 8d 7d e8 b9 08 00 00 00 f3 a4 c7 45 f0 02 00 00 00 8d 45 e0}  //weight: 3, accuracy: High
        $x_1_5 = {50 8d 45 e4 50 6a 10 8d 45 e4 50 6a 00 ff 75 fc}  //weight: 1, accuracy: High
        $x_3_6 = {ac aa 85 c0 75 fa 4f 80 7f ff 5c 74 06 66 c7 47 ff 5c 00 66 c7 07 74 00 6a 00 6a 06}  //weight: 3, accuracy: High
        $x_1_7 = {33 f8 d1 ef b8 0a 00 00 00 33 c0 eb 05}  //weight: 1, accuracy: High
        $x_3_8 = {64 65 73 6b 74 6f 70 2e 69 6e 69 00 55 8b ec 81 c4 58 f4 ff ff 57}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

