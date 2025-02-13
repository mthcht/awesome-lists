rule Trojan_Win32_Qorifecho_A_2147705990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Qorifecho.A"
        threat_id = "2147705990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Qorifecho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 00 00 00 51 00 43 00 48 00 52 00 4f 00 4d 00 45 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {08 00 00 00 51 00 46 00 49 00 52 00 45 00 46 00 4f 00 58 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f bf c0 25 00 80 00 00 66 85 c0 74 07 b8 01 00 00 00 eb 69 83 3b 09 75 11}  //weight: 1, accuracy: High
        $x_1_4 = {68 fa 00 00 00 e8 ?? ?? ?? ff a1 ?? ?? ?? 00 8b 00 e8 ?? ?? ?? ff 33 d2 8b c3 e8 ?? ?? ?? ff b2 03 8b c3}  //weight: 1, accuracy: Low
        $x_1_5 = {7e 12 b8 01 00 00 00 8b 4b 04 66 83 7c 41 fe 7c 40 4a 75 f3}  //weight: 1, accuracy: High
        $x_1_6 = {e9 b9 00 00 00 8b c3 c7 00 02 00 00 00 c7 40 04 01 00 00 00 c7 40 08 02 00 00 00 33 d2 89 50 0c b8 01 00 00 00 e9 94 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

