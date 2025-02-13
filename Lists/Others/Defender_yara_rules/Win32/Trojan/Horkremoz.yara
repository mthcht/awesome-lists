rule Trojan_Win32_Horkremoz_A_2147691758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Horkremoz.A"
        threat_id = "2147691758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Horkremoz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 05 00 ?? 00 65 85 c0 0f 84 ?? 00 00 00 [0-16] 8b 4d}  //weight: 4, accuracy: Low
        $x_2_2 = {68 84 00 00 00 68 ?? ?? 00 65 e8 ?? ?? 00 00 83 c4 08 89 85 ?? fe ff ff}  //weight: 2, accuracy: Low
        $x_2_3 = {f8 6a 00 8b ?? 08 ?? 68 ?? ?? 00 65 6a 04 ff 15 ?? ?? 00 65 a3 00 50 00 65 8b}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 45 10 50 8b 4d 0c 51 8b 55 08 52 a1 00 50 00 65 50 ff 15}  //weight: 2, accuracy: High
        $x_1_5 = {83 7d f4 03 0f 87 ?? ?? 00 00 8b 4d f4 ff 24 8d ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_6 = {fe ff ff 6a 1d 68 ?? ?? 00 65 e8 ?? ?? 00 00 83 c4 08 89 85 ?? fe ff ff}  //weight: 1, accuracy: Low
        $x_2_7 = {83 ea 01 89 55 e4 8b 45 e4 35 ?? ?? ?? ?? 03 45 f4 89 45 f4 8b 4d f8 83 c1 01 89 4d f8 c7 45 f4 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_2_8 = {8a 02 88 01 8b [0-16] 89 [0-8] 8b 55 ?? 0f be 02 8b 4d ?? 0f be 11 33 d0 8b 45 ?? 88 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

