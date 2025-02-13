rule Trojan_Win32_Esendi_D_2147730990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Esendi.D"
        threat_id = "2147730990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Esendi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {56 33 f6 46 eb 29 8b 0c b5 ?? ?? ?? ?? 8d 04 b5 ?? ?? ?? ?? 50 ff 30 8d 82 ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? 8b 14 b5 ?? ?? ?? ?? 8d 76 03}  //weight: 20, accuracy: Low
        $x_10_2 = {80 fb 21 8b c2 0f 45 c1 42 8b c8 8a 1a 84 db ?? ?? 85 c9 ?? ?? 8d 41 01}  //weight: 10, accuracy: Low
        $x_10_3 = {3c 20 74 14 8b ca 0f be c0 83 c9 01 46 0f af c8 03 d1}  //weight: 10, accuracy: High
        $x_10_4 = {8d 57 04 8b 0a 33 c8 81 e1 ff ff ff 7f 33 c8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 87 34 06 00 00 33 c1}  //weight: 10, accuracy: High
        $x_10_5 = {8d 57 04 8b 0a 33 c8 81 e1 ff ff ff 7f 33 c8 8b c1 24 01 0f b6 c0 f7 d8 1b c0 d1 e9 25 df b0 08 99 33 87 b4 f2 ff ff 33 c1 89 87 40 f6 ff ff 8d 3a 8b 02 83 eb 01}  //weight: 10, accuracy: High
        $x_10_6 = {8b 8e 80 13 00 00 33 4e 04 81 e1 ff ff ff 7f 33 8e 80 13 00 00 8b c1 24 01 0f b6 c0 f7 d8 5f 1b c0 d1 e9 25 df b0 08 99 33 86 34 06 00 00 33 c1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            ((1 of ($x_20_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

