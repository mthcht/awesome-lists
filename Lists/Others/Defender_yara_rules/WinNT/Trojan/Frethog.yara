rule Trojan_WinNT_Frethog_AD_2147602288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Frethog.AD"
        threat_id = "2147602288"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 40 04 89 45 ?? 81 e9 4b e1 22 00 [0-7] 83 e9 ?? 74 0a ?? bb 00 00 c0 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {80 4e 06 01 6a 00 56 ff 15}  //weight: 1, accuracy: High
        $x_3_3 = {83 65 fc 00 6a 04 6a 04 57 ff 15 ?? ?? 01 00 6a 04 6a 04 ?? ff 15 ?? ?? 01 00 83 4d fc ff 8b}  //weight: 3, accuracy: Low
        $x_3_4 = {83 e8 05 89 45 ?? 6a 05 ?? 8d 45 03 00 e9}  //weight: 3, accuracy: Low
        $x_2_5 = {83 fe 01 74 1d 83 fe 02 74 18 83 fe 26 74 13 83 fe 03 74 0e 83 fe 25 74 09 83 fe 0c}  //weight: 2, accuracy: High
        $x_2_6 = {3b 7d 1c 75 09 c7 45 28 06 00 00 80 eb 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Frethog_AE_2147606983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Frethog.AE"
        threat_id = "2147606983"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d f0 4d 5a 91 11 75 07 c6 05 ?? ?? 01 00 01 81 7d f0 4b 43 55 46 75 07 c6 05 ?? ?? 01 00 00 33 c9 8a 0d ?? ?? 01 00 85 c9 75 09 81 7d f0 4b 43 55 46 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

