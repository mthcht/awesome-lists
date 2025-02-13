rule Trojan_WinNT_Percol_A_2147647873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Percol.A"
        threat_id = "2147647873"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Percol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 e8 ?? ?? ?? ?? 8b 45 08 c7 40 40 ?? ?? ?? ?? 8b 4d 08 8b 55 08 8b 42 40 89 41 38 8b 4d 08 c7 41 70 ?? ?? ?? ?? 8b 55 08 c7 42 34 ?? ?? ?? ?? 33 c0 8b 4d fc 33 cd}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 45 ee 63 00 66 c7 45 f0 4c 00 66 c7 45 f2 69 00 66 c7 45 f4 6e 00 66 c7 45 f6 6b 00 66 c7 45 f8 00 00 6a 2a 8d 45 d0 50 e8 ?? ?? ?? ?? 89 45 c8 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 55 c8 89 45 c4 83 7d c4 00 7d ?? 8b 4d cc 51}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 85 30 ff ff ff 74 fa 4c 16 c7 85 34 ff ff ff 4a 0a 47 45 c7 85 38 ff ff ff 0d a5 ed 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

