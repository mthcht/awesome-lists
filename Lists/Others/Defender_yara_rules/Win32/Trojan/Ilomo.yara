rule Trojan_Win32_Ilomo_A_2147600104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ilomo.gen!A"
        threat_id = "2147600104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilomo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 0f 04 41 88 06 46 c1 ea 04 e2 f2 c6 06 00 5e 8b 7d 04 83 c7 15 33 c0 56 57 50 6a 04 50 6a ff b8 44 33 22 11 ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 b8 8b 42 20 ff d0 85 c0 74 44 6a 05 8b 4d b8 8b 11 52 8b 45 b8 8b 48 24 ff d1 6a 00 6a 00 8b 55 b8 8b 02 50 8d 4d 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ilomo_B_2147622879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ilomo.gen!B"
        threat_id = "2147622879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ilomo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8d 45 fc 50 ff 75 08 ff 76 0c ff 77 08 ff 15 ?? ?? ?? ?? 85 c0 74 08 8b 45 08 3b 45 fc 74 10}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 42 eb 02 33 d2 52 53 ff 74 24 14 ff 71 08 ff 15 ?? ?? ?? ?? 85 c0 74 02 b3 01 8a c3}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 04 24 e8 03 00 00 8d 85 f4 fa ff ff 50 68 02 10 00 00 68 00 04 00 00 ff 15 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? 00 00 80 bd ?? ?? ?? ?? 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

