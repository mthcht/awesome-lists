rule Trojan_Win32_Tilcun_A_2147597039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tilcun.gen!A"
        threat_id = "2147597039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tilcun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 45 fa c1 e8 08 8b 55 ec 32 02 8b 55 e8 88 02 8b 45 ec 0f b6 00 66 03 45 fa 66 69 c0 2e 16 66 05 38 15 66 89 45 fa 8b 45 e8 40 89 45 e8 8b 45 ec 40 89 45 ec ff 45 f0 ff 4d e4 75 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tilcun_B_2147603536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tilcun.gen!B"
        threat_id = "2147603536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tilcun"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 22 0f b7 d7 c1 ea 08 32 13 88 16 33 d2 8a 13 66 03 fa 66 69 d7 2e 16 66 81 c2 38 15 8b fa 46 43 48 75 de}  //weight: 1, accuracy: High
        $x_1_2 = {81 7d 08 21 74 9e 22 75 1d 6a 00 a1 ?? ?? ?? ?? 50 b8 ?? ?? ?? ?? 50 6a 03 e8}  //weight: 1, accuracy: Low
        $n_10_3 = "Softany" ascii //weight: -10
        $n_10_4 = "68B42D1B5018F4305F92EA03BFF5866C743E2F704594" ascii //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

