rule TrojanDropper_Win32_Nuwar_B_2147595774_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nuwar.B"
        threat_id = "2147595774"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $n_100_1 = "\\Simply Super Software\\Trojan Remover\\" ascii //weight: -100
        $x_1_2 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed}  //weight: 1, accuracy: High
        $x_1_3 = "/config /syncfro" ascii //weight: 1
        $x_1_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00}  //weight: 1, accuracy: High
        $x_1_5 = "windev-" ascii //weight: 1
        $x_1_6 = "wincom32.sys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Nuwar_A_2147600049_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nuwar.gen!A"
        threat_id = "2147600049"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 0f b7 45 fc 33 d2 f7 f7 30 14 33 43 47 3b d9 72 ef ff 75 f4 56 ff 75 f8}  //weight: 1, accuracy: High
        $x_1_2 = {56 8d 85 cc fc ff ff 50 e8 cf 01 00 00 83 c4 0c a1 40 20 40 00 89 85 cc fc ff ff 83 8d e0 fc ff ff 01 81 a5 e0 fc ff ff ff ff f0 ff}  //weight: 1, accuracy: High
        $x_1_3 = {81 e0 ff 00 00 00 8b 4d f8 0f b6 09 31 c1 8b 45 f8 88 08 eb ?? c9 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {81 e0 ff 00 00 00 88 45 ?? 8b 45 08 8b 4d fc 01 c8 0f b6 4d ?? 0f b6 55 ?? 31 d1 88 08 eb ?? c9 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {81 e0 ff 00 00 00 [0-3] 88 45 ?? 8b 45 08 8b 4d fc 01 c8 0f b6 4d ?? 51 0f b6 4d ?? 51 89 45 [0-64] 88 01 (eb ??|e9 ?? ?? ?? ??) c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Nuwar_B_2147601229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nuwar.gen!B"
        threat_id = "2147601229"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 14 ff 75 10 e8 ?? ?? ff ff 83 c4 ?? 39 f3 73 0b e8 ?? ?? ff ff 30 04 3b 43 eb f1}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 75 14 ff 75 10 e8 ?? ?? ff ff 83 c4 ?? 39 ?? 73 18 e8 ?? ?? ff ff 50 0f b6 04 ?? 50 e8 ?? ?? ff ff 88 04 ?? ?? ?? ?? eb e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Nuwar_C_2147603728_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Nuwar.gen!C"
        threat_id = "2147603728"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Nuwar"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c e8 74 04 3c e9 75 0f 8b 46 01 2b c7 03 45 fc 8d 44 30 fb 89 47 01 03 5d fc 03 7d fc 03 75 fc 83 fb 05 72 c2 2b f7 83 ee 05 89 77 01 c6 07 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0e 8b d8 8b 01 ff 50 14 50 53 ff 15 ?? ?? ?? ?? 8b 0e 8b 11 50 ff 12 8b 0e 8b 01 ff 50 04 47 83 ff ?? 72 ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 41 1b ff d0 85 c0 7c 13 8b 07 a3 ?? ?? ?? ?? 8b 06 a3 ?? ?? ?? ?? b8 03 00 00 40 5f 5e eb 21 ff 75 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

