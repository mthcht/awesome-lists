rule Trojan_Win32_Waski_A_2147783780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.A!MTB"
        threat_id = "2147783780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 77 07 00 00 57 50 ba 24 24 40 00 52 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {4f 66 8b 07 8a cc 47 33 c0 e8 de 01 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 06 33 c1 e8 0b 00 00 00 c3 [0-21] 8b c8 88 07 83 c6 01 c3}  //weight: 1, accuracy: Low
        $x_1_4 = {6a 00 68 ff 00 00 00 68 00 da 55 00 68 18 21 55 00 68 18 21 55 00 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waski_A_2147783780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.A!MTB"
        threat_id = "2147783780"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d e8 8b 41 3c ff 75 f0 03 c1 0f b7 50 06 6b d2 28 8d 84 02 d0 00 00 00 8b 70 14 03 70 10 03 f1}  //weight: 1, accuracy: High
        $x_1_3 = {31 0c 96 8b 45 f8 42 c1 e8 02}  //weight: 1, accuracy: High
        $x_1_4 = "budha.exe" wide //weight: 1
        $x_1_5 = "kilf.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waski_E_2147787079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.E!MTB"
        threat_id = "2147787079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 8b 45 0c c1 e8 02 2b c1 50 f7 f3 [0-3] 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 ?? ?? ?? ?? 5a 31 16 83 c6 04 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {03 75 fc 8b 7d 0c 03 7f 3c 83 c7 14 83 c7 04 8b 7f 18 81 c7 ?? ?? ?? ?? 81 ef 00 20 00 00 03 7d 08 50 8b 45 0c 03 40 3c 83 c0 14 83 c0 04 8b 40 18 05 ?? ?? ?? ?? 2d 00 20 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waski_AA_2147793414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.AA!MTB"
        threat_id = "2147793414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 75 f4 33 c0 21 45 fc 8b 75 0c 8b c8 41 ac 85 c0 75 fa}  //weight: 10, accuracy: High
        $x_10_2 = {03 f0 47 51 33 c0 56 8b c8 ac 41 85 c0 75 fa}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waski_GSB_2147810539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.GSB!MTB"
        threat_id = "2147810539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 4d fc ba ec 8c 8b e8 89 55 b8 b8 ?? ?? ?? ?? 89 45 ac b9 ?? ?? ?? ?? 8b d1 c1 ca 06 89 55 c0 8b c1 35 ?? ?? ?? ?? 89 45 d4 c1 c9 1a 89 4d dc 89 2d}  //weight: 10, accuracy: Low
        $x_5_2 = {8b 13 8b 45 d8 2d ?? ?? ?? ?? 03 d8 4e 89 17 b8 ?? ?? ?? ?? 35 ?? ?? ?? ?? 03 f8 85 f6 75 be}  //weight: 5, accuracy: Low
        $x_5_3 = {33 c2 33 ff 3b d7 0f 84 ?? ?? ?? ?? 8b d7 e9 19 03 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Waski_GZZ_2147901849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waski.GZZ!MTB"
        threat_id = "2147901849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {10 56 8b f1 57 8d 46 08 33 ff 39 38 74 12 50 e8 b7 ea ff ff 83 c4 04 ff 46 0c 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = "188.255.239.34" ascii //weight: 1
        $x_1_3 = "173.243.255.79" ascii //weight: 1
        $x_1_4 = "ofylywo.exe" ascii //weight: 1
        $x_1_5 = "bloosid.exe" ascii //weight: 1
        $x_1_6 = "/g11.png" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

