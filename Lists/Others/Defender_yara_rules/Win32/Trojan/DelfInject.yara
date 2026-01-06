rule Trojan_Win32_DelfInject_A_2147640164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.A"
        threat_id = "2147640164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff}  //weight: 2, accuracy: High
        $x_2_2 = " /1stemail.php HTTP/1.1" ascii //weight: 2
        $x_1_3 = ".162.85.234" ascii //weight: 1
        $x_1_4 = "205.251.140.178" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DelfInject_BS_2147749292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.BS!MTB"
        threat_id = "2147749292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {8a 00 88 45 ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 30 45 f7 8b 45 ?? 8a 55 f7 88 10 8b e5 5d c3 06 00 89 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_B_2147755888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.B!MTB"
        threat_id = "2147755888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 74 11 83 7d fc 04 75 0b c7 45 fc 00 00 00 00 80 34 01 ?? ff 45 fc 41 89 d3 39 d9 90 90 75 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RR_2147779781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RR!MTB"
        threat_id = "2147779781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ca 00 02 00 00 a9 00 00 00 20 74}  //weight: 1, accuracy: High
        $x_1_2 = {31 d1 89 c8 6a 00 6a 01 a1 [0-5] 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RV_2147779950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RV!MTB"
        threat_id = "2147779950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 07 88 07 8d 45 ec 8a 17}  //weight: 2, accuracy: High
        $x_2_2 = {89 07 8b 03 8b 17 89 10 83 03 04 8b 03 83 38 00 75 a2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_DD_2147780840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.DD!MTB"
        threat_id = "2147780840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 83 8c 01 00 00 b2 01 a1 38 1b 42 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b f0 89 b3 70 01 00 00 8b 53 70}  //weight: 1, accuracy: High
        $x_1_3 = {a0 a0 9d 45 00 88 83 62 01 00 00 c6 83 63 01 00 00 02 c6 83 64 01 00 00 01 c7 83 68 01 00 00 01 00 00 00 c6 83 50 01 00 00 01 33 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AF_2147781682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AF!MTB"
        threat_id = "2147781682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "spiralbundene" ascii //weight: 3
        $x_3_2 = "bristler" ascii //weight: 3
        $x_3_3 = "EDLIN" ascii //weight: 3
        $x_3_4 = "dosers" ascii //weight: 3
        $x_3_5 = "Udlejningsejendommen9" ascii //weight: 3
        $x_3_6 = "Kurverne" ascii //weight: 3
        $x_3_7 = "springningernes" ascii //weight: 3
        $x_3_8 = "Slaskedukken7" ascii //weight: 3
        $x_3_9 = "Swarms5" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RF_2147783936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RF!MTB"
        threat_id = "2147783936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 03 8b 00 25 ff ff 00 00 50 8b 06 50 e8 ?? ?? ?? ?? 89 07 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 8b 06 50 e8 ?? ?? ?? ?? 89 07 8b 03 8b 17 89 10 83 03 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RF_2147783936_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RF!MTB"
        threat_id = "2147783936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f2 3f 8d 91 ?? ?? ?? ?? 81 f3 51 03 00 00 8b 45 ?? 8b 40 ?? 03 45 ?? 89 45 ?? 8d 14 03 29 d1 83 f2 3f}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 c4 f0 74 ?? 8b 5d ?? 8b 5b ?? 8b 75 ?? 8b 76 ?? 03 1e 66 25 ff 0f 0f b7 c0 03 d8 8b 45 ?? 8b 40 ?? 01 03 83 01 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 08 f6 c5 f0 74 ?? 8b 45 ?? 8b 00 03 05 ?? ?? ?? ?? 66 81 e1 ff 0f 0f b7 c9 03 c1 8b 0d ?? ?? ?? ?? 01 08 83 45 ?? 02 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 2b 50 ?? 8b 45 ?? 8b 00 03 c7 8b 4d ?? 66 8b 09 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 8b 45 ?? 83 c0 02 89 45 ?? 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c4 f9 74 ?? 8b 4d ?? 8b 49 ?? 8b 75 ?? 8b 76 ?? 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 ?? 8b 40 ?? 01 01 83 03 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 8b 00 25 ff ff 00 00 50 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 16 89 02 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 83 c0 04 89 ?? 8b ?? 8b ?? 85 ?? 75 ?? a1 ?? ?? ?? ?? 83 c0 14 a3 ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 10 00 00 50 8d 04 9b 8b 44 c6 ?? 03 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {f6 c4 f0 74 ?? 8b 5d ?? 8b 5b ?? 8b 75 ?? 8b 76 ?? 03 1e 66 25 ff 0f 0f b7 c0 03 d8 8b 45 ?? 8b 40 ?? 01 03 83 01 02 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 52 50 8b 43 ?? 99 03 04 24 13 54 24 ?? 83 c4 08 89 45 ?? 8b 45 ?? 89 48}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 03 c1 e8 0c 83 f8 03 75 ?? 8b 45 ?? 8b d6 2b 50 ?? 8b 45 ?? 8b 00 03 c6 0f b7 0b 66 81 e1 ff 0f 0f b7 c9 03 c1 01 10 83 c3 02 4f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RT_2147787195_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RT!MTB"
        threat_id = "2147787195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 c4 f9 74 ?? 8b 4d ?? 8b 49 ?? 8b 75 ?? 8b 76 ?? 03 0e 66 25 ff 0f 0f b7 c0 03 c8 8b 45 ?? 8b 40 ?? 01 01 8d 0c 03 8d 8b [0-30] 83 03 02}  //weight: 1, accuracy: Low
        $x_1_2 = {66 f7 c6 00 f9 74 ?? 8b 45 ?? 8b 40 ?? 8b 4d ?? 8b 49 ?? 03 01 66 81 e6 ff 0f 0f b7 ce 03 c1 8b 4d ?? 8b 49 ?? 01 08 83 03 02 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DelfInject_ME_2147788933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.ME!MTB"
        threat_id = "2147788933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 0b 00 00 00 d2 e1 f6 ed ef ee e4 ae}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AG_2147798208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AG!MTB"
        threat_id = "2147798208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 6c 11 fc 01 c5 89 6c 13 04 83 c2 04 81 fa fc 4f 00 00 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {a1 60 ca 8d 00 89 43 08 56 ff 74 24 04 68 00 50 00 00 53 ff d7 a1 7c ca 8d 00 01 d8 03 43 0c 03 1d 7c ca 8d 00 53 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AG_2147798208_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AG!MTB"
        threat_id = "2147798208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "WinHttpCrackUrl" ascii //weight: 3
        $x_3_2 = {46 00 52 00 45 00 52 00 05 00 4d 00 54 00 4f 00 47 00 4f}  //weight: 3, accuracy: High
        $x_3_3 = "DockSite" ascii //weight: 3
        $x_3_4 = "DeCoder" ascii //weight: 3
        $x_3_5 = "KillTimer" ascii //weight: 3
        $x_3_6 = "LoadKeyboardLayoutA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AG_2147798208_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AG!MTB"
        threat_id = "2147798208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ZcedmjnZ" ascii //weight: 3
        $x_3_2 = "WndProcPtr%.8X%.8X" ascii //weight: 3
        $x_3_3 = "winhttp" ascii //weight: 3
        $x_3_4 = {44 00 45 00 53 00 54 00 41 00 04 00 41 00 4b 00 41 00 4e}  //weight: 3, accuracy: High
        $x_3_5 = {71 49 44 41 54 78 9c ed 9d 69 83 82 2a 14 86 c5 b6 a9 6c 9b b4 a9 b1 29}  //weight: 3, accuracy: High
        $x_3_6 = "WinHttpCrackUrl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AE_2147798447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AE!MTB"
        threat_id = "2147798447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e0 8b 00 89 45 d4 8b 45 e0 83 c0 04 89 45 e0 8b 45 d8 89 45 dc 8b 45 dc 83 e8 04 89 45 dc 33 c0 89 45 bc 33 c0 89 45 b8 c7 45 cc 6e c3 01 00 33 c0 89 45 c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_DF_2147798520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.DF!MTB"
        threat_id = "2147798520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SendMail" ascii //weight: 3
        $x_3_2 = "LockResource" ascii //weight: 3
        $x_3_3 = "WinHttpCrackUrl" ascii //weight: 3
        $x_3_4 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_5 = "AutoHotkeysT" ascii //weight: 3
        $x_3_6 = {5a 00 41 00 4d 00 4f 00 52 00 05 00 43 00 48 00 45 00 43 00 4d}  //weight: 3, accuracy: High
        $x_3_7 = {42 00 42 00 41 00 42 00 4f 00 52 00 54 00 05 00 42 00 42 00 41 00 4c 00 4c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AQ_2147798739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AQ!MTB"
        threat_id = "2147798739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ShellExecuteA" ascii //weight: 3
        $x_3_2 = {5a 00 41 00 4d 00 4f 00 52 00 05 00 43 00 48 00 45 00 43 00 4d 00 05 00 42 00 42 00 4e 00 4b 00 4f}  //weight: 3, accuracy: High
        $x_3_3 = "JtwNswVxsWteOhJ5KH2DA" ascii //weight: 3
        $x_3_4 = "DilHrsLyuN" ascii //weight: 3
        $x_3_5 = "HelpKeywordp" ascii //weight: 3
        $x_3_6 = "AutoLineReduction" ascii //weight: 3
        $x_3_7 = "\\Configuration.ini" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AM_2147798740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AM!MTB"
        threat_id = "2147798740"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Print Screen to File" ascii //weight: 3
        $x_3_2 = "Screen.bmp" ascii //weight: 3
        $x_3_3 = {54 00 45 00 43 00 4f 00 05 00 54 00 45 00 43 00 4f 00 4d}  //weight: 3, accuracy: High
        $x_3_4 = "Picture.Data" ascii //weight: 3
        $x_3_5 = "winhttp" ascii //weight: 3
        $x_3_6 = "DllGetClassObject" ascii //weight: 3
        $x_3_7 = "ActivateKeyboardLayout" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_QW_2147799574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.QW!MTB"
        threat_id = "2147799574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {42 00 42 00 41 00 42 00 4f 00 52 00 54 00 05 00 42 00 42 00 41 00 4c 00 4c}  //weight: 3, accuracy: High
        $x_3_2 = {54 00 46 00 52 00 4d 00 5f 00 4c 00 49 00 4e 00 5f 00 53 00 59 00 53 00 54 00 45 00 4d}  //weight: 3, accuracy: High
        $x_3_3 = "crypt32" ascii //weight: 3
        $x_3_4 = "Bitmap.Data" ascii //weight: 3
        $x_3_5 = "btn_creer_systemeClick" ascii //weight: 3
        $x_3_6 = "APropos2Click" ascii //weight: 3
        $x_3_7 = "vvvjjjcccaaaaaabbbbbbaaaaaaeeennn" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_QE_2147805525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.QE!MTB"
        threat_id = "2147805525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {43 00 4c 00 5f 00 4d 00 50 00 42 00 41 00 43 00 4b}  //weight: 3, accuracy: High
        $x_3_2 = {44 00 49 00 5f 00 4d 00 50 00 52 00 45 00 43 00 4f 00 52 00 44}  //weight: 3, accuracy: High
        $x_3_3 = "ApiSetHost.AppExecutionAlias" ascii //weight: 3
        $x_3_4 = "888EPPPfQQQfQQQfSVWfTWXfTWXfUXYfTVWfTVWfQRRfQQQfPPPf888E" ascii //weight: 3
        $x_3_5 = "WinSpool" ascii //weight: 3
        $x_3_6 = "InetIsOffline" ascii //weight: 3
        $x_3_7 = "TrackMouseEvent" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_QR_2147805526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.QR!MTB"
        threat_id = "2147805526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d0 03 d2 8b 4c 24 08 8d 54 d1 04 89 54 24 04 8b 54 24 04 8b 0b 89 0a 8b 54 24 04 89 13 40 83 f8 64}  //weight: 10, accuracy: High
        $x_3_2 = {45 00 4d 00 53 00 49 00 52 00 4f}  //weight: 3, accuracy: High
        $x_3_3 = "RTLConsts" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_QG_2147805527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.QG!MTB"
        threat_id = "2147805527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 08 88 0a c3 0f b7 08 66 89 0a c3 66 8b 08 8a 40 02 66 89 0a 88 42 02 c3 8b 08 89 0a c3}  //weight: 10, accuracy: High
        $x_3_2 = {45 00 4d 00 53 00 49 00 52 00 4f}  //weight: 3, accuracy: High
        $x_3_3 = "synacode" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_QA_2147806301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.QA!MTB"
        threat_id = "2147806301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HTTPWebNode.Agent" ascii //weight: 3
        $x_3_2 = "Borland SOAP 1.2" ascii //weight: 3
        $x_3_3 = "SOAPAttach" ascii //weight: 3
        $x_3_4 = "ShellExecuteExW" ascii //weight: 3
        $x_3_5 = "InternetCrackUrlA" ascii //weight: 3
        $x_3_6 = "base64Binary" ascii //weight: 3
        $x_3_7 = "CeaEusYNbrJ" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_C_2147814998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.C!MTB"
        threat_id = "2147814998"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "T__2679099957" ascii //weight: 3
        $x_3_2 = "WA_VMSIB" ascii //weight: 3
        $x_3_3 = "T__2670651631" ascii //weight: 3
        $x_3_4 = "8NLL7OMM7PNN68760" ascii //weight: 3
        $x_3_5 = "FindResourceA" ascii //weight: 3
        $x_3_6 = "VirtualAlloc" ascii //weight: 3
        $x_3_7 = "SizeofResource" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_CA_2147814999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.CA!MTB"
        threat_id = "2147814999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "philaPINO SofN" ascii //weight: 3
        $x_3_2 = "MP_I3MSIS" ascii //weight: 3
        $x_3_3 = "LoadResource" ascii //weight: 3
        $x_3_4 = "mgclt.h16.ru" ascii //weight: 3
        $x_3_5 = "naumov_@mail.ru" ascii //weight: 3
        $x_3_6 = "password" ascii //weight: 3
        $x_3_7 = "UniversalPass" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_CB_2147815091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.CB!MTB"
        threat_id = "2147815091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "5YTGT3456TMOYTR56QW" ascii //weight: 3
        $x_3_2 = "RsGg9NObOcDaPILyVYeb" ascii //weight: 3
        $x_3_3 = "T__1ff32ccU" ascii //weight: 3
        $x_3_4 = "SHGetFolderPathA" ascii //weight: 3
        $x_3_5 = "\\save\\solved" ascii //weight: 3
        $x_3_6 = "*.crswrd|*.crswrd" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_CB_2147815091_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.CB!MTB"
        threat_id = "2147815091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "HintShortCuts" ascii //weight: 3
        $x_3_2 = "philaPINO SofN" ascii //weight: 3
        $x_3_3 = "T__3929095737" ascii //weight: 3
        $x_3_4 = "GetLastActivePopup" ascii //weight: 3
        $x_3_5 = "GetKeyboardState" ascii //weight: 3
        $x_3_6 = "GetKeyboardLayoutNameA" ascii //weight: 3
        $x_3_7 = "TaskbarCreated" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_MA_2147815843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.MA!MTB"
        threat_id = "2147815843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e 5a 2d 24 46 5a 2d 24 3e 5a 09 00 33 4c 3a 34 2f 48 3e 38 9b 4e 38 32 91 4a 09 00 62 7e 09 56 bb 0c 7d 75 c3 12 48 6c c6 11 6a 00 62 7e 09 00 62 7e 5f 69 90 0a 7c 61 86 38 7b 65 87 7e 09}  //weight: 1, accuracy: High
        $x_1_2 = {2a de 09 10 da b9 14 f8 21 01 f2 04 f6 68 83 4d 6b 07 4c f8 d8 ca f3 c0 4b 7b 89 e1 61 3e e9 02 60 46 83 45 4b 07 44 fc e8 48 c9 e9 60 fe e7 0f 22 5f 0a 0a 0a 0a 0d c0 40 7d 0b c8 60 c9 f2 4e}  //weight: 1, accuracy: High
        $x_1_3 = "Ctrl+" ascii //weight: 1
        $x_1_4 = "shutdown" ascii //weight: 1
        $x_1_5 = "getprotobynumber" ascii //weight: 1
        $x_1_6 = "WSAUnhookBlockingHook" ascii //weight: 1
        $x_1_7 = "GetKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_RRR_2147816197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RRR!MTB"
        threat_id = "2147816197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 47 02 00 00 a9 1c 00 00 00 0f af cb 6a 04 68 00 10 00 00 a1 ?? ?? ?? ?? 50 8b 06 8d 04 80 8b 15 ?? ?? ?? ?? 8b 44 c2 ?? 03 05 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 69 c0 47 02 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_DA_2147819302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.DA!MTB"
        threat_id = "2147819302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 f0 2b d1 89 55 f0 0f b6 05 ?? ?? ?? ?? 8b 4d f0 2b c8 89 4d f0 0f b6 15 ?? ?? ?? ?? 03 55 f0 89 55 f0 0f b6 05 ?? ?? ?? ?? 33 45 f0 89 45 f0 0f b6 0d ?? ?? ?? ?? 8b 55 f0 2b d1 89 55 f0 0f b6 05 ?? ?? ?? ?? 03 45 f0 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11 e9}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 f0 2b c2 89 45 f0 b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 03 4d f0 89 4d f0 68 ?? ?? ?? ?? 8d 4d dc e8 ?? ?? ?? ?? 8d 4d dc e8 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 8b 45 f0 2b c2 89 45 f0 8b 0d ?? ?? ?? ?? 03 4d ec 8a 55 f0 88 11 e9}  //weight: 10, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DelfInject_RPU_2147819775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.RPU!MTB"
        threat_id = "2147819775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 40 fc 8b 40 04 83 e8 08 d1 e8 8b 55 08 89 42 f0 8b 45 08 8b 40 fc 83 c0 08 89 01 8b 45 08 8b 50 f0 4a 85 d2 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_DB_2147834826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.DB!MTB"
        threat_id = "2147834826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 55 ec 01 02 8b 45 b8 03 45 e8 89 45 b4 [0-15] 8b 55 d8 03 55 b4 03 c2 8b 55 ec 31 02 [0-15] 8b 55 e8 83 c2 04 03 c2 89 45 e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_SSP_2147835405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.SSP!MTB"
        threat_id = "2147835405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CfF0iuwEdtG6OscKMv.Tkdn4yRccjuDMqdVmJ" ascii //weight: 2
        $x_2_2 = "FJCXTZbYx" ascii //weight: 2
        $x_2_3 = "889.114.1.14451" ascii //weight: 2
        $x_1_4 = "$8cb56e64-8836-4230-ba31-61ae1b39d16c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DelfInject_MBFE_2147850100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.MBFE!MTB"
        threat_id = "2147850100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ifjgoafgnklcqvoazkdkpobhbeljpyhvgxi" wide //weight: 1
        $x_1_2 = {18 53 40 00 98 11 40 00 10 f2 70 00 00 ff ff ff 08 00 00 00 01 00 00 00 0c 00 00 00 e9 00 00 00 98 29 40 00 dc 10 40 00 a0 10 40 00 78 00 00 00 7d 00 00 00 80}  //weight: 1, accuracy: High
        $x_1_3 = {6f 7a 69 6f 00 63 6d 00 00 46 69 65 73 74 61 73 00 00 00 00 f4 01 00 00 b0 54 40 00 00 00 00 00 c0 be 44 00 d0 be 44 00 2c 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AY_2147896933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AY!MTB"
        threat_id = "2147896933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 33 32 c4 32 07 88 07 47 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AZ_2147896984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AZ!MTB"
        threat_id = "2147896984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 cc 8a 04 33}  //weight: 1, accuracy: High
        $x_1_2 = {32 07 88 07 47 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AX_2147897099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AX!MTB"
        threat_id = "2147897099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 33 32 c4}  //weight: 1, accuracy: High
        $x_1_2 = {32 07 88 07 47 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AA_2147898556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AA!MTB"
        threat_id = "2147898556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 8b 00 89 85 b4 fe ff ff 8b 85 cc fe ff ff 8b 04 85 6c 26 5f 00 89 85 b8 fe ff ff b8 d8 a5 59 00 89 85 bc fe ff ff 8b 85 cc fe ff ff 8b 04 85 6c 36 5f 00 31 d2 89 85 a8 fe ff ff 89 95 ac fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_AB_2147900133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.AB!MTB"
        threat_id = "2147900133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_ADE_2147928516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.ADE!MTB"
        threat_id = "2147928516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 16 88 c3 32 da c1 e8 08 33 04 9d 40 54 41 00 88 c3 32 de c1 e8 08 33 04 9d 40 54 41 00 c1 ea 10 88 c3 32 da c1 e8 08 33 04 9d 40 54 41 00 88 c3 32 de c1 e8 08 33 04 9d 40 54 41 00 83 c6 04}  //weight: 2, accuracy: High
        $x_1_2 = {88 c3 32 1e c1 e8 08 46 33 04 9d 40 54 41 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DelfInject_MK_2147960595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DelfInject.MK!MTB"
        threat_id = "2147960595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DelfInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "u_ScreenSpy" ascii //weight: 15
        $x_15_2 = "u_VideoSpy" ascii //weight: 15
        $x_15_3 = "vu_MemRunExe" ascii //weight: 15
        $x_10_4 = "nu_FunProc" ascii //weight: 10
        $x_5_5 = "u_ReadCMD" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

