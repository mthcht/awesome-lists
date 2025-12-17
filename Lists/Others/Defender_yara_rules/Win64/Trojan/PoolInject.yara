rule Trojan_Win64_PoolInject_GA_2147933552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.GA!MTB"
        threat_id = "2147933552"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 4c 24 28 33 c8 8b c1 89 44 24 24 8b 44 24 2c 89 44 24 28 eb b9}  //weight: 3, accuracy: High
        $x_3_2 = {0f b6 c8 48 8b 44 24 38 48 d3 e8 48 25 ff 00 00 00 48 63 4c 24 24 48 8b 54 24 28 48 03 d1 48 8b ca 48 8b 54 24 30 88 04 0a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_PoolInject_BR_2147935039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.BR!MTB"
        threat_id = "2147935039"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {45 33 ca 49 c1 e1 20 4c 0b c9 49 8b c9 45 88 0c 03 48 c1 e9 08 41 88 4c 03 01}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 0c 2f 4c 8d 1c 2f 45 0f b6 4b 01 49 c1 e1 08 4c 0b c9}  //weight: 2, accuracy: High
        $x_1_3 = {45 88 4c 03 ?? 41 88 4c 03 ?? 48 83 c7 08 48 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_GVA_2147941529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.GVA!MTB"
        threat_id = "2147941529"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 00 41 0f b6 81 ?? ?? ?? ?? 42 0f b6 14 0a 42 32 14 08 43 30 14 10 49 ff c2 48 8b 41 08 4c 3b 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_MR_2147948071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.MR!MTB"
        threat_id = "2147948071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b c3 48 c1 e9 10 25 ff 00 04 00 83 e1 06 89 05 6d 34 11 00 48 81 c9 29 00 00 01 48 f7 d1 48 23 0d 10 1d 11 00}  //weight: 10, accuracy: High
        $x_1_2 = "Stop reversing the binary" ascii //weight: 1
        $x_1_3 = "Reconsider your life choices" ascii //weight: 1
        $x_1_4 = "And go touch some grass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_C_2147950592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.C!MTB"
        threat_id = "2147950592"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 14 08 44 31 c2 88 14 08 48 8b 84 24 ?? ?? ?? ?? 8b 00 8b 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_SXA_2147950803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.SXA!MTB"
        threat_id = "2147950803"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 44 24 60 48 c7 44 24 50 ?? 00 00 00 ff 15 ?? ?? ?? ?? 48 89 44 24 68 e8 ?? ?? ?? ?? 48 8d 4c 24}  //weight: 3, accuracy: Low
        $x_2_2 = {48 63 84 24 dc 00 00 00 48 83 f8 ?? 73 35 48 8b 44 24 70 48 63 8c 24 dc 00 00 00 66 8b 94 4c aa 00 00 00 48 63 8c 24 dc 00 00 00 66 89 54 48 02 8b 84 24 dc 00 00 00 83 c0 ?? 89 84 24 dc 00 00 00 eb bd}  //weight: 2, accuracy: Low
        $x_1_3 = {48 8b 4c 24 28 4c 8d 44 24 28 48 8b d3 ff 15 ?? ?? ?? ?? 85 c0 75 16 48 8d 4c 24 28 ff 15 ?? ?? ?? ?? 48 8d 4c 24 28 ff 15 ?? ?? ?? ?? 48 8d 4c 24 28 45 33 c9 45 33 c0 33 d2 ff 15 ?? ?? ?? ?? 85 c0 75 bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_SXB_2147951008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.SXB!MTB"
        threat_id = "2147951008"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b c5 49 f7 e3 48 d1 ea 0f b6 c2 02 c0 02 d0}  //weight: 3, accuracy: High
        $x_2_2 = {73 23 48 8b 04 24 48 63 4c 24 4c 8b 54 8c 5c 48 63 4c 24 4c 89 54 88 04 8b 44 24 4c 83 c0 ?? 89 44 24 4c eb d2}  //weight: 2, accuracy: Low
        $x_1_3 = "/c timeout 2 & del /f /q \"%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_SXC_2147951031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.SXC!MTB"
        threat_id = "2147951031"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 44 24 60 48 c7 44 24 50 06 00 00 00 ff 15 ?? ?? ?? ?? 48 89 44 24 68 e8 ?? ?? ?? ?? 48 8d 4c 24 20}  //weight: 3, accuracy: Low
        $x_2_2 = {48 63 44 24 4c 48 83 f8 ?? 73 23 48 8b 04 24 48 63 4c 24 4c 8b 54 8c 5c 48 63 4c 24 4c 89 54 88 04 8b 44 24 4c 83 c0 ?? 89 44 24 4c eb d2}  //weight: 2, accuracy: Low
        $x_1_3 = {49 f7 d8 4d 31 c8 49 f7 d8 42 8a 14 02 0f be d2 0f af ca 01 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_SX_2147951144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.SX!MTB"
        threat_id = "2147951144"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 0f 4c d0 48 8d 05 ?? ?? ?? ?? 48 8b 04 d0 48 8b 0d ?? ?? ?? ?? 48 0f af ca 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 31 d1 48 29 c8}  //weight: 5, accuracy: Low
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "ShellExecuteEx" ascii //weight: 1
        $x_1_4 = "GetMessageW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_AR_2147952015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.AR!MTB"
        threat_id = "2147952015"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 44 24 58 b8 08 00 00 00 48 6b c0 07 48 8b 8c 24 d8 00 00 00 48 8b 04 01 48 89 44 24 50 b8 08 00 00 00 48 6b c0 07 48 8b 8c 24 d0 00 00 00 48 8b 54 24 50 48 89 14 01 b8 08 00 00 00 48 6b c0 07 48 8b 8c 24 d8 00 00 00}  //weight: 10, accuracy: High
        $x_8_2 = {48 8b 84 24 c8 00 00 00 48 89 44 24 20 48 8b 84 24 c0 00 00 00 48 83 c0 20 48 89 44 24 38 48 8b 44 24 20 48 89 44 24 28 48 8d 44 24 50 48 8b f8 48 8b 74 24 28 b9 10 00 00 00 f3 a4 48 8d 54 24 50}  //weight: 8, accuracy: High
        $x_7_3 = {b8 08 00 00 00 48 6b c0 07 48 c7 84 04 80 00 00 00 00 00 00 00 48 8b 84 24 d0 00 00 00 48 89 44 24 60 48 8b 54 24 60 48 8d 8c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_MK_2147952561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.MK!MTB"
        threat_id = "2147952561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 c0 0c 48 89 44 24 78 48 8b 44 24 78 0f b6 00 89 44 24 74 8b 44 24 74 89 c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 44 24 74 41 89 c0 48 8b 54 24 78 48 83 c2 01 48 8b 4c 24 68}  //weight: 10, accuracy: High
        $x_10_3 = {c7 44 24 64 00 00 00 00 48 8b 54 24 78 48 83 c2 01 8b 44 24 74 48 01 c2 48 8d 4c 24 64}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_AHB_2147953711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.AHB!MTB"
        threat_id = "2147953711"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {88 44 24 09 0f b6 44 24 09 c1 f8 ?? 0f b6 4c 24 09 c1 e1 ?? 0b c1 0f b6 4c 24 09 33 c8 8b c1 88 44 24 09}  //weight: 20, accuracy: Low
        $x_30_2 = {48 8b 84 24 b0 00 00 00 48 25 ?? ?? ?? ?? 0f b7 c0 89 44 24 70 48 8b 84 24 b0 00 00 00 48 c1 e8 ?? 48 25 ?? ?? ?? ?? 0f b7 c0}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_ARR_2147954232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.ARR!MTB"
        threat_id = "2147954232"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 63 84 24 c8 00 00 00 45 8b 44 ?? 04 48 63 84 24 c8 00 00 00 44 23 44 24 38 45 03 c0 41 8b 54 ?? 04 48 63 84 24}  //weight: 15, accuracy: Low
        $x_10_2 = {83 c8 01 44 8b c7 42 89 04 09 4d 03 c1 48 8b 05 ?? ?? ?? ?? 48 8d 4c 24 ?? 48 89 44 24 ?? 33 d2 33 c0 41 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_MKA_2147954932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.MKA!MTB"
        threat_id = "2147954932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8b 8c 24 68 03 00 00 88 c2 8b 84 24 64 03 00 00 0f be d2 01 d0 89 84 24 70 03 00 00 48 8b 05}  //weight: 15, accuracy: High
        $x_10_2 = {0f be c9 0f af c1 89 c1 44 89 c0 8d 04 88 8a 0d ?? ?? ?? ?? 0f be c9 f7 f1 8a 0d ?? ?? ?? ?? 0f be c9 29 c8 83 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_FO_2147957515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.FO!MTB"
        threat_id = "2147957515"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 c7 84 24 00 01 00 00 80 69 67 ff 48 8d 84 24 00 01 00 00 48 89 44 24 50 48 c7 44 24 48 00 00 00 00 48 c7 44 24 40 00 00 00 00 48 8d 84 24 58 06 00 00 48 89 44 24 38 48 8d 84 24 10 01 00 00 48 89 44 24 30 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 02 00 4c 8d 4c 24 60 4c 8d 84 24 80 05 00 00 48 8d 94 24 48 05 00 00 48 8d 8c 24 78 05 00 00 ff 94 24 38 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_KK_2147957800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.KK!MTB"
        threat_id = "2147957800"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {33 d2 48 8d 0d ?? ?? ?? ?? ?? ?? ?? 00 00 48 8b 00 48 83 c0 20 48 89 44 24 60 48 8b 44 24 60 8b 00 ff c0 48 8b 4c 24 60 89 01 33 c0 85 c0}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_PoolInject_AHD_2147959622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PoolInject.AHD!MTB"
        threat_id = "2147959622"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {41 0f af cb 44 03 ee 8d 14 09 0f be ?? ?? ?? ?? ?? 2b d3 41 03 d6 03 ca 0f}  //weight: 30, accuracy: Low
        $x_20_2 = {89 44 24 38 8b 44 24 38 b9 0d f0 ad ba ba ef be ad de 85 c0 0f 45 ca}  //weight: 20, accuracy: High
        $x_10_3 = "Stop reversing the binary" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

