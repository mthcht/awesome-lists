rule Trojan_Win32_Ranumbot_GA_2147751389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GA!MTB"
        threat_id = "2147751389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 9b 00 00 00 00 8b 7c 24 14 8b ?? c1 ?? 05 89 4c 24 10 8b 44 24 ?? 01 44 24 10 8b ?? c1 e6 04 03 74 24 20 8d 14 2f 33 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 74 24 10 81 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 10 33 cb 33 ce 8d 44 24 14 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 83 6c 24 18 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GA_2147751389_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GA!MTB"
        threat_id = "2147751389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3d b2 79 32 00 75 ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 40 3d 32 89 93 00 7c ?? 81 05 ?? ?? ?? ?? e1 bf 01 00 33 ?? 81 ?? d8 dc 35 00 75 ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? 81 ?? 36 bd 5a 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 45 fc b8 e1 bf 01 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GA_2147751389_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GA!MTB"
        threat_id = "2147751389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3d b2 79 32 00 75 ?? 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 40 3d 32 89 93 00 7c ?? 81 05 ?? ?? ?? ?? e1 bf 01 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 33 ?? 81 ?? d8 dc 35 00 75 ?? 56 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? 81 ?? 36 bd 5a 00 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 45 fc b8 e1 bf 01 00 01 45 fc 8b 45 fc 8a 04 08 88 04 0a c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_MX_2147754939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.MX!MTB"
        threat_id = "2147754939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 6c 24 58 b3 30 c7 6b 81 84 24 40 02 00 00 21 f4 7c 36 8b 44 24 ?? 30 0c 06 b8 01 00 00 00 29 44 24 ?? 83 7c 24 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RMG_2147755451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RMG!MTB"
        threat_id = "2147755451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b7 59 e7 1f f7 a4 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 81 44 24 ?? f3 ae ac 68 81 ac 24 ?? ?? ?? ?? b3 30 c7 6b 81 84 24 ?? ?? ?? ?? 21 f4 7c 36 30 0c 3e 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RQ_2147769053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RQ!MSR"
        threat_id = "2147769053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b f3 c1 e6 04 03 74 24 ?? 8d 14 1f 33 f2 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RD_2147772843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RD!MTB"
        threat_id = "2147772843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d0 89 45 ?? 89 95 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 29 45 ?? 81 3d ?? ?? ?? ?? d5 01 00 00}  //weight: 1, accuracy: Low
        $x_5_2 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 5, accuracy: Low
        $x_5_3 = {8d 0c 02 e8 ?? ?? ?? ?? 30 01 42 3b 54 24 ?? 7c}  //weight: 5, accuracy: Low
        $x_1_4 = {69 c0 fd 43 03 00 a3 ?? ?? ?? ?? 81 45 ?? c3 9e 26 00 a1 ?? ?? ?? ?? 03 45 ?? 83 65 ?? ?? a3 ?? ?? ?? ?? 81 45 ?? ff 7f 00 00 c1 e8 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ranumbot_GKM_2147774223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GKM!MTB"
        threat_id = "2147774223"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f8 94 08 00 01 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 8a 04 08 8b 15 ?? ?? ?? ?? 88 04 0a a1 ?? ?? ?? ?? 3d 03 02 00 00 75 ?? 89 35 ?? ?? ?? ?? 41 3b c8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RRQ_2147775270_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RRQ!MTB"
        threat_id = "2147775270"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 eb 05 89 5d 70 c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? 01 45 70 81 3d ?? ?? ?? ?? 12 09 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8d 04 16 50 8b 45 ?? e8 ?? ?? ?? ?? 33 45 ?? 89 3d ?? ?? ?? ?? 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RHJ_2147775680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RHJ!MTB"
        threat_id = "2147775680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {57 33 db 33 ff 3b eb 7e ?? 56 8b 44 24 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 fd 19 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GB_2147775848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GB!MTB"
        threat_id = "2147775848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 39 1d ?? ?? ?? ?? 76 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 8a 84 30 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88 04 31 46 3b 35 ?? ?? ?? ?? 72 ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 f6}  //weight: 10, accuracy: Low
        $x_10_2 = {51 6a 40 ff 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff d0 46 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GB_2147775848_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GB!MTB"
        threat_id = "2147775848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7c 24 14 8b ?? c1 e9 ?? 89 4c 24 10 8b 44 24 ?? 01 44 24 10 8b f7 c1 e6 ?? 03 74 24 ?? 8d 14 2f 33 f2 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 74 24 10 81 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4c 24 10 33 cb 33 ce 8d 44 24 14 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 83 6c 24 18 01 0f 85 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b 54 24 14 89 78 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GC_2147775975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GC!MTB"
        threat_id = "2147775975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f6 33 c0 3b ce ?? ?? 8b 3d ?? ?? ?? ?? 8a 94 07 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 88 14 03 81 f9 ?? ?? ?? ?? 40 3b c1}  //weight: 10, accuracy: Low
        $x_10_2 = "VirtualProtect" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GC_2147775975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GC!MTB"
        threat_id = "2147775975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 01 89 4d ?? 8b 55 ?? 8b 45 ?? 3b 82 ?? ?? ?? ?? 73 ?? 8b 4d ?? 03 4d ?? 0f b6 11 8b 45 ?? 03 45 ?? 0f b6 08 33 ?? 8b 55 ?? 03 55 ?? 88 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GD_2147776090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GD!MTB"
        threat_id = "2147776090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 ce c1 ee ?? 89 74 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 94 24 ?? ?? ?? ?? 8d 34 17 33 f1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 74 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GE_2147776091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GE!MTB"
        threat_id = "2147776091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cf c1 e9 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 4c 24 ?? 33 cb 33 ce 8d 84 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 83 ac 24 ?? ?? ?? ?? 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RT_2147776319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RT!MTB"
        threat_id = "2147776319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 55 e0 89 55 ?? c7 ?? ?? ?? ?? ?? 36 06 ea e9 8b ?? ?? 81 ?? ?? ?? ?? ?? ca f9 15 16 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RT_2147776319_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RT!MTB"
        threat_id = "2147776319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RT_2147776319_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RT!MTB"
        threat_id = "2147776319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 8b 2d ?? ?? ?? ?? 8d 64 24 ?? e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 81 ff 71 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RT_2147776319_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RT!MTB"
        threat_id = "2147776319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 c7 [0-9] 8b ?? ?? 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 05 ?? ?? ?? ?? 89 ?? ?? 83 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RT_2147776319_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RT!MTB"
        threat_id = "2147776319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4d e0 89 4d ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? ?? 81 05 [0-8] 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 15 ?? ?? ?? ?? 89 ?? ?? c7 05}  //weight: 1, accuracy: Low
        $x_1_2 = {03 55 e0 89 55 ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? ?? 81 ?? ?? ?? ?? ?? ca f9 15 16 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GF_2147776436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GF!MTB"
        threat_id = "2147776436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4c 24 10 33 cf 33 ce 8d 84 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 ac 24 ?? ?? ?? ?? 01 0f 85 78 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_KM_2147776499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.KM!MTB"
        threat_id = "2147776499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 3b cd 76 ?? 8b 35 ?? ?? ?? ?? 8a 94 06 ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88 14 07 81 f9 03 02 00 00 75 ?? 89 2d ?? ?? ?? ?? 40 3b c1 72 ?? 8b 3d ?? ?? ?? ?? 33 f6 eb ?? 8d 49 00 81 fe 6c 02 05 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GH_2147777006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GH!MTB"
        threat_id = "2147777006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 05 89 44 24 10 8b 84 24 ?? ?? ?? ?? 01 44 24 10 8d 0c 37 31 4c 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 54 24 ?? 31 54 24 ?? 83 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GH_2147777006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GH!MTB"
        threat_id = "2147777006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 ea 05 89 4c 24 ?? 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8d 04 33 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 83 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GI_2147777007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GI!MTB"
        threat_id = "2147777007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d6 33 ca 8d 84 24 ?? ?? ?? ?? e8 64 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 10 8b ?? 24 ?? ?? ?? ?? 01 ?? 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 10 8b ?? 24 0c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GJ_2147777444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GJ!MTB"
        threat_id = "2147777444"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d6 33 ca 8d ?? 24 ?? 89 ?? 24 ?? e8 64 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? 01 ?? 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 8b ?? 24}  //weight: 10, accuracy: Low
        $x_10_2 = {33 d6 33 ca 8d ?? 24 ?? e8 64 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? 01 ?? 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 8b ?? 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GL_2147777556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GL!MTB"
        threat_id = "2147777556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 33 c8 8d ?? 24 [0-4] e8 64 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 [0-4] 01 ?? 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 8b ?? 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GL_2147777556_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GL!MTB"
        threat_id = "2147777556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e8 05 89 ?? 24 ?? 89 ?? 24 ?? 8b ?? 24 ?? ?? ?? ?? 01 ?? 24 ?? 8b ?? 24 ?? 8d 0c 37 33 c1 31 44 24 ?? 83 3d ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 2b 5c 24 ?? c7 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GM_2147778459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GM!MTB"
        threat_id = "2147778459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 33 c8 8d ?? 24 ?? ?? ?? ?? 89 ?? 24 ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83 ?? 01 50 00 8b ?? c1 ?? 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 ?? 24 ?? 8b ?? 24 ?? 8b ?? 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_GN_2147778460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GN!MTB"
        threat_id = "2147778460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e9 05 89 ?? 24 ?? 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 44 24 ?? 8d 14 33 31 54 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 31 ?? 24 ?? 83 ?? ?? ?? ?? ?? ?? 2b ?? 24 ?? c7 ?? 24}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 89 ?? 24 ?? 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 44 24 ?? 8d 14 33 31 54 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 31 ?? 24 ?? 83 ?? ?? ?? ?? ?? ?? 2b ?? 24 ?? c7 ?? 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GO_2147778595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GO!MTB"
        threat_id = "2147778595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? 33 d6 33 ca 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 ?? 8b 4d ?? 33 d6 33 ca 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 83}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GP_2147778596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GP!MTB"
        threat_id = "2147778596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e9 05 89 45 ?? 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8d 14 37 31 55 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 2b [0-4] c7}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 89 45 ?? 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8d 14 37 31 55 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 83 3d ?? ?? ?? ?? ?? 2b [0-4] c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GQ_2147778605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GQ!MTB"
        threat_id = "2147778605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e9 05 89 ?? 24 ?? 89 ?? 24 ?? 8b ?? 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 2e 31 54 24 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 31 ?? 24 ?? 83 3d ?? ?? ?? ?? ?? 2b [0-4] c7}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 89 ?? 24 ?? 89 ?? 24 ?? 8b ?? 24 ?? ?? ?? ?? 01 44 24 ?? 8d 14 2e 31 54 24 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b ?? 24 ?? 31 ?? 24 ?? 83 3d ?? ?? ?? ?? ?? 2b [0-4] c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_RW_2147778708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RW!MTB"
        threat_id = "2147778708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 83 3d [0-6] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RW_2147778708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RW!MTB"
        threat_id = "2147778708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 45 ?? 81 05 ?? ?? ?? ?? ca f9 15 16 01 05 ?? ?? ?? ?? 8b ?? ?? 33 ?? ?? ?? ?? ?? 89 ?? ?? c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RW_2147778708_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RW!MTB"
        threat_id = "2147778708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 89 44 24 ?? 03 ce 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RW_2147778708_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RW!MTB"
        threat_id = "2147778708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 ?? ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 8b 45 e4 50 8d ?? ec 51 e8 ?? ?? ?? ?? 8b ?? ?? 2b ?? ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RTH_2147778768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTH!MTB"
        threat_id = "2147778768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 6c 24 ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RTH_2147778768_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTH!MTB"
        threat_id = "2147778768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 c7 [0-9] 8b ?? ec 01 ?? ?? ?? ?? ?? 8b ?? ?? 33 05 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RTH_2147778768_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTH!MTB"
        threat_id = "2147778768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 4d ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b 55 ?? 8b 4d ?? 33 d6 33 ca 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 ad ?? ?? ?? ?? 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RTH_2147778768_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTH!MTB"
        threat_id = "2147778768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 8d 0c 38 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 83 3d ?? ?? ?? ?? 71 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_GR_2147778871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.GR!MTB"
        threat_id = "2147778871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 ea 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 ?? 24 ?? 8b ?? 24 ?? 8b ?? 24 ?? 33 cf 33 c1 89 44 24 ?? 2b f0 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 83 ed 01 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 ?? 24 ?? 8b ?? 24 ?? 8b ?? 24 ?? 33 cf 33 c1 89 44 24 ?? 2b f0 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 83 ed 01 0f 85}  //weight: 10, accuracy: Low
        $x_10_3 = {c1 e9 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ff ff ff ff 89 ?? 24 ?? 8b ?? 24 ?? ?? 00 00 01 ?? 24 ?? 8b ?? 24 ?? 8b ?? 24 ?? 33 cf 33 c1 89 44 24 ?? 2b f0 8b 84 24 ?? ?? ?? ?? 29 44 24 ?? 83 ed 01 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_RM_2147778947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RM!MTB"
        threat_id = "2147778947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 4c 24 ?? 8d 0c 32 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RM_2147778947_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RM!MTB"
        threat_id = "2147778947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? ?? 89 ?? ?? c7 [0-9] 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e9 05 89 4d ?? 8b 45 ?? 01 45 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RM_2147778947_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RM!MTB"
        threat_id = "2147778947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 89 4d ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 55 ?? 33 55 ?? 89 55 ?? 83 3d [0-8] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 e0 01 45 ec c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 [0-12] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_RF_2147779228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RF!MTB"
        threat_id = "2147779228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RF_2147779228_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RF!MTB"
        threat_id = "2147779228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b ?? e4 33 ?? f0 89 ?? e4 8b ?? e4 50 8d ?? ?? 51 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RF_2147779228_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RF!MTB"
        threat_id = "2147779228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 83 3d ?? ?? ?? ?? 71 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RF_2147779228_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RF!MTB"
        threat_id = "2147779228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 85 db 7e ?? 56 8b 45 ?? 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 fb 19 75 ?? 33 c0 50 50 50 50 ff 15 ?? ?? ?? ?? 47 3b fb 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f6 85 ff 7e ?? 8d 9b ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 83 ff 19 75 ?? 6a 00 8d 85 ?? ?? ?? ?? 50 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ranumbot_RTA_2147779343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTA!MTB"
        threat_id = "2147779343"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 8b 2d ?? ?? ?? ?? 8d 9b ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 81 ff 71 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RTB_2147779346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RTB!MTB"
        threat_id = "2147779346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 3b fd 7e ?? 8b 2d [0-6] e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 33 ed 81 ff 71 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_RWA_2147779423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.RWA!MTB"
        threat_id = "2147779423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 55 8b 2d ?? ?? ?? ?? 8b ff e8 ?? ?? ?? ?? 30 04 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff d5 46 3b f7 7c ?? 5d 5e 81 ff 71 11 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ranumbot_SM_2147781208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ranumbot.SM!MSR"
        threat_id = "2147781208"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ranumbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WirteosBloclsk" ascii //weight: 1
        $x_1_2 = {8b 4d e4 33 4d ec 89 4d e4 8b 45 e4 29 45 d0 8b 55 e8 2b 55 d8 89 55 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

