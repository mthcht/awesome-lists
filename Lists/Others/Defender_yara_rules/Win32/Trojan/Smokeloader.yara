rule Trojan_Win32_Smokeloader_G_2147773872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.G!MTB"
        threat_id = "2147773872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {01 45 fc 8b 45 f4 8b 4d f8 03 c2 d3 ea 89 45 f0 03 55 d4 8b 45 f0 31 45 fc 31 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_G_2147773872_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.G!MTB"
        threat_id = "2147773872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VirtualProtect" ascii //weight: 1
        $x_1_2 = ".pdb" ascii //weight: 1
        $x_1_3 = "cujalunodig" ascii //weight: 1
        $x_1_4 = "Feyocixugowa" ascii //weight: 1
        $x_1_5 = "yumejinef" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_DKL_2147808593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.DKL!MTB"
        threat_id = "2147808593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 c1 e0 08 03 c1 8b c8 c1 e0 10 03 c1 8b ca 83 e2 03 c1 e9 02 74 06}  //weight: 10, accuracy: High
        $x_1_2 = "VESURAGOSAG" ascii //weight: 1
        $x_1_3 = "CIDAFICUDUROSOTAROM" ascii //weight: 1
        $x_1_4 = "VIDIWAYAPENIGU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GY_2147814777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GY!MTB"
        threat_id = "2147814777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetMonitorInfo" ascii //weight: 1
        $x_1_2 = "GetTimeZoneInformation" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "huzefuhatocalu" ascii //weight: 1
        $x_1_5 = "coyurezajatevipulir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GY_2147814777_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GY!MTB"
        threat_id = "2147814777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 d3 e2 8d 0c 07 c1 e8 ?? 89 4c 24 18 03 54 24 38 89 44 24 14 89 54 24 10 8b 44 24 3c 01 44 24 14 8b 54 24 14 33 54 24 18 8b 44 24 10 33 c2 2b f0 81 c7 47 86 c8 61 83 ed ?? 89 44 24 10 89 1d ?? ?? ?? ?? 89 74 24 2c 89 7c 24 28 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_VX_2147820019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.VX!MTB"
        threat_id = "2147820019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d e8 8b c3 d3 e8 89 45 f8 8b 45 d0 01 45 f8 8b f3 c1 e6 04 03 75 d8 33 75 f0 81 3d e4 ba 8e 00}  //weight: 10, accuracy: High
        $x_10_2 = {56 69 72 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 72 6f 74 65 66 c7 05 ?? ?? ?? ?? 63 74 c6 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_XT_2147823781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.XT!MTB"
        threat_id = "2147823781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 8b 45 80 8d 1c 30 e8 ?? ?? ?? ?? 30 03 81 ff ?? ?? ?? ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_UE_2147824942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.UE!MTB"
        threat_id = "2147824942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 14 03 c1 83 e0 ?? 0f b6 80 ?? ?? ?? ?? 30 41 ?? 83 c1 ?? 8d 04 0e 3d ?? ?? ?? ?? 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_UH_2147825470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.UH!MTB"
        threat_id = "2147825470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 08 03 4d fc 0f be 11 89 55 f8 e8 ?? ?? ?? ?? 33 45 f8 8b 4d 08 03 4d fc 88 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_F_2147828906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.F!MTB"
        threat_id = "2147828906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 bc 56 c6 45 bd 69 8d 4d bc 51}  //weight: 1, accuracy: High
        $x_1_2 = "LertualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_F_2147828906_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.F!MTB"
        threat_id = "2147828906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 c4 04 10 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_F_2147828906_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.F!MTB"
        threat_id = "2147828906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 15 31 01 8b 0a 01 ad c2 15 f1 7b}  //weight: 1, accuracy: High
        $x_1_2 = {26 08 01 01 7b 3e 8a db 01 8b 0e 01 ad c2 b9 15 66 01 8b 0a 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_F_2147828906_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.F!MTB"
        threat_id = "2147828906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c6 83 c4 08 83 e0 03 8a 80 ?? ?? ?? ?? 30 86 ?? ?? ?? ?? 46 81 fe ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HA_2147830076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HA!MTB"
        threat_id = "2147830076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ec 51 c7 45 fc 02 00 00 00 8b 45 0c 01 45 fc 83 6d fc 02 8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 55 8b ec 8b 4d 08}  //weight: 10, accuracy: High
        $x_10_2 = {8b ca c1 e9 ?? 03 4d e4 89 45 08 33 c8 89 4d f4 8b 45 f4 01 05 ?? ?? ?? ?? 8b 45 f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GA_2147830211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GA!MTB"
        threat_id = "2147830211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 83 e0 03 8a 80 ?? ?? ?? ?? 30 04 3e 46 3b 75 0c 72 e6 5f 5e}  //weight: 10, accuracy: Low
        $x_1_2 = "\\output.pdb" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_IA_2147830368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.IA!MTB"
        threat_id = "2147830368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eovwwni" ascii //weight: 1
        $x_1_2 = "lgrmdyk" ascii //weight: 1
        $x_1_3 = "ecbzhry" ascii //weight: 1
        $x_1_4 = "SystemFunction036" ascii //weight: 1
        $x_1_5 = "GetSystemInfo" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_IG_2147830531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.IG!MTB"
        threat_id = "2147830531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 4c 24 1c 8b c5 83 e0 03 8a 04 08 8b 4c 24 14 30 04 29 45 3b 6c 24 18 72 dc}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_IK_2147830650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.IK!MTB"
        threat_id = "2147830650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 57 33 c9 bf 7e 07 00 00 8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b cf 72 ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_IK_2147830650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.IK!MTB"
        threat_id = "2147830650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b c6 c1 e0 ?? 03 45 f0 8d 0c 32 33 c1 33 45 ?? 2b f8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_TC_2147831009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.TC!MTB"
        threat_id = "2147831009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e1 04 03 4d f0 c1 e8 05 03 45 ec 33 ca 33 c1 89 4d 08 89 45 0c}  //weight: 10, accuracy: High
        $x_10_2 = {8d 4d fc 51 51 00 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GD_2147831541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GD!MTB"
        threat_id = "2147831541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 20 89 44 24 28 8b 44 24 18 c1 e8 ?? 89 44 24 14 8b 44 24 3c 01 44 24 14 8b 4c 24 14 33 4c 24 28 8b 44 24 10 81 44 24 ?? 47 86 c8 61 33 c1 2b f0 83 eb 01 89 44 24 10 89 3d ?? ?? ?? ?? 89 74 24 30 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GW_2147831841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GW!MTB"
        threat_id = "2147831841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 d0 c1 e8 05 03 45 e8 03 ce 33 ca 33 c1 89 55 0c 89 4d 08 89 45 f0 8b 45 f0}  //weight: 10, accuracy: High
        $x_10_2 = {01 45 fc 8b 45 08 8b 4d fc 31 08 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08 8b 45 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GWE_2147832082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GWE!MTB"
        threat_id = "2147832082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 08 8b 4d 0c 31 08 c9 c2 08 00 55 8b ec 8b 4d 08 8b 01 89 45 08}  //weight: 10, accuracy: High
        $x_10_2 = {8d 4d fc 51 44 00 c6 05 ?? ?? ?? ?? 63 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 74 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 72 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GWF_2147832138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GWF!MTB"
        threat_id = "2147832138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 4d 8f 0f b6 55 8f a1 ?? ?? ?? ?? 03 45 84 0f be 08 33 ca 8b 15 ?? ?? ?? ?? 03 55 84 88 0a e9 15 ff ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJZ_2147834522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJZ!MTB"
        threat_id = "2147834522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 1c 10 d3 ea 8b 4d c4 8d 45 e0 89 55 e0 e8 ?? ?? ?? ?? 8b 45 e0 33 c3 31 45 f8 89 35 ?? ?? ?? ?? 8b 45 f4 89 45 e4 8b 45 f8 29 45 e4 8b 45 e4 89 45 f4 81 45 ?? 47 86 c8 61 ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJZ_2147834522_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJZ!MTB"
        threat_id = "2147834522"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9 ?? 8d 3c 2e c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKD_2147834697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKD!MTB"
        threat_id = "2147834697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c7 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {8b ec 51 51 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 56 c6 05 ?? ?? ?? ?? 69 c6 05 ?? ?? ?? ?? 72 c6 05 ?? ?? ?? ?? 50 c6 05 ?? ?? ?? ?? 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKL_2147834890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKL!MTB"
        threat_id = "2147834890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 83 e0 03 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c3 83 e0 03 8a 80 ?? ?? ?? ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 72}  //weight: 10, accuracy: Low
        $x_1_3 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-32] 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Smokeloader_GKM_2147834929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKM!MTB"
        threat_id = "2147834929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 f8 03 45 f4 89 45 0c 8b 4d e0 83 0d ?? ?? ?? ?? ?? ?? c3 c1 e8 05 03 45 ec 03 f1 33 f0 33 75 0c c7 05 ?? ?? ?? ?? 19 36 6b ff 89 75 fc 8b 45 fc 29 45 08 81 3d ?? ?? ?? ?? 93 00 00 00 74}  //weight: 10, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKQ_2147835050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKQ!MTB"
        threat_id = "2147835050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 05 03 45 ?? 03 f3 33 c6 33 45 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 29 45 ?? 81 3d ?? ?? ?? ?? 93 00 00 00 74 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 8b 45 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKT_2147835258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKT!MTB"
        threat_id = "2147835258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 55 d8 8b 45 d8 3b 05 ?? ?? ?? ?? 73 ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 d8 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d d8 88 01 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKX_2147835423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKX!MTB"
        threat_id = "2147835423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 dc 89 45 f8 33 c7 31 45 fc 8b 45 f0 89 45 e4 8b 45 fc 29 45 e4 8b 45 e4 89 45 f0 8b 45 c4 29 45 f4 ff 4d d8 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKV_2147835707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKV!MTB"
        threat_id = "2147835707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 55 f8 0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 4d f8 88 01 eb b7 33 00 0f b6 0d ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GTP_2147836216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GTP!MTB"
        threat_id = "2147836216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c3 c1 e0 ?? 03 c6 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 03 f3 33 75 ?? 8d 45 ?? 50 89 75 ?? e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_GAB_2147836348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAB!MTB"
        threat_id = "2147836348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 72 74 c7 05 ?? ?? ?? ?? 6f 74 65 63 c7 05 ?? ?? ?? ?? 75 61 6c 50 c6 05 ?? ?? ?? ?? 72 66 c7 05 ?? ?? ?? ?? 74 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GAB_2147836348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAB!MTB"
        threat_id = "2147836348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c6 c1 e0 04 03 c7 33 45 ?? 89 45 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? ff 75 ?? 8d 45 ?? 50 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ID_2147838195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ID!MTB"
        threat_id = "2147838195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c3 2b f0 8b 45 ?? 01 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ID_2147838195_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ID!MTB"
        threat_id = "2147838195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 8b 4d ?? 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 2b 4d ?? 8d 45 ?? 89 4d ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CZ_2147839715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CZ!MTB"
        threat_id = "2147839715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8a 4d ?? 03 c3 30 08 83 7d ?? 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CZ_2147839715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CZ!MTB"
        threat_id = "2147839715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 8b 4d ?? 89 45 ?? 8d 45 fc e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CZ_2147839715_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CZ!MTB"
        threat_id = "2147839715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d3 ea 8b 4c 24 34 8d 44 24 28 c7 05 [0-4] ee 3d ea f4 89 54 24 28 e8 [0-4] 8b 44 24 20 31 44 24 10 81 3d [0-4] e6 09 00 00 75 08 56 56 ff 15 [0-4] 8b 44 24 10 31 44 24 28 8b 44 24 28 83 44 24 18 64 29 44 24 18 83 6c 24 18 64 83 3d [0-4] 0c 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GFQ_2147842696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GFQ!MTB"
        threat_id = "2147842696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 03 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 2b f8 89 44 24 ?? 8d 44 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 83 eb ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHA_2147843578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHA!MTB"
        threat_id = "2147843578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 44 24 ?? 33 44 24 ?? 33 c8 51 8b c6 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? 47 86 c8 61 83 6c 24 ?? ?? 8b f0 89 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHC_2147843797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHC!MTB"
        threat_id = "2147843797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a3 5e b0 38 c7 44 24 ?? 46 30 42 6c c7 44 24 ?? 08 00 9b 44 c7 44 24 ?? b9 b1 c2 45 c7 44 24 ?? 2c eb 0e 7c c7 44 24 ?? 3d 1c 36 22 c7 44 24 ?? c2 9e 83 44 c7 44 24 ?? ee 2b d8 59 c7 44 24 ?? 5d b4 9b 4c c7 44 24 ?? 8c 86 28 22 c7 44 24 ?? 48 a2 2c 39 c7 44 24 ?? aa 93 62 7c c7 44 24 ?? ec a7 c6 42 c7 44 24 ?? 95 9f 4d 2e c7 44 24 ?? b0 1d 78 4c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHG_2147844052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHG!MTB"
        threat_id = "2147844052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHG_2147844052_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHG!MTB"
        threat_id = "2147844052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 2b d9 8b c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHJ_2147844173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHJ!MTB"
        threat_id = "2147844173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c3 33 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b c6 c1 e8 ?? 03 c5 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHK_2147844262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHK!MTB"
        threat_id = "2147844262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d3 ee 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 74 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 2b f9 8b c7 8d 4c 24 ?? 89 7c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHM_2147844418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHM!MTB"
        threat_id = "2147844418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? 47 86 c8 61 83 ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHM_2147844418_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHM!MTB"
        threat_id = "2147844418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 83 ea ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHL_2147844420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHL!MTB"
        threat_id = "2147844420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 e2 ?? 03 54 24 ?? 8d 0c 07 c1 e8 ?? 89 54 24 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHN_2147844631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHN!MTB"
        threat_id = "2147844631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 2b f9 83 6c 24 ?? ?? 89 4c 24 ?? 89 7c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHN_2147844631_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHN!MTB"
        threat_id = "2147844631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? 47 86 c8 61 83 6c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHO_2147844785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHO!MTB"
        threat_id = "2147844785"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 03 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ba 05 00 00 89 44 24 ?? c7 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHQ_2147845296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHQ!MTB"
        threat_id = "2147845296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 06 c1 e8 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 31 44 24 ?? 81 3d ?? ?? ?? ?? ba 05 00 00 89 44 24 ?? 89 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHS_2147845373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHS!MTB"
        threat_id = "2147845373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c5 8d 0c 37 31 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 47 86 c8 61 4b 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHT_2147845500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHT!MTB"
        threat_id = "2147845500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 c5 03 fe 31 7c 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GHV_2147845722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GHV!MTB"
        threat_id = "2147845722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce c1 e9 ?? 03 cb 8b 44 24 ?? 31 44 24 ?? 8b 54 24 ?? 52 51 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 ed}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GIE_2147846464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GIE!MTB"
        threat_id = "2147846464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 c1 ea 05 03 ce c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GIF_2147846582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GIF!MTB"
        threat_id = "2147846582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 64 89 45 c4 83 6d ?? 64 8b 45 bc 8a 4d ?? 03 c7 30 08 83 fb 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GIF_2147846582_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GIF!MTB"
        threat_id = "2147846582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 0c 2f 31 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 74 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJA_2147846634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJA!MTB"
        threat_id = "2147846634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cb 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 51 52 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 83 ed ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJD_2147846836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJD!MTB"
        threat_id = "2147846836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 de 31 5c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJE_2147846922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJE!MTB"
        threat_id = "2147846922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {9d 69 2b 38 c7 84 24 ?? ?? ?? ?? 9b 17 ec 41 c7 84 24 ?? ?? ?? ?? 81 6f 30 16 c7 84 24 ?? ?? ?? ?? 5c 0b e9 11 c7 84 24 ?? ?? ?? ?? 2c dc 00 48 c7 44 24 ?? 31 64 01 50 c7 44 24 ?? 24 04 8b 41 c7 84 24 ?? ?? ?? ?? 06 51 bf 3e c7 44 24 ?? 4a b5 04 32 c7 84 24 ?? ?? ?? ?? 74 4c 89 41}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJF_2147846994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJF!MTB"
        threat_id = "2147846994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 33 c1 2b f8 89 44 24 ?? 8b c7 c1 e0 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c7 c1 e8 ?? 8d 34 3b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJG_2147847255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJG!MTB"
        threat_id = "2147847255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 c1 e8 ?? 8d 34 2b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {33 c6 33 c1 2b d8 89 44 24 ?? 8b c3 c1 e0 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJH_2147847332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJH!MTB"
        threat_id = "2147847332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 33 c1 2b f8 89 44 24 ?? 8b c7 c1 e0 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 10, accuracy: Low
        $x_10_2 = {8b cf c1 e9 ?? 03 f7 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJI_2147847357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJI!MTB"
        threat_id = "2147847357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 f7 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 4c 24 ?? 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 31 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 5c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJJ_2147847454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJJ!MTB"
        threat_id = "2147847454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 c1 ea ?? 8d 3c 33 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
        $x_10_2 = {33 cf 33 c1 2b e8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJJ_2147847454_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJJ!MTB"
        threat_id = "2147847454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {46 ed d3 2b 81 84 24 ?? ?? ?? ?? dc 08 20 39 81 6c 24 ?? 00 d3 54 57 81 6c 24 ?? 9b 3c e4 2c 81 6c 24 ?? 20 1d 72 30 81 6c 24 ?? 22 08 cd 2c 81 44 24 ?? d8 8e 04 41 81 6c 24 ?? 12 93 56 0c 81 44 24 ?? a5 74 dd 47 b8 6e 7e 7a 1b f7 64 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJJ_2147847454_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJJ!MTB"
        threat_id = "2147847454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {35 46 1e 40 81 84 24 ?? ?? ?? ?? 2e fb 9c 53 81 84 24 ?? ?? ?? ?? 7f 94 a3 3b 81 ac 24 ?? ?? ?? ?? 3f b2 4a 59 81 ac 24 ?? ?? ?? ?? ab 60 1f 5e 81 ac 24 ?? ?? ?? ?? 25 d9 82 22 81 84 24 ?? ?? ?? ?? 6b da 4b 2f 81 84 24 ?? ?? ?? ?? 25 36 fd 7a 81 6c 24 ?? ec 66 9a 3f b8 a4 9b 8a 28 f7 a4 24}  //weight: 10, accuracy: Low
        $x_10_2 = {35 46 1e 40 81 44 24 ?? 2e fb 9c 53 81 84 24 ?? ?? ?? ?? 7f 94 a3 3b 81 6c 24 ?? 3f b2 4a 59 81 ac 24 ?? ?? ?? ?? ab 60 1f 5e 81 ac 24 ?? ?? ?? ?? 25 d9 82 22 81 44 24 ?? 6b da 4b 2f 81 84 24 ?? ?? ?? ?? 25 36 fd 7a 81 ac 24 ?? ?? ?? ?? ec 66 9a 3f b8 a4 9b 8a 28 f7 a4 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_GJK_2147848082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJK!MTB"
        threat_id = "2147848082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 d3 ea 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 54 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJL_2147848210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJL!MTB"
        threat_id = "2147848210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d7 33 c2 89 44 24 ?? 2b d8 8b 44 24 ?? 29 44 24 ?? ff 4c 24}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c6 c1 e8 ?? 03 fe c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJM_2147848356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJM!MTB"
        threat_id = "2147848356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 d3 ea 8b 4c 24 ?? 8d 04 37 89 44 24 ?? 8d 44 24 ?? 89 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJN_2147848429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJN!MTB"
        threat_id = "2147848429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
        $x_10_2 = {33 cf 33 c1 2b e8 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJO_2147848493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJO!MTB"
        threat_id = "2147848493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 8b 4c 24 ?? 03 d6 89 54 24 ?? 89 44 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJS_2147848737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJS!MTB"
        threat_id = "2147848737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d7 33 c2 2b d8 81 f9 ?? ?? ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {8b ce c1 e9 ?? 8d 3c 2e c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJT_2147848968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJT!MTB"
        threat_id = "2147848968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 3c 2e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJT_2147848968_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJT!MTB"
        threat_id = "2147848968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d6 31 54 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 15}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c7 c1 e8 ?? 8d 34 3b c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GJW_2147849241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GJW!MTB"
        threat_id = "2147849241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9 ?? 8d 3c 33 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GKA_2147849394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GKA!MTB"
        threat_id = "2147849394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 cb 33 c1 2b e8 81 c7 ?? ?? ?? ?? ff 4c 24 18}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 1c 37 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CRXM_2147850004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CRXM!MTB"
        threat_id = "2147850004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 8d 0c 2f 33 c1 2b f0 8b d6 c1 e2}  //weight: 1, accuracy: High
        $x_1_2 = {33 cb 33 c1 2b f8 a1 ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBFN_2147850171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBFN!MTB"
        threat_id = "2147850171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 55 f8 88 55 ff 0f b6 45 ff 05 ?? ?? ?? ?? 88 45 ff 0f b6 4d ff f7 d9 88 4d ff 0f b6 55 ff 83 c2 6b 88 55 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 4d ff f7 d1 88 4d ff 0f b6 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "BLFOIOCQIOWVJAISHJIAJIHX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNA_2147850654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNA!MTB"
        threat_id = "2147850654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d7 d3 ea 8d 04 3b 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 89 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNA_2147850654_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNA!MTB"
        threat_id = "2147850654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 33 d3 ee 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNA_2147850654_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNA!MTB"
        threat_id = "2147850654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d6 d3 ee 8b cd 8d 44 24 ?? 89 54 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNA_2147850654_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNA!MTB"
        threat_id = "2147850654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 d4 ec 26 b8 ?? ?? ?? ?? f7 64 24 ?? 8b 44 24 ?? 81 6c 24 ?? 46 47 2e 63 81 44 24 ?? d0 50 3e 7e 81 6c 24 ?? 74 f6 20 40 81 44 24 ?? 6d 8d f3 1b 81 44 24 ?? 1a 8d 4c 3c 81 6c 24 ?? a7 1e 7a 2c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNE_2147850663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNE!MTB"
        threat_id = "2147850663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 ?? 03 44 24 ?? 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 de 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNF_2147850666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNF!MTB"
        threat_id = "2147850666"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 8d 4c 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 01 5c 24 ?? 8d 34 17 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 31 74 24 ?? 81 3d ?? ?? ?? ?? 21 01 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNG_2147850669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNG!MTB"
        threat_id = "2147850669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 d3 ea 03 c6 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNG_2147850669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNG!MTB"
        threat_id = "2147850669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d3 33 c2 8d 14 0f 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 03 fe 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNJ_2147851148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNJ!MTB"
        threat_id = "2147851148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 14 37 d3 ee 8b 4c 24 ?? 8d 44 24 ?? 89 54 24 ?? 89 74 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNL_2147851254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNL!MTB"
        threat_id = "2147851254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d7 31 54 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 3d ?? ?? ?? ?? 81 ff}  //weight: 10, accuracy: Low
        $x_10_2 = {03 d5 33 c2 03 cb 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNP_2147851627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNP!MTB"
        threat_id = "2147851627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d5 33 c2 03 cf 33 c1 2b f0 8b d6 c1 e2 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 1c 37}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNR_2147851901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNR!MTB"
        threat_id = "2147851901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d5 33 c2 8b 54 24 ?? 03 d1 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0}  //weight: 10, accuracy: Low
        $x_10_2 = {8b d6 c1 ea ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNR_2147851901_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNR!MTB"
        threat_id = "2147851901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 03 44 24 ?? 03 d5 33 c2 8b 54 24 ?? 03 d1 33 c2 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 1d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 7c 24 ?? 03 fe 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNQ_2147852279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNQ!MTB"
        threat_id = "2147852279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 44 24 ?? 89 2d ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 ce 33 c1 2b f8 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNW_2147852726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNW!MTB"
        threat_id = "2147852726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 14 c1 e8 05 03 44 24 34 81 3d ?? ?? ?? ?? 79 09 00 00 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 20}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNW_2147852726_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNW!MTB"
        threat_id = "2147852726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 3e 89 45 ?? 8b c7 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNW_2147852726_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNW!MTB"
        threat_id = "2147852726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 03 89 4d ?? 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 8b c8 8b 45 ?? 31 45 ?? 33 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNZ_2147852906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNZ!MTB"
        threat_id = "2147852906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 8a 89 88 c7 45 ?? 8f 8e 8d 8c 66 c7 45 ?? ?? ?? 8a 44 0d c0 34 bb 88 44 0d 80 41 83 f9 3e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMA_2147853068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMA!MTB"
        threat_id = "2147853068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f3 d3 ee 8d 04 1f 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMB_2147853174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMB!MTB"
        threat_id = "2147853174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f7 d3 ee 03 c7 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMC_2147853336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMC!MTB"
        threat_id = "2147853336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea ?? 03 54 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 d1 8b 4c 24 ?? 03 c8 33 d1 2b fa 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMD_2147853494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMD!MTB"
        threat_id = "2147853494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea ?? 03 54 24 ?? 03 c6 33 d1 33 d0 2b fa 8b cf c1 e1 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GME_2147888187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GME!MTB"
        threat_id = "2147888187"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea ?? 03 54 24 ?? 03 cd 33 d1 8b 4c 24 ?? 03 c8 33 d1 2b fa 8b d7 c1 e2 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMF_2147888452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMF!MTB"
        threat_id = "2147888452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d0 c1 ea ?? 03 54 24 ?? 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 4c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBIK_2147889297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBIK!MTB"
        threat_id = "2147889297"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 2b c8 8a 10 ff 4d 10 88 14 01 40 83 7d 10 00 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "Dijirobebager wezisisoxewana domese" ascii //weight: 1
        $x_1_3 = "Texosikuhon fipuzec" ascii //weight: 1
        $x_1_4 = "cicokirafinibirozatuwaj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMH_2147891195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMH!MTB"
        threat_id = "2147891195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f3 33 f0 2b fe 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 5c 24 ?? 8b 0d ?? ?? ?? ?? 03 df 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBIX_2147891259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBIX!MTB"
        threat_id = "2147891259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kegewivi wihosiwoboyude zerenobavasaxop vimoyotefen gor rot diwexow bevuxumicixe wovexecisi telakih" wide //weight: 1
        $x_1_2 = "Suzowebo gusidelor jalelogikot nufivulohexuf" wide //weight: 1
        $x_1_3 = "jVivobizihosuxa vigigazapegud ficucafoximu lizikafirepijoz xejij timehi hujosu gegobareyixil" wide //weight: 1
        $x_1_4 = "Fopok xekufisi rejafigoyovol focutube coh ruvegame jey lojativ zihadixobayufu" wide //weight: 1
        $x_1_5 = "Doleriyi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBIZ_2147891260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBIZ!MTB"
        threat_id = "2147891260"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 de 33 d8 2b fb 8b d7 c1 e2 04 89 54 24 14 8b 44 24 2c 01 44 24 14}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 6f 00 72 00 75 00 78 00 75 00 74 00 61 00 67 00 65 00 62 00 75 00 62 00 20 00 78 00 75 00 67 00 69 00 68 00 69 00 66 00 65 00 68 00 75 00 66 00 75 00 77 00 75 00 20 00 6d 00 61 00 6e 00 65 00 74 00 61 00 78 00 6f 00 73 00 65 00 72 00 20 00 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMG_2147891489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMG!MTB"
        threat_id = "2147891489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 d3 ef 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d ?? 8b 45 ?? 31 45 ?? 33 7d ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBJB_2147891636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBJB!MTB"
        threat_id = "2147891636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 24 b8 d1 05 00 00 01 04 24 8b 04 24 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 33 c9 8d 54 24 14 66 89 44 24 04 89 44 24 06 89 44 24 0a}  //weight: 1, accuracy: High
        $x_1_3 = {65 00 66 00 69 00 74 00 6f 00 74 00 69 00 20 00 6d 00 61 00 78 00 61 00 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMJ_2147891737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMJ!MTB"
        threat_id = "2147891737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 c1 ea 05 03 54 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 33 d3 31 54 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 c7 ?? ?? ?? ?? ff 4c 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMK_2147891843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMK!MTB"
        threat_id = "2147891843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {32 98 72 16 98 7b 3e 8a fd 01 bb 32 01 ad b6 7b}  //weight: 10, accuracy: High
        $x_10_2 = {08 3c de 8a e3 00 32 15 e7 84 f0 7e 04 5e 78}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMK_2147891843_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMK!MTB"
        threat_id = "2147891843"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 8b 55 ?? d3 e8 03 d7 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 c2 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GPAA_2147891962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GPAA!MTB"
        threat_id = "2147891962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 df 33 d8 2b f3 8b d6 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMO_2147892231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMO!MTB"
        threat_id = "2147892231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 d3 ee 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 33 75 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMP_2147892432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMP!MTB"
        threat_id = "2147892432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 89 4d ?? 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 ?? 8b c8 8b 45 ?? 31 45 ?? 33 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMQ_2147892521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMQ!MTB"
        threat_id = "2147892521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce c1 e9 ?? 03 cd 33 cf 31 4c 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMQ_2147892521_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMQ!MTB"
        threat_id = "2147892521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d3 d3 ea 03 c3 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBJV_2147893011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBJV!MTB"
        threat_id = "2147893011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 ff d3 80 04 3e ?? ff d3 80 04 3e ?? 46 3b 74 24 ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {ff d3 80 04 3e ?? ff d3 80 34 3e ?? ff d3 80 04 3e ?? ff d3 80 2c 3e ?? ff d3 80 04 3e ?? 46 3b 74 24 ?? 0f}  //weight: 1, accuracy: Low
        $x_4_3 = {46 72 69 65 68 69 55 54 59 75 61 69 00 00 00 00 44 55 73 75 64 67 64 67 65 75 64 75 77}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Smokeloader_AMBA_2147893054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBA!MTB"
        threat_id = "2147893054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 cc 33 45 ec 33 c8 2b f1 83 6d e0 ?? 89 4d fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBA_2147893054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBA!MTB"
        threat_id = "2147893054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f4 8b 7d f0 8b d6 d3 ea 8d 04 37 89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 dc 8b 45 ec 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 ec}  //weight: 5, accuracy: Low
        $x_5_2 = {c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 75 f8 8b 4d f4 8d 04 37 31 45 fc d3 ee 03 75 d0 81 3d ?? ?? ?? ?? 21 01 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBA_2147893054_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBA!MTB"
        threat_id = "2147893054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 44 24 30 8b cf c1 e1 04 03 4c 24 2c 8d 14 2f 33 c1 33 c2 2b d8 8b c3 c1 e0 04 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 14 8b 44 24 24 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 04 2b 33 f0 8b 44 24 14 33 c6 2b f8 81 c5 ?? ?? ?? ?? ff 4c 24 1c 89 44 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMR_2147893123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMR!MTB"
        threat_id = "2147893123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 c1 e8 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? 19 36 6b ff 33 c3 31 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 81 c7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMT_2147893156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMT!MTB"
        threat_id = "2147893156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 1f d3 eb 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 5d ?? 8b 45 ?? 31 45 ?? 33 5d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PABI_2147893351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PABI!MTB"
        threat_id = "2147893351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 3c 8d 87 ?? ?? ?? ?? 56 81 f1 6c 06 00 00 51 50 8b 44 24 34 05 d2 fe ff ff 35 dd 02 00 00 50 8d 83 76 fd ff ff 50 e8 ?? ?? ?? ?? 83 c4 14 81 ?? ?? ?? ?? 00 78 c6 00 00 77 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCDK_2147895023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCDK!MTB"
        threat_id = "2147895023"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ca 89 44 24 ?? 89 4c 24 ?? 89 35 ?? ?? ?? ?? 8b 44 24 ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 ?? 89 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 89 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNT_2147895032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNT!MTB"
        threat_id = "2147895032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 f5 33 c6 2b f8 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 89 44 24}  //weight: 10, accuracy: Low
        $x_10_2 = {8b c7 c1 e8 ?? 03 44 24 ?? 8d 14 3b 33 ca 89 44 24 ?? 89 4c 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCDO_2147895119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCDO!MTB"
        threat_id = "2147895119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 04 2f 33 f0 8b 44 24 ?? 33 c6 2b d8 81 c5 ?? ?? ?? ?? ff 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_RH_2147895655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.RH!MTB"
        threat_id = "2147895655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 6a 58 20 c7 [0-5] 3c 46 ae 28 c7 85 ?? ?? ?? ?? 78 f4 32 3b c7 85 ?? ?? ?? ?? c4 9f 3a 07 c7 [0-5] f4 9c fa 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_XU_2147896107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.XU!MTB"
        threat_id = "2147896107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 ff d3 e8 ?? ?? ?? ?? 8b 4d ?? 30 04 0e 46 3b f7 ?? ?? 5b 5f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEC_2147896739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEC!MTB"
        threat_id = "2147896739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 8b c8 8b 45 ?? 31 45 ?? 33 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 03 c7 33 c2 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MB_2147896787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MB!MTB"
        threat_id = "2147896787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 14 8b 4c 24 10 c1 e8 05 03 44 24 34 33 cb c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 18 89 4c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10 81 c7 47 86 c8 61 4d 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCED_2147896850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCED!MTB"
        threat_id = "2147896850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 55}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e8 8d 3c 13 81 c3 ?? ?? ?? ?? 03 45 ?? 33 c7 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMZ_2147896952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMZ!MTB"
        threat_id = "2147896952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d6 d3 ea 8d 04 33 89 45 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMZ_2147896952_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMZ!MTB"
        threat_id = "2147896952"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Pev nefukululepedey" ascii //weight: 1
        $x_1_2 = "tipivagocimowiya" ascii //weight: 1
        $x_1_3 = "xafecelocixupapedahesofunezodicexegenogexepumawojuyagon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEG_2147897061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEG!MTB"
        threat_id = "2147897061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 d3 ef 8d 14 03 31 55 ?? 03 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f4 31 7d ?? 8b 4d ?? 29 4d ?? 81 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEO_2147897401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEO!MTB"
        threat_id = "2147897401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a a8 b2 27 c7 84 24 ?? ?? ?? ?? 94 5a 88 45 c7 84 24 ?? ?? ?? ?? ff 33 8b 26 c7 84 24 ?? ?? ?? ?? 4d 24 0a 2b c7 84 24 ?? ?? ?? ?? fe f4 15 66 c7 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEP_2147897526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEP!MTB"
        threat_id = "2147897526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 31 45 ?? 33 55}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 fc 8b 7d ?? 8b 4d ?? 8d 04 3b 31 45 fc d3 ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEQ_2147897682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEQ!MTB"
        threat_id = "2147897682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 55 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b ?? 24 ?? 89 6c 24 ?? 8b 44 24 ?? 01 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_FK_2147897715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.FK!MTB"
        threat_id = "2147897715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f4 8b 7d f0 8b d6 d3 ea 8d 04 37 89 45 d8 c7 05 90 a5 a9 02 ee 3d ea f4 03 55 dc 8b 45 d8 31 45 fc 33 55 fc 89 55 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCEV_2147897889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCEV!MTB"
        threat_id = "2147897889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 d3 ea 8d 04 1f 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 55 ?? 8b 45 ?? 31 45 ?? 33 55 ?? 89 55 ?? 8b 45 ?? 83 45 ?? ?? 29 45 ?? 83 6d ?? ?? 83 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e8 03 fa 03 45 ?? 33 c7 31 45 ?? 2b 5d ?? 8d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_RF_2147898325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.RF!MTB"
        threat_id = "2147898325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 84 24 1c 02 00 00 56 b5 8b 2c c7 84 24 64 01 00 00 e1 c3 9c 0c c7 84 24 5c 01 00 00 94 27 73 51 c7 84 24 58 01 00 00 65 48 6d 5a c7 84 24 f0 01 00 00 9f 3a 12 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBI_2147898382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBI!MTB"
        threat_id = "2147898382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 31 45 fc 33 55 fc 89 55 ec 8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 83 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCFC_2147898654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCFC!MTB"
        threat_id = "2147898654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 89 74 24 ?? 89 3d ?? ?? ?? ?? 8b 44 24 ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 ?? 89 7c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 89 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 4c 24 ?? 8b c1 c1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAB_2147898711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAB!MTB"
        threat_id = "2147898711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 f4 8b 4d f8 8b f2 d3 ee 8d 04 13 31 45 fc 03 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GAD_2147898866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAD!MTB"
        threat_id = "2147898866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 c5 47 86 c8 61 ff 4c 24 ?? 0f 85 ?? ?? ?? ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBD_2147898907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBD!MTB"
        threat_id = "2147898907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 55 dc 8b 45 f0 31 45 fc 33 55 fc 89 55 f0 8b 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBD_2147898907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBD!MTB"
        threat_id = "2147898907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 40 01 44 24 24 8b 44 24 14 33 44 24 24 89 44 24 24 8b 54 24 24 89 54 24 24 8b 44 24 24 29 44 24 1c 8b 4c 24 1c 8b 74 24 18 8b c1 c1 e0 04 03 44 24 48 03 f1 81 3d ?? ?? ?? ?? be 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCFH_2147898968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCFH!MTB"
        threat_id = "2147898968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 33 c6 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 c3 ?? ?? ?? ?? ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMBF_2147899663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMBF!MTB"
        threat_id = "2147899663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tupeyatoz kakezufor" ascii //weight: 1
        $x_1_2 = "Jehes pucedayuriki" ascii //weight: 1
        $x_1_3 = "Bezematevaneri fedilovewe" ascii //weight: 1
        $x_1_4 = "zihogofaxexoruhecedec" ascii //weight: 1
        $x_1_5 = "kahokivezav" ascii //weight: 1
        $x_1_6 = "wilebudugarurave" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Smokeloader_GAM_2147899713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAM!MTB"
        threat_id = "2147899713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 0c 3b 89 4d ?? 8b 4d ?? 8b f7 d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GAN_2147899868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAN!MTB"
        threat_id = "2147899868"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "loyusotonofasuba" ascii //weight: 2
        $x_2_2 = "jokediteroviwedarafinayog" ascii //weight: 2
        $x_2_3 = "jowuharatapiyilijadezumadayeduje" ascii //weight: 2
        $x_2_4 = "bikoveholajijovizijilumefu" ascii //weight: 2
        $x_2_5 = "jiriyamuwez" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_RA_2147900078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.RA!MTB"
        threat_id = "2147900078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe cd 65 84 00 75 0f a1 ?? ?? ?? 00 05 31 a2 00 00 a3 ?? ?? ?? 00 81 3d ?? ?? ?? 00 41 01 00 00 75 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPX_2147900191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPX!MTB"
        threat_id = "2147900191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 d6 d3 ee 89 55 ec c7 05 70 04 84 00 ee 3d ea f4 03 75 e0 8b 45 ec 31 45 fc 33 75 fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAC_2147900197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAC!MTB"
        threat_id = "2147900197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 75 dc 8b 45 ec 31 45 fc 33 75 fc 89 75 d8 8b 45 d8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPXY_2147900321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPXY!MTB"
        threat_id = "2147900321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c2 d3 e8 8b 4d fc 03 45 dc 33 45 ec 33 c8 8d 45 e8 89 4d fc 2b f1 e8 ?? ?? ?? ?? 83 eb 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPXZ_2147900328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPXZ!MTB"
        threat_id = "2147900328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sakezuwejowawezuhawujagad" wide //weight: 1
        $x_1_2 = "Punacodatupo mab jilizutixe" wide //weight: 1
        $x_1_3 = "varixoyayusifunibubusolahacifoza" wide //weight: 1
        $x_1_4 = "cayucuxamukujowitusojujuni suyinovosiwohibipivetayodubemera nujenowelijexolecuwima lugos" wide //weight: 1
        $x_1_5 = "DilufivoENijexuji bipuficef porilokacovorej simuludu bayuza pidom gizemayisofa!Favewohefu citepu sizecoc zawemoy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCGR_2147900757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCGR!MTB"
        threat_id = "2147900757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 14 8b 4c 24 10 30 04 0a 83 7d 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAD_2147900904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAD!MTB"
        threat_id = "2147900904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "letebovula jin" ascii //weight: 1
        $x_1_2 = "Fewixetomonelo" ascii //weight: 1
        $x_1_3 = "zezoteko" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPDM_2147900936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPDM!MTB"
        threat_id = "2147900936"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "menogec zezahas wotehuvobefukik jovovebuxadutobewehisayexofo muserilefekaj" wide //weight: 1
        $x_1_2 = "deyuhiboxowi wocitaxahutexodezura dutuxo" wide //weight: 1
        $x_1_3 = "fuwozivezojafi ribixaxilukenutim nuhorabinexekobutakiraredereje" wide //weight: 1
        $x_1_4 = "sevihonofahekusedejonulik gabofugupetigedacegacopuxaciy zegamefu" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPXD_2147901085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPXD!MTB"
        threat_id = "2147901085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 14 30 04 0e 83 7c 24 18 0f 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZA_2147901330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZA!MTB"
        threat_id = "2147901330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 04 33 83 ff 0f 75 ?? 6a 00 8d 44 24 0c 50 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7}  //weight: 10, accuracy: Low
        $x_10_2 = {30 04 33 83 ff 0f 75 ?? 6a 00 8d 44 24 0c 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 46 3b f7 7c ?? 5d 5e 83 ff 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_SPJJ_2147901935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPJJ!MTB"
        threat_id = "2147901935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 45 e8 8b 45 e8 33 d0 89 45 fc 89 55 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d 08 30 04 ?? 83 ff 0f 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 d2 85 ff ?? ?? e8 ?? ?? ?? ?? 30 04 32 42 3b d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 30 08 83 ff ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 ff d5 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 33 46 3b f7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 69 c6 05 ?? ?? ?? ?? 2e c7 05 ?? ?? ?? ?? 6d 67 33 32 c7 05 ?? ?? ?? ?? 64 6c 6c 00 a2 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZZ_2147902062_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZZ!MTB"
        threat_id = "2147902062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c2 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 83 65 ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZD_2147902264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZD!MTB"
        threat_id = "2147902264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b 00 65 00 c7 05 ?? ?? ?? ?? 72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 66 a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZD_2147902264_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZD!MTB"
        threat_id = "2147902264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 d2 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZF_2147902379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZF!MTB"
        threat_id = "2147902379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 52 51 a3 ?? ?? ?? ?? ff d0 81 c4}  //weight: 5, accuracy: Low
        $x_5_2 = {73 69 c6 05 ?? ?? ?? ?? 2e c7 05 ?? ?? ?? ?? 6d 67 33 32 c7 05 ?? ?? ?? ?? 64 6c 6c 00 a2 ?? ?? ?? ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZF_2147902379_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZF!MTB"
        threat_id = "2147902379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 3b 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 d2 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 89 55 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 33 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZE_2147902469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZE!MTB"
        threat_id = "2147902469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {65 00 72 00 c7 05 ?? ?? ?? ?? 6e 00 65 00 c7 05 ?? ?? ?? ?? 6c 00 33 00 c7 05 ?? ?? ?? ?? 32 00 2e 00 c7 05 ?? ?? ?? ?? 64 00 6c 00 c7 05 ?? ?? ?? ?? 6c 00 00 00 66 a3 ?? ?? ?? ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPGS_2147902518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPGS!MTB"
        threat_id = "2147902518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 45 f0 8b 45 f0 33 c2 2b f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GPX_2147902633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GPX!MTB"
        threat_id = "2147902633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {30 04 1e 83 ff 0f 75 08}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXA_2147902931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXA!MTB"
        threat_id = "2147902931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c8 89 4d ?? 8b 4d ?? d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 c3 50 59 8b 45 ?? 31 45 ?? 33 4d ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXZ_2147903166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXZ!MTB"
        threat_id = "2147903166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 04 33 83 ff 0f 75 ?? ff 15 ?? ?? ?? ?? 46 3b f7 7c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXZ_2147903166_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXZ!MTB"
        threat_id = "2147903166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 14 30 83 ff 0f ?? ?? 6a 00 6a 00 53 8d 44 24 ?? 50 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXZ_2147903166_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXZ!MTB"
        threat_id = "2147903166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 c7 05 ?? ?? ?? ?? 6b 00 65 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXZ_2147903166_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXZ!MTB"
        threat_id = "2147903166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 6e 00 c7 05 ?? ?? ?? ?? 65 00 6c 00 c7 05 ?? ?? ?? ?? 33 00 32 00 c7 05 ?? ?? ?? ?? 2e 00 64 00 c7 05 ?? ?? ?? ?? 6c 00 6c 00 66 89 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6b 00 65 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPZJ_2147903226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPZJ!MTB"
        threat_id = "2147903226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 04 24 f0 43 03 00 83 04 24 0d a1 ?? ?? ?? ?? 0f af 04 24 81 3d ?? ?? ?? ?? 9e 13 00 00 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPXH_2147903760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPXH!MTB"
        threat_id = "2147903760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 e8 31 45 f0 8b 45 f0 31 45 f8 2b 75 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CCHU_2147904532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CCHU!MTB"
        threat_id = "2147904532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 89 45 e8 89 7d ec 8b 45 e8 89 45 ec 8b 45 f8 31 45 ec 8b 45 ec 89 45 fc 8b 45 fc 29 45 f4 81 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPFD_2147904684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPFD!MTB"
        threat_id = "2147904684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 dc 31 45 f0 8b 45 e8 33 45 f0 2b d8 89 45 e8 8b c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPDD_2147905229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPDD!MTB"
        threat_id = "2147905229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 8d d4 fb ff ff 30 04 31 83 ff 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_Y_2147905652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.Y!MTB"
        threat_id = "2147905652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f0 33 45 ?? 31 45 ?? 8b 45 fc 29 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_Y_2147905652_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.Y!MTB"
        threat_id = "2147905652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 8b 45 ?? 01 45 f8 8b 45 f8 31 45 ec 8b 4d f0 8b 45 ec 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_RP_2147906356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.RP!MTB"
        threat_id = "2147906356"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 30 83 ff 0f 75}  //weight: 1, accuracy: Low
        $x_1_2 = "xohelocajaxekehave" ascii //weight: 1
        $x_1_3 = "fipelidivukaluvijahevavuzuke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GAC_2147906458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAC!MTB"
        threat_id = "2147906458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 33 83 ff 0f 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GAZ_2147906963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GAZ!MTB"
        threat_id = "2147906963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 30 83 7c 24 ?? 0f ?? ?? 6a 00 6a 00 6a 00 ff d3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 44 24 10 69 c9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 30 83 ?? 24 ?? ?? ?? ?? 0f ?? ?? 6a 00 6a 00 6a 00 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_GZX_2147907257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZX!MTB"
        threat_id = "2147907257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 8b c7 d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 55 ?? 8d 04 3e 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GMN_2147907455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GMN!MTB"
        threat_id = "2147907455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 69 72 74 c7 05 ?? ?? ?? ?? 6f 74 65 63 c7 05 ?? ?? ?? ?? 75 61 6c 50 c6 05 ?? ?? ?? ?? 72 66 c7 05 ?? ?? ?? ?? 74 00 c7 45 ?? 20 00 00 00 83 45 ?? 20 8d 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_Z_2147908226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.Z!MTB"
        threat_id = "2147908226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e8 03 d7 89 45 f8 8b 45 d8 01 45 f8 8b 45 f8 8d 4d f0 33 c2 8b 55 f4 33 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PADR_2147908263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PADR!MTB"
        threat_id = "2147908263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d ?? ?? ?? ?? 8a 15 ?? ?? ?? ?? 30 14 1e 83 ff 0f 75}  //weight: 1, accuracy: Low
        $x_1_2 = {46 3b f7 7c ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PADR_2147908263_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PADR!MTB"
        threat_id = "2147908263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 c1 e0 04 89 45 f4 8b 45 e0 01 45 f4 8b 4d ec 8b c7 8b 55 fc d3 e8 03 d7 89 45 f8 8b 45 d8 01 45 f8 8b 45 f8 8d 4d f0 33 c2 8b 55 f4 33 d0 89 55 f4}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f0 c1 e8 05 89 45 f8 8b 55 f4 33 db 8b 45 f8 33 d1 03 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNB_2147908588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNB!MTB"
        threat_id = "2147908588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 65 f4 8b 45 f4}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 20 00 00 00 83 45 fc 20 8d 45 f8 50 ff 75 fc}  //weight: 1, accuracy: High
        $x_1_3 = {83 65 fc 00 81 45 fc 00 00 00 00 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNC_2147908591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNC!MTB"
        threat_id = "2147908591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d fc 5f 33 cd 33 c0 5e 06 00 ff 15}  //weight: 5, accuracy: Low
        $x_5_2 = {8d 95 ec fb ff ff 52 50 50 66 89 85 ec fb ff ff 89 85 ee fb ff ff 89 85 f2 fb ff ff 89 85 f6 fb ff ff 66 89 85 fa fb ff ff}  //weight: 5, accuracy: High
        $x_5_3 = {55 8b ec 81 ec ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 c5 89 45 fc 56 57}  //weight: 5, accuracy: Low
        $x_1_4 = {25 73 20 25 63 00 00 [0-9] 6d 73 69 6d 67 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {25 73 20 25 63 00 [0-9] 6d 00 73 00 69 00 6d 00 67 00 33 00 32 00 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 31 a2 00 00 01 44 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Smokeloader_AMMH_2147908999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMMH!MTB"
        threat_id = "2147908999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 24 08 30 0c 1e 83 ff 0f 75 ?? 55 55 55 e8 ?? ?? ?? ?? 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXN_2147909129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXN!MTB"
        threat_id = "2147909129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 04 2a 89 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 4c 24 ?? 8b 44 24 ?? 33 4c 24 ?? 03 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXN_2147909129_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXN!MTB"
        threat_id = "2147909129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c7 89 45 ?? 8b 45 ?? c1 e8 ?? 89 45 ?? 8b 4d ?? 33 4d ?? 8b 45 ?? 03 45 ?? 8b 55 ?? 33 c1 89 4d ?? 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 ?? 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNF_2147909700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNF!MTB"
        threat_id = "2147909700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 75 f0 81 45 f0 00 00 00 00 8b 45 f0}  //weight: 1, accuracy: High
        $x_1_2 = {d3 ea 03 d3 8b ?? ?? 31 45 ?? 31 55 ?? 2b 7d fc 81 45 ?? ?? ?? ?? ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {3d a9 0f 00 00 [0-96] 83 45 ?? 64 29 45 01 83 6d 01 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_HNH_2147909725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNH!MTB"
        threat_id = "2147909725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 8e ea 1e c7 45 ?? a7 a1 63 15 c7 45}  //weight: 1, accuracy: Low
        $x_1_2 = "msimg32.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZY_2147909777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZY!MTB"
        threat_id = "2147909777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 45 f8 8b 45 e0 01 45 f8 8b 45 f8 33 45 f4 31 45 fc 8b 45 fc 29 45 e8 8b 4d d4 81 c7 ?? ?? ?? ?? 89 7d f0 4e 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMAA_2147909976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMAA!MTB"
        threat_id = "2147909976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 30 83 ff 0f 75 [0-30] 6a 00 6a 00 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNG_2147910195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNG!MTB"
        threat_id = "2147910195"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 38 71 20 00 c0 00 [0-185] b8 ?? ?? ?? ?? f7 [0-3] 8b [0-32] b8 ?? ?? ?? ?? f7 [0-3] 8b [0-32] b8 ?? ?? ?? ?? f7 [0-3] 8b [0-48] 33 ?? 81 3d ?? ?? ?? ?? 00 04 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNI_2147910243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNI!MTB"
        threat_id = "2147910243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d a4 24 00 00 00 00 8b 15 ?? ?? ?? ?? 89 54 24 10 b8 ?? ?? 00 00 01 44 24 10 8b 44 24 10 8a 0c 30 8b 15 ?? ?? ?? ?? 88 0c 32 81 3d [0-8] 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPHT_2147910483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPHT!MTB"
        threat_id = "2147910483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c1 e8 05 89 45 f8 8b 4d fc 33 4d f0 8b 45 f8 03 45 cc 33 c1 89 4d fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNE_2147910485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNE!MTB"
        threat_id = "2147910485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ee 3d ea f4 (89|8b) a0 00 [0-160] 02 00 00 00 83 [0-3] 03 [0-32] c1 e0 04 [0-48] 89 [0-96] 8b [0-48] c7 05 ?? ?? ?? ?? ee 3d ea f4 [0-176] c1 e0 04 [0-64] d3 e8 [0-48] 8b [0-48] 8b [0-48] 02 01 01 0f e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HNE_2147910485_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HNE!MTB"
        threat_id = "2147910485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f0 8b 4d d8 03 4d f0 8a 09 88 08 81}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 00 00 6b 00 65 00 72 00 6e 00 65 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00 00 00 20 25 73 20 25 64 20 25 66 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {03 55 e4 8b 45 f0 31 45 fc 33 55 fc}  //weight: 1, accuracy: High
        $x_1_4 = {29 45 f4 83 6d f4 04 00 83 45 f4 ?? 29 45 f4 83 6d f4 01}  //weight: 1, accuracy: Low
        $x_1_5 = {8b d7 d3 ea 8d 04 3b 89 45 ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Smokeloader_GPAE_2147910722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GPAE!MTB"
        threat_id = "2147910722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 cc 33 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPZB_2147911339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPZB!MTB"
        threat_id = "2147911339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {89 45 f8 8b 45 f8 03 45 e0 33 45 e4 33 45 fc 2b d8 89 45 f8 8b c3 c7 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GXY_2147911430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GXY!MTB"
        threat_id = "2147911430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 0c 1e 83 ff 0f ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 6a 00 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZZ_2147911540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZZ!MTB"
        threat_id = "2147911540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_VOO_2147911811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.VOO!MTB"
        threat_id = "2147911811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 14 8b 4c 24 10 33 ed 8b 44 24 14 33 4c 24 18 03 44 24 2c 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 4c 24 10 89 44 24 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_YZ_2147912030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.YZ!MTB"
        threat_id = "2147912030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f8 83 c0 ?? 89 45 ?? 83 6d ?? ?? 8b 45 ?? 8a 4d ?? 03 c6 30 08 83 fb ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPMB_2147912713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPMB!MTB"
        threat_id = "2147912713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b 55 0c 7c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SMMB_2147913589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SMMB!MTB"
        threat_id = "2147913589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e8 05 89 45 6c 8b 45 6c 31 4d 74 03 c3 33 45 74 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 83 3d ?? ?? ?? ?? 0c 89 45 6c 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAE_2147914078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAE!MTB"
        threat_id = "2147914078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 c1 e8 ?? 03 cb 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b f3 c1 e6 ?? 03 b5 ?? ?? ?? ?? 33 f1 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNU_2147914103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNU!MTB"
        threat_id = "2147914103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 ce 8b 85 ?? ?? ?? ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 03 85 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 33 c3 2b f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GND_2147914228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GND!MTB"
        threat_id = "2147914228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 f8 30 04 3b 83 7d 08 0f 59 ?? ?? 56 ff 15 ?? ?? ?? ?? 56 56}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMAI_2147914453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMAI!MTB"
        threat_id = "2147914453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 8b c6 c1 e8 05 03 ce 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b c6 c1 e0 04 03 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? c7 45 ?? ?? ?? ?? ?? 33 c1 2b f8 89 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPNN_2147914517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPNN!MTB"
        threat_id = "2147914517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4d f8 89 7d f8 e8 ?? ?? ?? ?? 8a 45 f8 30 04 33 83 7d 08 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GQZ_2147914797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GQZ!MTB"
        threat_id = "2147914797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 cb 8b 85 ?? ?? ?? ?? c1 e8 ?? 89 45 ?? 8b 45 ?? 03 85 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c1 8b 4d ?? 33 c7 2b f0 8b c6 c1 e8 ?? 03 ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPXV_2147915531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPXV!MTB"
        threat_id = "2147915531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c1 8b 4d 70 33 c7 2b f0 8b c6 c1 e8 05 89 b5 7c fe ff ff 03 ce 89 45 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZM_2147915756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZM!MTB"
        threat_id = "2147915756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 c6 30 08 83 ff 0f ?? ?? 53 53 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PAFB_2147915866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PAFB!MTB"
        threat_id = "2147915866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 7c 8b 8d 78 fe ff ff 5f 5e 89 18 89 48 04}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 70 8b 45 70 8b 95 80 fe ff ff 03 c7 03 d3 33 c2 33 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SHJJ_2147915934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SHJJ!MTB"
        threat_id = "2147915934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b f3 c1 e6 04 03 b5 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 0c}  //weight: 5, accuracy: Low
        $x_4_2 = {03 d7 33 c2 33 c1 2b d8 8b c3 c1 e8 05 c7 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMAO_2147916073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMAO!MTB"
        threat_id = "2147916073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 3b 33 c2 33 c1 29 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? c1 e8 05 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8b b5 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? c1 e6 04 03 b5 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GZN_2147916366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GZN!MTB"
        threat_id = "2147916366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 b0 83 c0 01 89 45 b0 83 7d b0 0d ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 0f b6 11 81 f2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 b0 88 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AMAQ_2147916453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AMAQ!MTB"
        threat_id = "2147916453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e6 04 03 b5 ?? ?? ?? ?? 03 c3 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75 [0-20] 33 c6 2b f8 89 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNN_2147916574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNN!MTB"
        threat_id = "2147916574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 08 8a 4d fc 03 c2 30 08 42 3b d6}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAF_2147917014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAF!MTB"
        threat_id = "2147917014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d6 33 c2 33 c1 2b f8 83 3d ?? ?? ?? ?? ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SCMB_2147917131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SCMB!MTB"
        threat_id = "2147917131"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b c7 c1 e0 04 03 45 d8 03 d7 33 c2 33 45 fc 2b f0 ff 4d ec 89 75 f0 0f 85}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_FFZ_2147917276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.FFZ!MTB"
        threat_id = "2147917276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 ea 05 8d 0c 18 89 55 f8 8b 45 e4 01 45 f8 8b f3 c1 e6 04 03 75 dc 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_FFZ_2147917276_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.FFZ!MTB"
        threat_id = "2147917276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e8 05 89 45 fc 8b 45 fc 03 45 e4 8b 55 f8 03 d6 33 c2 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 fc 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SZ_2147917345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SZ!MTB"
        threat_id = "2147917345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 59 8a 4d ?? 03 c7 30 08 83 7d ?? 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AAZ_2147917424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AAZ!MTB"
        threat_id = "2147917424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {50 e8 c9 ff ff ff 8b 45 08 59 8a 4d fc 03 c6 30 08 83 fb 0f 75 10 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 46 3b f3 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AAT_2147917521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AAT!MTB"
        threat_id = "2147917521"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 c1 e0 04 03 45 dc 8d 1c 0e 33 c3 33 45 ?? 81 c6 47 86 c8 61 2b d0 ff 4d f0 89 55 f4 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HEZ_2147917701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HEZ!MTB"
        threat_id = "2147917701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c1 c1 e8 05 89 45 ?? 8b 45 e0 01 45 ?? 8b c1 c1 e0 04 03 45 dc 33 45 f8 33 45 e4 2b d0 89 55 f0 8b 45 d8 29 45 fc ff 4d ec 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HHZ_2147917825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HHZ!MTB"
        threat_id = "2147917825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8d b5 f4 fb ff ff 89 bd f4 fb ff ff e8 ?? ?? ?? ?? 8b 8d f8 fb ff ff 8b 85 f0 fb ff ff 8b 75 0c 03 c1 8a 8d f4 fb ff ff 30 08 83 fe 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_HTZ_2147917858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.HTZ!MTB"
        threat_id = "2147917858"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b f8 8b c7 c1 e8 05 03 d7 89 45 f8 8b 45 dc 01 45 f8 8b f7 c1 e6 04 03 75 d8 33 f2 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_NZE_2147918077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.NZE!MTB"
        threat_id = "2147918077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 d7 8b 45 f0 c1 e8 05 89 45 f8 8b 45 f8 03 45 e4 33 f6 33 c2 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GNX_2147918132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GNX!MTB"
        threat_id = "2147918132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 d6 33 c2 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_NEE_2147918298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.NEE!MTB"
        threat_id = "2147918298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8d b5 f4 fb ff ff 89 bd f4 fb ff ff e8 ?? ?? ?? ?? 8b 85 f8 fb ff ff 8a 8d f4 fb ff ff 03 c3 30 08 83 7d 0c 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PAFC_2147918308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PAFC!MTB"
        threat_id = "2147918308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 7c 8b 8d 78 fe ff ff 5f 5e 89 18 89 48 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MEE_2147918395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MEE!MTB"
        threat_id = "2147918395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b c3 c1 e8 05 89 45 fc 8b 45 dc 01 45 fc 8b 4d f8 03 4d f0 c1 e3 04 03 5d d8 33 d9 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MAA_2147918526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MAA!MTB"
        threat_id = "2147918526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8d b5 f8 fb ff ff 89 9d f8 fb ff ff e8 ?? ?? ?? ?? 8b 85 f4 fb ff ff 8a 8d f8 fb ff ff 03 c7 30 08 83 7d 0c 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SPDB_2147918628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SPDB!MTB"
        threat_id = "2147918628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e8 05 89 45 f8 8b 45 d8 01 45 f8 8b 4d f4 03 4d ec c1 e3 04 03 5d d4 33 d9 81 3d ?? ?? ?? ?? 03 0b 00 00 75 11 56 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_REW_2147918741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.REW!MTB"
        threat_id = "2147918741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 3b 47 3b 7d 08 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CBB_2147918870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CBB!MTB"
        threat_id = "2147918870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 03 c7 30 08 47 3b fb 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_VDZ_2147919001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.VDZ!MTB"
        threat_id = "2147919001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 03 c7 30 08 47 3b 7d 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MRR_2147919513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MRR!MTB"
        threat_id = "2147919513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 14 07 8b 44 24 1c c1 e8 05 89 44 24 14 8b 44 24 14 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 14 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_CZS_2147920029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.CZS!MTB"
        threat_id = "2147920029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 d0 8b 44 24 18 c1 e8 05 89 44 24 14 8b 44 24 14 33 ca 03 c5 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24 14 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GBZ_2147921676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GBZ!MTB"
        threat_id = "2147921676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 04 37 6a 00 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a 00 ff 15 ?? ?? ?? ?? 46 3b f3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GTN_2147921678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GTN!MTB"
        threat_id = "2147921678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b f9 c1 e7 ?? 03 7d ?? 8d 04 0b 33 f8 81 3d ?? ?? ?? ?? 03 0b 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_RKB_2147921720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.RKB!MTB"
        threat_id = "2147921720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 c7 04 24 b6 e4 fa 1b 81 24 24 ae 8e db 1e 81 04 24 50 b4 bd 7f c1 24 24 07 81 34 24 bb 6a 5c 23}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KNO_2147921727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KNO!MTB"
        threat_id = "2147921727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e8 05 89 45 f8 8b 45 f8 03 45 d4 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KIZ_2147921730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KIZ!MTB"
        threat_id = "2147921730"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ff ff 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 38 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZZY_2147921737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZZY!MTB"
        threat_id = "2147921737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 49 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 8b 75 0c 30 14 38 83 fe 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MUM_2147922336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MUM!MTB"
        threat_id = "2147922336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f0 03 4d f8 8b 45 f0 c1 e8 05 89 45 f4 8b 45 f4 03 45 d0 33 d9 33 c3 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f4 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_TSM_2147922510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.TSM!MTB"
        threat_id = "2147922510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 f0 c1 e8 05 89 45 f4 8b 45 f4 03 45 dc 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f4 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAG_2147922748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAG!MTB"
        threat_id = "2147922748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 ?? 03 45 ?? 03 d1 33 c2 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SGOB_2147922995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SGOB!MTB"
        threat_id = "2147922995"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 45 f4 c1 e8 05 89 45 f8 8b 45 f8 03 45 d4 33 f1 33 c6 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_BKC_2147923017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.BKC!MTB"
        threat_id = "2147923017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d1 c1 ea 05 89 55 ?? 8b 45 e0 01 45 ?? 8b 45 ec 8b f1 c1 e6 04 03 75 d8 03 c1 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_GOB_2147923089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.GOB!MTB"
        threat_id = "2147923089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e8 05 89 45 f8 8b 45 f8 03 45 d4 33 f9 33 c7 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 f8 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MGV_2147923388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MGV!MTB"
        threat_id = "2147923388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 eb 07 8d a4 24 00 00 00 00 8d b5 ?? ?? ff ff c7 85 ?? ?? ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 ?? ?? ff ff 8b 85 ?? ?? ff ff 30 14 38 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_YIO_2147923574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.YIO!MTB"
        threat_id = "2147923574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 69 c9 94 0b 00 00 f7 7c 24 28 8b 54 24 24 30 0a 8b 74 24 34 03 f2 0f af c1 69 c0 ?? ?? ?? ?? 01 44 24 18 ff 44 24 18 8b c1 0f af 44 24 18 83 c0 48 99 f7 fe 29 44 24 1c 3b 4c 24 18 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_AIN_2147923695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.AIN!MTB"
        threat_id = "2147923695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d7 c1 ea 05 89 55 f8 8b 45 e0 01 45 f8 8b 45 e8 8b 4d ec c1 e7 04 03 7d d8 03 c8 33 f9 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZAZ_2147924046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZAZ!MTB"
        threat_id = "2147924046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8d a4 24 00 00 00 00 8d 74 24 10 c7 44 24 0c 05 00 00 00 c7 44 24 10 00 00 00 00 e8 ?? ?? ?? ?? 8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c ?? 8a 4c 24 0c 30 0c 2f 83 fb 0f 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZAT_2147924091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZAT!MTB"
        threat_id = "2147924091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d7 c1 ea 05 03 cf 89 55 ?? 8b 45 e0 01 45 ?? c1 e7 04 03 7d dc 33 f9 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KAH_2147924325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KAH!MTB"
        threat_id = "2147924325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 06 75 04 a9 ?? ?? ?? ?? 30 75 ?? 74 03 f7 be ?? ?? ?? ?? 84 29 c0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_JOZ_2147924436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.JOZ!MTB"
        threat_id = "2147924436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 10 83 c0 46 89 44 24 0c 83 6c 24 0c ?? 8a 4c 24 0c 30 0c 2f 83 fb 0f 75 37 6a 00 6a 00 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_JAZ_2147924515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.JAZ!MTB"
        threat_id = "2147924515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 ea 05 03 cb 89 55 f8 8b 45 d4 01 45 f8 8b f3 c1 e6 04 03 75 e0 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SFSB_2147925017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SFSB!MTB"
        threat_id = "2147925017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f be 04 2f 89 44 24 0c 8b 44 24 10 31 44 24 0c 8a 4c 24 0c 88 0c 2f 83 fb 0f 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_WXD_2147925271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.WXD!MTB"
        threat_id = "2147925271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d7 c1 e2 04 03 55 ?? 33 55 ?? 33 d1 89 55 ?? 8b 45 ?? 29 45 f4 8b 45 e8 29 45 f8 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SVCB_2147925658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SVCB!MTB"
        threat_id = "2147925658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 2c 24 46 0f be 04 32 89 44 24 ?? 8b 04 24 31 44 24 ?? 8a 4c 24 ?? 88 0c 32 42 3b d7 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZSZ_2147928802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZSZ!MTB"
        threat_id = "2147928802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 6c 24 10 3c 8a 44 24 10 30 04 2f 83 fb 0f 75 ?? 8b 4c 24 0c 51 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_TFZ_2147928931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.TFZ!MTB"
        threat_id = "2147928931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d1 c1 ea 05 89 55 f8 8b 45 e4 01 45 f8 8b f1 c1 e6 04 03 75 ?? 8d 04 0b 33 f0 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_MBV_2147929406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.MBV!MTB"
        threat_id = "2147929406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 1a 89 45 fc 8b 45 ?? 01 45 fc 8b d3 c1 e2 04 03 55 e0 33 55 fc 33 d1 2b fa 89 7d ?? 8b 45 d8 29 45 f8 83 6d ec 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_PBV_2147929407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.PBV!MTB"
        threat_id = "2147929407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 cf 8b 45 f0 c1 e8 05 89 45 fc 8b 55 dc 01 55 fc 33 f1 81 3d ?? ?? ?? ?? e6 09 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SDCF_2147929467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SDCF!MTB"
        threat_id = "2147929467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 cf 8b 45 f0 c1 e8 05 89 45 fc 8b 55 dc 01 55 fc 33 f1 81 3d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_SACF_2147929942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.SACF!MTB"
        threat_id = "2147929942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c0 46 89 44 24 04 83 6c 24 04 0a 90 83 6c 24 04 3c 8a 44 24 04 30 04 37 83 fb 0f 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_LOP_2147930713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.LOP!MTB"
        threat_id = "2147930713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75 06 ff 15 ?? ?? ?? ?? 8b 4d fc 33 ce 2b f9 89 7d f0 8b 45 d8 29 45 f8 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_KKJ_2147931562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.KKJ!MTB"
        threat_id = "2147931562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 ea 05 03 cb 89 55 f8 8b 45 dc 01 45 f8 8b f3 c1 e6 04 03 75 e0 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_ZKZ_2147932057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.ZKZ!MTB"
        threat_id = "2147932057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 0c 83 c0 46 89 44 24 ?? 83 6c 24 14 0a ?? 83 6c 24 ?? 3c 8a 44 24 ?? 30 04 1f 47 3b fd 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_EAVZ_2147939212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.EAVZ!MTB"
        threat_id = "2147939212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 95 14 f7 ff ff 83 c2 04 89 95 14 f7 ff ff 3b 17}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_NEW_2147942085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.NEW!MTB"
        threat_id = "2147942085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 0c 10 30 0c 17 8b 4c 24 28 42 39 d1 75 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Smokeloader_EAPG_2147947300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smokeloader.EAPG!MTB"
        threat_id = "2147947300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smokeloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 14 24 89 4c 24 0c 8b 44 24 0c 31 04 24 8b 04 24 33 44 24 04 83 c4 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

