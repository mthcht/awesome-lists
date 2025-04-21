rule Trojan_Win32_IcedId_PA_2147739826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PA!MTB"
        threat_id = "2147739826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 3b 39 05 ?? ?? ?? ?? 75 40 3b ea 73 1e 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af ca 69 c9 55 69 00 00 66 89 0d ?? ?? ?? ?? eb 07 66 8b 0d ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 76 16 0f b7 05 ?? ?? ?? ?? 29 05 ?? ?? ?? ?? eb 07 66 8b 0d ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 56 5e 04 00 75 02 2b f5 81 c7 a0 c9 ce 01 89 3b ba 02 00 00 00 39 35 ?? ?? ?? ?? 76 06 29 15 ?? ?? ?? ?? 8b 44 24 14 83 c3 04 83 6c 24 10 01 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 2a 83 c1 fa 03 cf a3 ?? ?? ?? 00 0f b7 c1 05 eb 00 00 00 66 89 0d ?? ?? ?? 00 3d 21 1b 00 00 7e ?? 8b 0d ?? ?? ?? 00 69 c7 58 18 00 00 2b c8 8d 0c 4b 66 89 0d ?? ?? ?? 00 0f b7 c1 81 c5 ac 00 56 01 05 eb 00 00 00 89 2a 3d 21 1b 00 00 7e ?? 8b 0d ?? ?? ?? 00 8b c1 2b c6 83 e8 1d 69 c0 58 18 00 00 2b c8 8d 0c 4b 66 89 0d ?? ?? ?? 00 a1 ?? ?? ?? 00 83 c2 04 2b 05 ?? ?? ?? 00 83 c0 06 89 54 24 18 ff 4c 24 1c 0f b7 f8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_PB_2147745018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PB!MTB"
        threat_id = "2147745018"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b d8 7f 51 8b 07 8b 78 0c 8b 48 14 2b f9 8d 4d ?? 51 ff d6 8b 4d ?? 83 c3 05 8b 51 0c 2b 51 14 66 0f b6 04 10 66 99 66 f7 fb 8d 45 ?? 50 66 8b da ff d6 8a 0c 38 32 d9 8d 4d ?? 51 ff d6 8b 4d ?? 88 1c 38 8b 7d 08 b8 01 00 00 00 03 c8 89 4d ?? 8b d9 eb 05 00 b8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_PC_2147748466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PC!MTB"
        threat_id = "2147748466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b c3 03 f9 05 ?? ?? ?? ?? 81 ff ?? ?? 00 00 75 08 8d 74 29 ?? 8d 4c 01 ?? 8b 54 24 10 8b 5c 24 14 03 c6 03 c8 a1 ?? ?? ?? ?? 8d 84 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 38 8b d1 2b d5 81 c2 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 0f bd ?? ?? ?? ?? 2b e9 8b cd 8b 2d ?? ?? ?? ?? 83 44 24 10 04 81 c7 dc 6b ee 01 89 38 8b c1 8b 0d ?? ?? ?? ?? 2b c2 83 c0 09 81 7c 24 10 ?? ?? 00 00 a3 ?? ?? ?? ?? 8d 4c 01 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_PVS_2147748658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PVS!MTB"
        threat_id = "2147748658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5c 24 24 69 c5 83 e5 00 00 66 03 c8 8b 02 05 2c 5a 16 01 66 89 0d ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 2b df 89 02}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 44 0f 03 8a d0 80 e2 fc c0 e2 04 0a 54 0f 01 88 55 ff 8a d0 24 f0 c0 e0 02 0a 04 0f c0 e2 06 0a 54 0f 02 88 04 1e}  //weight: 2, accuracy: High
        $x_2_3 = {8b 4d fc 8b 55 cc 8b 04 8a 33 05 24 70 44 00 8b 4d fc 8b 55 cc 89 04 8a}  //weight: 2, accuracy: High
        $x_2_4 = {81 c2 f0 a5 f7 01 89 15 ?? ?? ?? ?? 89 94 1e e9 fc ff ff 8b 35 ?? ?? ?? ?? ba 04 00 00 00 03 da 81 fb 07 04 00 00 89 15 06 00 8b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_VSK_2147749240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.VSK!MTB"
        threat_id = "2147749240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 46 00 41 81 f0 a0 00 00 00 8b fa 81 e9 51 6b 4f 00 81 c7 32 64 00 00 41 81 c1 4e 42 00 00 89 43 00}  //weight: 2, accuracy: High
        $x_2_2 = {8b 44 24 30 8b 4c 24 58 0f af 4c 24 30 8d 04 85 1f 01 00 00 0f af 44 24 10 2b c8 0f af 4c 24 58 6a 48 58 2b c1 01 44 24 30}  //weight: 2, accuracy: High
        $x_2_3 = {8b 44 24 24 2a ca 83 44 24 10 04 8d 14 19 2c 45 f6 d9 02 d0 81 c7 2c b0 15 01 8a c2 89 7d 00}  //weight: 2, accuracy: High
        $x_2_4 = {8b 55 ec 31 ca c6 45 eb 16 89 55 ec 8b 4d e4 8b 55 f4 8a 65 eb 8a 1c 0a 28 e0 88 45 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_PVD_2147750142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PVD!MTB"
        threat_id = "2147750142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b7 c3 89 2d ?? ?? ?? ?? 8b e8 2b ee 8d 34 29 81 c2 b4 33 da 01 8d 0c c0 2b 0d ?? ?? ?? ?? 89 17 07 00 8b 17 a3}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 9c 24 df 03 00 00 88 a4 24 7f 01 00 00 c7 84 24 ec 00 00 00 00 00 00 00 c7 84 24 e8 00 00 00 46 3e 00 00 80 f3 16 c6 84 24 97 01 00 00 94 88 9c 24 0f 01 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DHA_2147757153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DHA!MTB"
        threat_id = "2147757153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 2c 89 85 01 0f b6 94 15 ?? ?? ?? ?? 30 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "RP5dRFB7AqcBcwwqvpbFjlFptqdJq4C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEB_2147757648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEB!MTB"
        threat_id = "2147757648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 33 f6 8d 44 24 10 56 6a 01 5d 55 56 56 50 ff 15 ?? ?? ?? ?? 85 c0 5b 75 36 6a 08 55 56 8d 44 24 18 56 50 ff 15 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "RYxhhug5op5e0nh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEC_2147758831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEC!MTB"
        threat_id = "2147758831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 53 6a 01 53 53 8d 44 24 28 50 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 53 8d 4c 24 28 51 ff 15 00 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DEE_2147758930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEE!MTB"
        threat_id = "2147758930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 53 6a 01 53 53 8d 44 24 28 50 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 53 8d 4c 24 28 51 ff 15 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "hfRuPhzYOiqUHw59w9g68tAN1lVGPBlmYjNKv6HArNKYj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEF_2147759258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEF!MTB"
        threat_id = "2147759258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 8d 44 24 18 53 6a 01 53 53 50 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 8d 4c 24 24 53 51 ff 15 00 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DEG_2147759357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEG!MTB"
        threat_id = "2147759357"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 10 8d 44 24 1c 53 6a 01 53 53 50 ff 15 ?? ?? ?? ?? 85 c0 5e 75 3b 6a 08 6a 01 53 8d 4c 24 24 53 51 ff 15 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "H7Gx9op2JpZ3BwqtjR2PgOcnlo3MsUBimaeBgh3GvPVpLJuZfHAdfOmuvsolHZeEyQQGiE0IhjdNj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEH_2147759822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEH!MTB"
        threat_id = "2147759822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 48 53 6a 01 53 53 8d 4c 24 ?? 51 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 53 8d 54 24 00 52 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "FGDAFGSDSFGSDSFGSDFGGHFDdtydrTFSFGSDAgfsdgfs" ascii //weight: 1
        $x_1_3 = "06WYp4KuV4611XwjqHdiuB1jb0JNhUZLhzUQ6V4M2S6I1gFXpyxE2MQBfJu4iigy" ascii //weight: 1
        $x_1_4 = "qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y" ascii //weight: 1
        $x_1_5 = "k9HlXs5j5MF4nmN" ascii //weight: 1
        $x_1_6 = "eOrSHsbkt5WGM9s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEJ_2147760011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEJ!MTB"
        threat_id = "2147760011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 6a 00 6a 01 6a 00 6a 00 8d 55 ?? 52 ff 15 ?? ?? ?? ?? 85 c0 75 40 6a 08 6a 01 6a 00 6a 00 8d 45 00 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "EeSVHCB8fA84i6E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEK_2147760012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEK!MTB"
        threat_id = "2147760012"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 84 34 ?? ?? ?? ?? 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8d 4c 24 14 83 c5 01 0f b6 94 14 00 30 55 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "onItrOx8cz93ZpykfJlBaYTDZvZYVfHRQjiEB4a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_AB_2147760344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.AB!MTB"
        threat_id = "2147760344"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Warco  leggu" ascii //weight: 3
        $x_3_2 = "LocaleNameToLCID" ascii //weight: 3
        $x_3_3 = "Hair\\Tierange.pdb" ascii //weight: 3
        $x_3_4 = "some\\us\\See\\thank" ascii //weight: 3
        $x_3_5 = "GetEnvironmentVariableW" ascii //weight: 3
        $x_3_6 = "GetTextMetricsW" ascii //weight: 3
        $x_3_7 = "ord6582" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DEM_2147760367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEM!MTB"
        threat_id = "2147760367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 14 6a 00 6a 01 6a 00 6a 00 8d 55 ?? 52 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 6a 00 6a 00 8d 45 00 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DEO_2147760805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEO!MTB"
        threat_id = "2147760805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 50 6a 01 6a 00 6a 00 8d 4d f4 51 ff 15 ?? ?? ?? ?? 85 c0 75 ?? 32 c0 e9 ?? ?? ?? ?? c7 45 d4 00 00 00 00 8d 55 d4 52 6a 00 6a 00 68 34 01 00 00 68 ?? ?? ?? ?? 8b 45 f4 50 ff 15 ?? ?? ?? ?? 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DEP_2147760877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEP!MTB"
        threat_id = "2147760877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 fc 6a 00 6a 01 6a 00 6a 00 50 c7 45 f8 ?? ?? ?? ?? ff d6 85 c0 75 ?? 6a 08 6a 01 50 50 8d 45 fc 50 ff d6 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "0oFW9eeKrWCPUZxEr9i0VuyhowVRpsztR4iBzl3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DEQ_2147760878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DEQ!MTB"
        threat_id = "2147760878"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 00 6a 00 8d 55 ?? 52 ff 15 ?? ?? ?? ?? 85 c0 75 40 6a 08 6a 01 6a 00 6a 00 8d 45 00 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "Xdq7mk5iNSp2eWF" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DAS_2147760976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAS!MTB"
        threat_id = "2147760976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a cb 02 c1 8b 4c 24 18 89 39 8b 7c 24 0c 83 c7 04 89 7c 24 0c 81 ff 07 12 00 00 0f}  //weight: 5, accuracy: High
        $x_1_2 = "Desertpick" ascii //weight: 1
        $x_1_3 = "Runbook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DAS_2147760976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAS!MTB"
        threat_id = "2147760976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 01 53 8d 45 ?? 53 50 89 5d 0c ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 8d 45 00 53 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "Em1O7ccsDHAQEUj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DAT_2147761039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAT!MTB"
        threat_id = "2147761039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 01 53 8d 44 24 ?? 53 50 89 5c 24 ?? ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 8d 4c 24 00 53 51 ff 15 02 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "VVXNHZEfp71kFlGUXv5du60C599rgamSBySsjXA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DAU_2147761046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAU!MTB"
        threat_id = "2147761046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 01 53 53 8d 44 24 ?? 50 89 5c 24 ?? ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 53 8d 4c 24 00 51 ff 15 02 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "jzaWmvU4NxwhOXQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DAZ_2147761198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAZ!MTB"
        threat_id = "2147761198"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 81 c1 ?? ?? ?? ?? 8b f7 2b 35 ?? ?? ?? ?? 83 c6 10 89 08 83 c0 04 83 6c 24 18 01 89 44 24 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DBA_2147761199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBA!MTB"
        threat_id = "2147761199"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b c7 48 0f b7 d8 0f b7 cb 2b 0d ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 2a 83 c2 04 83 6c 24 14 01 8d 74 0e 14 89 54 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DAJ_2147761346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DAJ!MTB"
        threat_id = "2147761346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 14 b0 a9 2a 05 ?? ?? ?? ?? 8b 74 24 10 2a c4 02 c8 89 1d ?? ?? ?? ?? 8b 44 24 28 89 35 ?? ?? ?? ?? 8b 38 81 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DBD_2147761504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBD!MTB"
        threat_id = "2147761504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 00 6a 00 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 3f 6a 08 6a 01 6a 00 6a 00 8d 4d 00 51 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "457867ujhfghdhgdgfdgh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBF_2147761528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBF!MTB"
        threat_id = "2147761528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 d8 7d 11 89 c2 40 f7 da 8a 54 11 ff 88 90 01 04 eb eb}  //weight: 1, accuracy: Low
        $x_1_2 = "Preceding with zeros: %010d" ascii //weight: 1
        $x_2_3 = "$}*tnKEPGFHBLSO" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_IcedId_DBG_2147761612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBG!MTB"
        threat_id = "2147761612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 00 6a 00 8d 55 ?? 52 ff 15 ?? ?? ?? ?? 85 c0 75 3f 6a 08 6a 01 6a 00 6a 00 8d 45 00 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "jH9{P|nWKBpPP%J" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBH_2147761927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBH!MTB"
        threat_id = "2147761927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6a 01 53 53 8d 45 0c 50 89 5d 0c ff d6 85 c0 75 2e 6a 08 6a 01 53 53 8d 45 0c 50 ff d6 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = "wPB6Gy0*CuLienC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBI_2147761935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBI!MTB"
        threat_id = "2147761935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 50 8d 44 24 0c 53 6a 01 53 53 50 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 8d 4c 24 18 53 51 ff 15 00 85 c0 75 25}  //weight: 1, accuracy: Low
        $x_1_2 = "W8mWzWSX6Zvw1mG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBK_2147762001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBK!MTB"
        threat_id = "2147762001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 5d 55 56 56 50 ff 15 ?? ?? ?? ?? 85 c0 5b 75 37 6a 08 55 56 8d 44 24 18 56 50 ff 15 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "OGur1xPpGxsXWcS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBL_2147762002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBL!MTB"
        threat_id = "2147762002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 01 53 53 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 48 6a 08 6a 01 53 53 8d 4c 24 00 51 ff 15 01 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "EcX1EsAduZpJrQGnsGrHl2PsDK5bXR10f6YmuCu0nAUca76MgpN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBO_2147762241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBO!MTB"
        threat_id = "2147762241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "h5Wgm709oTYZKcP" ascii //weight: 1
        $x_1_2 = "Sqy8XSv5KzLZNIyjLZ6dFwAe8I2Ko" ascii //weight: 1
        $x_1_3 = "CwhbgYCTyuFKNbpu6i2p2WSaLh" ascii //weight: 1
        $x_1_4 = "QaAmD?VXwRSRbg3" ascii //weight: 1
        $x_1_5 = "pOAtPRWSOyuRVs8KZRALHcSmY" ascii //weight: 1
        $x_1_6 = "5YO5BoUoiEPnNkg52mpwEAX" ascii //weight: 1
        $x_1_7 = "CJ6dBqnAQZ3P8Y@" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedId_DBR_2147762482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBR!MTB"
        threat_id = "2147762482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 53 6a 01 53 53 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 3d 6a 08 6a 01 53 53 8d 4c 24 00 51 ff 15 01 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DC_2147762489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DC!MTB"
        threat_id = "2147762489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6b c9 21 89 4d dc 8b 55 e4 83 ea 01 89 55 e4}  //weight: 10, accuracy: High
        $x_10_2 = {89 82 45 df ff ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 84 0a 57 7a 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 69 c9 f7 00 00 00 81 f9 45 25 00 00 76 18 8b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DBU_2147762595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBU!MTB"
        threat_id = "2147762595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 6a 01 53 53 8d 44 24 ?? 50 ff 15 ?? ?? ?? ?? 85 c0 75 3f 6a 08 6a 01 53 53 8d 4c 24 00 51 ff 15 01 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DBX_2147762765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DBX!MTB"
        threat_id = "2147762765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 8d 45 ?? 53 6a 01 53 53 50 ff 15 ?? ?? ?? ?? 85 c0 75 36 6a 08 6a 01 53 8d 45 00 53 50 ff 15 01 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DE_2147763880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DE!MTB"
        threat_id = "2147763880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 f7 ff 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 3b ce 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_DH_2147764494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.DH!MTB"
        threat_id = "2147764494"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e5e13930335eca21201cbe7a139e5ba05a1f5f152128b3c6ca8c6ed2f95f965c7f70a2c" ascii //weight: 1
        $x_1_2 = "58f5fe26d5059f8f63ff4d6651f5aaef0a23675b02448c49d2956a8e760443b6459b6730bb4844b51b9f9" ascii //weight: 1
        $x_1_3 = "D$4ZzNf" ascii //weight: 1
        $x_1_4 = "HcD$4" ascii //weight: 1
        $x_1_5 = "oAQM#" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_PK_2147765380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PK!MTB"
        threat_id = "2147765380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 8b f0 33 c9 8b 84 ?? ?? ?? ?? ?? ba ?? ?? ?? ?? f7 e2 03 c7 89 84 ?? ?? ?? ?? ?? 83 d2 00 41 8b fa 3b ce 75}  //weight: 1, accuracy: Low
        $x_1_2 = "thus bal Hit rive Cook Lin" ascii //weight: 1
        $x_1_3 = "\\This\\49\\soldier\\Hope.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_PK_2147765380_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PK!MTB"
        threat_id = "2147765380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c2 2b d8 83 c3 1e 8b 44 24 18 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 38 a1 ?? ?? ?? ?? 8b 7c 24 18 2b c6 03 d0 83 c7 04 ff 4c 24 1c 89 54 24 ?? 89 7c 24 ?? 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Step\\Shoe\\Wave\\pull\\Allow\\condition\\copy.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SC_2147778200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SC!MTB"
        threat_id = "2147778200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 cc 49 3e 22 e8 34 5b e9 [0-5] 03 e2 ff [0-6] 3e cc ff cc e9}  //weight: 10, accuracy: Low
        $x_10_2 = "c:\\Order\\sharp\\Tree\\standFill.pdb" ascii //weight: 10
        $x_1_3 = "icesuit.exe" wide //weight: 1
        $x_10_4 = "IsDebuggerPresent" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SA_2147778337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SA!MTB"
        threat_id = "2147778337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\temp\\foo.txt" ascii //weight: 1
        $x_2_2 = "jl7CvWj8waEAh3eOe3r50kA0ojzhtmSNa3Q2FPzkb8ATgmdJr8" ascii //weight: 2
        $x_1_3 = "Microsoft\\windows\\CurrentVersion\\Explorer\\User Shell Folders" ascii //weight: 1
        $x_1_4 = "tw7TQt9pNstL7Wn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SB_2147778358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SB!MTB"
        threat_id = "2147778358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e:\\48\\Line\\25\\64\\Represent\\green\\Smell\\Excite\\search\\phrase\\48change.pdb" ascii //weight: 1
        $x_1_2 = "f:\\dd\\vctools\\crt\\vcruntime\\src\\internal\\winapi_downlevel.cpp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_EDV_2147783112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.EDV!MTB"
        threat_id = "2147783112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 4d e7 2b c1 0f b6 55 e7 03 d0 88 55 e7}  //weight: 10, accuracy: High
        $x_10_2 = {83 ea 04 33 c0 2b 55 e8 1b 45 ec 88 55 e7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_ACD_2147787530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.ACD!MTB"
        threat_id = "2147787530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "proces artDee" ascii //weight: 3
        $x_3_2 = "Pro shi" ascii //weight: 3
        $x_3_3 = "P@mapan" ascii //weight: 3
        $x_3_4 = "win\\with\\women" ascii //weight: 3
        $x_3_5 = "C:\\WINDOWS\\SYSTEM32" ascii //weight: 3
        $x_3_6 = "FindFirstChangeNotificationA" ascii //weight: 3
        $x_3_7 = "GetWindowThreadProcessId" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBE_2147787623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBE!MTB"
        threat_id = "2147787623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 37 81 fd ?? ?? ?? ?? [0-85] 8b 35 ?? ?? ?? ?? [0-5] 8d bc 2e ?? ?? ?? ?? 8b 37 [0-10] 81 c6 ?? ?? ?? ?? [0-5] 83 c5 04 [0-16] 89 37}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 89 45 ?? [0-240] 8b 75 00 [0-10] ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_QR_2147794962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.QR!MTB"
        threat_id = "2147794962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DleitrevrDlneitrevrPue" ascii //weight: 3
        $x_3_2 = "tpevrSsedevr" ascii //weight: 3
        $x_3_3 = "0SruAKSrpALSrpWKRE3" ascii //weight: 3
        $x_3_4 = "opj_codec_set_threads" ascii //weight: 3
        $x_3_5 = "ResumeServer" ascii //weight: 3
        $x_3_6 = "StartServer" ascii //weight: 3
        $x_3_7 = "StopServer" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_QA_2147796263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.QA!MTB"
        threat_id = "2147796263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 04 24 44 01 d0 83 c0 02 89 04 24 f7 04 24 03 00 00 00 0f 85 17 01 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {b8 6d e3 4c 00 89 04 24 89 44 24 04 f7 04 24 03 00 00 00 74 1e 41 83 f8 0a 0f 9c c2 41 8d 41 ff 41 0f af c1 83 e0 01 0f 94 c1 08 d1 80 f9 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ_2147813155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ!MTB"
        threat_id = "2147813155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FromFall\\wife.pdb" ascii //weight: 1
        $x_1_2 = {89 08 8b c2 [0-10] 81 7c 24 ?? ?? ?? ?? ?? [0-58] 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-5] 03 4c 24 01 [0-10] 89 4c 24 1c 8b 09 [0-37] 81 c1 ?? ?? ?? ?? 83 44 24 ?? 04 [0-16] 8b 44 24 1c 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ1_2147813156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ1!MTB"
        threat_id = "2147813156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Whenboy\\tenkept\\EarlyValue\\could.pdb" ascii //weight: 1
        $x_1_2 = {83 c6 04 8d [0-16] 81 fe ?? ?? ?? ?? [0-58] 8b 15 ?? ?? ?? ?? [0-10] 8b ac 32 ?? ?? ?? ?? [0-90] a1 04 81 c5 ?? ?? ?? ?? [0-10] 89 ac 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ2_2147813157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ2!MTB"
        threat_id = "2147813157"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MillionSummer\\Spring.pdb" ascii //weight: 1
        $x_1_2 = {83 c2 04 89 [0-10] 81 fa ?? ?? ?? ?? [0-42] 8b 1d ?? ?? ?? ?? 8b b4 13 ?? ?? ?? ?? [0-64] 81 c6 f4 49 0a 01 89 b4 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ3_2147813158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ3!MTB"
        threat_id = "2147813158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Oil.dll" ascii //weight: 1
        $x_1_2 = {83 c0 04 89 [0-10] 89 44 24 ?? 3d ?? ?? ?? ?? 73 ?? [0-10] [0-58] 03 2d ?? ?? ?? ?? [0-16] 8b 85 ?? ?? ?? ?? 89 44 24 ?? [0-85] 8b 44 24 0a 05 ?? ?? ?? ?? [0-10] 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ4_2147813797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ4!MTB"
        threat_id = "2147813797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Withexact\\Needsupport\\Before.pdb" ascii //weight: 1
        $x_1_2 = {8b 00 89 44 24 ?? [0-32] 8b 4c 24 ?? 8b 44 24 00 83 44 24 02 04 05 ?? ?? ?? ?? [0-5] 89 01 [0-16] ff 4c 24 ?? [0-122] 8b 44 24 02 [0-10] 8b 00 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ5_2147813798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ5!MTB"
        threat_id = "2147813798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 6f 64 79 [0-5] 57 6f 72 6c 64 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7d 00 a3 [0-58] 81 c7 a4 6f 01 01 89 7d 00 [0-26] 83 c5 04 83 6c 24 ?? 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ5_2147813798_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ5!MTB"
        threat_id = "2147813798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Knew.dll" wide //weight: 1
        $x_1_2 = {57 c7 44 24 ?? ?? ?? ?? ?? [0-139] 7c 24 ?? [0-139] 35 ?? ?? ?? ?? [0-141] bc 3e ?? ?? ?? ?? 8b 37 [0-131] 44 24 03 04 [0-129] c6 8c 48 06 01 81 7c 24 03 ?? ?? ?? ?? [0-137] 37 [0-15] 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBK_2147813799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBK!MTB"
        threat_id = "2147813799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "uwunhkqlzle.dll" ascii //weight: 1
        $x_1_2 = {c1 e5 07 8b 4c 24 ?? c1 e9 ?? 89 f0 89 fe 89 cf ba ?? ?? ?? ?? 31 d7 89 eb 31 d3 41 b8 ?? ?? ?? ?? 44 21 c7 83 e1 ?? 09 f9 89 f7 89 c6 44 21 c3 81 e5 ?? ?? ?? ?? 09 dd 31 cd 45 0f be e9 89 e9 31 d1 b8 ?? ?? ?? ?? 21 c1 bb ?? ?? ?? ?? 21 dd 09 cd 44 89 e9 31 d1 21 c1 41 21 dd 41 09 cd 8b 4c 24 ?? ff c1 48 63 c1 48 03 44 24 ?? 41 31 ed 8b 54 24 ?? ff c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBK_2147813799_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBK!MTB"
        threat_id = "2147813799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 31 48 c1 e2 ?? 48 0b c2 4c 8b c0 33 c9 b8 01 00 00 00 0f a2 89 44 24 ?? 89 5c 24 ?? 89 4c 24 ?? 89 54 24 ?? 0f 31 48 c1 e2 ?? 48 0b c2 49 2b c0 48 03 f8 ff 15 ?? ?? ?? ?? 0f 31 48 c1 e2 ?? 90 48 0b c2 48 8b c8 0f 31 48 c1 e2 ?? 48 0b c2 48 2b c1 48 03 f0 48 83 ed ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c0 4c 8d 0d ?? ?? ?? ?? 49 2b c9 4b 8d 14 08 49 ff c0 8a 42 ?? 32 02 88 44 11 ?? 49 83 f8 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ6_2147815126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ6!MTB"
        threat_id = "2147815126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CountFree\\Teach.pdb" ascii //weight: 1
        $x_1_2 = {83 c5 04 83 [0-5] 81 fd ?? ?? ?? ?? [0-10] [0-80] a1 ?? ?? ?? ?? [0-10] 8b 94 28 ?? ?? ?? ?? [0-74] 81 c2 ?? ?? ?? ?? [0-10] a1 05 89 94 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ7_2147815225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ7!MTB"
        threat_id = "2147815225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "draw.pdb" ascii //weight: 1
        $x_1_2 = {83 c2 04 89 55 ?? 81 7d 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? [0-147] [0-147] 8b 0d ?? ?? ?? ?? 03 4d 00 8b 91 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? [0-112] 8b 0d 09 81 c1 ?? ?? ?? ?? 89 0d 09 8b 15 06 03 55 00 a1 09 89 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ8_2147815226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ8!MTB"
        threat_id = "2147815226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Worldget\\Big.pdb" ascii //weight: 1
        $x_1_2 = {83 c7 04 83 6c 24 ?? 01 [0-10] [0-96] 8b 37 [0-80] 81 c6 ?? ?? ?? ?? [0-10] 89 37 [0-5] 83 c7 04 83 6c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ8_2147815226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ8!MTB"
        threat_id = "2147815226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Familywonder.pdb" ascii //weight: 1
        $x_1_2 = {83 c1 04 89 4d ?? 81 7d 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 60 01 8b 0d ?? ?? ?? ?? 03 4d 00 8b 91 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? e0 02 8b 15 08 81 c2 ?? ?? ?? ?? 89 15 08 a1 05 03 45 00 8b 0d 08 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ9_2147815328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ9!MTB"
        threat_id = "2147815328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Noticeweather\\Observe.pdb" ascii //weight: 1
        $x_1_2 = {89 37 83 c7 04 ff 4c 24 ?? [0-10] [0-64] 8b 37 [0-48] 81 c6 ?? ?? ?? ?? 89 37 83 c7 04 ff 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ9_2147815328_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ9!MTB"
        threat_id = "2147815328"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Tierange.pdb" ascii //weight: 1
        $x_1_2 = {83 c2 04 83 6c 24 ?? 01 89 54 24 ?? [0-16] [0-176] 8b 44 24 01 [0-16] 8b 00 [0-16] 89 44 24 ?? [0-186] 8b 54 24 01 [0-10] 8b 44 24 08 [0-10] 05 60 34 2f 01 [0-10] 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ10_2147815329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ10!MTB"
        threat_id = "2147815329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "AllShop\\Exact.pdb" ascii //weight: 1
        $x_1_2 = {83 c6 04 8b [0-32] 81 fe ?? ?? ?? ?? 73 ?? [0-16] [0-112] a1 ?? ?? ?? ?? [0-16] 8b bc 30 ?? ?? ?? ?? [0-16] a1 06 [0-16] 81 c7 ?? ?? ?? ?? [0-10] 89 bc 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ10_2147815329_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ10!MTB"
        threat_id = "2147815329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MilkPiece.pdb" ascii //weight: 1
        $x_1_2 = {83 c1 04 89 4d ?? 81 7d 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 8a 01 8b 15 ?? ?? ?? ?? 03 55 00 8b 82 ?? ?? ?? ?? a3 ?? ?? ?? ?? [0-220] 8b 0d 08 81 c1 ?? ?? ?? ?? 89 0d 08 8b 15 05 03 55 00 a1 08 89 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ11_2147815330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ11!MTB"
        threat_id = "2147815330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "enter.pdb" ascii //weight: 1
        $x_1_2 = {8b 0f 81 c1 ?? ?? ?? ?? [0-16] 89 0f 83 c7 04 83 6c 24 ?? 01 [0-16] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ11_2147815330_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ11!MTB"
        threat_id = "2147815330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dreamprovide.pdb" ascii //weight: 1
        $x_1_2 = {04 ff 4c 24 ?? [0-10] [0-112] 8b 5c 24 ?? [0-32] 8b 1b [0-58] 8b 44 24 04 81 c3 ?? ?? ?? ?? [0-16] 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ11_2147815330_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ11!MTB"
        threat_id = "2147815330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Colony\\except.pdb" ascii //weight: 1
        $x_1_2 = {83 c1 04 ff 4c 24 ?? 89 4c 24 ?? [0-176] 8b 54 24 01 [0-32] 8b 12 [0-32] 89 54 24 ?? [0-112] 8b 54 24 07 [0-64] 8b 4c 24 01 81 c2 ?? ?? ?? ?? [0-32] 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ12_2147815331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ12!MTB"
        threat_id = "2147815331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "includeblue\\chart.pdb" ascii //weight: 1
        $x_1_2 = {83 c6 04 2c [0-10] 81 fe ?? ?? ?? ?? [0-10] [0-112] 8b 2d ?? ?? ?? ?? [0-32] 8b bc 2e ?? ?? ?? ?? [0-48] 81 c7 ?? ?? ?? ?? [0-16] 89 bc 2e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ12_2147815331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ12!MTB"
        threat_id = "2147815331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Loudmine.pdb" ascii //weight: 1
        $x_1_2 = {03 cd 89 4c 24 ?? 8b 29 [0-48] 8b 4c 24 00 81 c5 ?? ?? ?? ?? [0-16] 89 29 [0-48] 8b 6c 24 ?? [0-16] 83 c5 04 [0-16] 89 6c 24 06 [0-16] 81 fd ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ12_2147815331_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ12!MTB"
        threat_id = "2147815331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "guncorrect.exe" wide //weight: 1
        $x_1_2 = {4d 85 ff 74 ?? b8 ?? ?? ?? ?? [0-10] 8b 15 ?? ?? ?? ?? 8b 8c 02 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-10] 89 8c 02 04 83 c0 04 3d ?? ?? ?? ?? 72 ?? [0-32] 4f [0-16] 73 ?? [0-10] 83 ff ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ13_2147815590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ13!MTB"
        threat_id = "2147815590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "chiefLeg.pdb" ascii //weight: 1
        $x_1_2 = {89 3e 83 c6 04 [0-16] 83 6c 24 ?? 01 89 74 24 ?? [0-96] 8b 54 24 02 8b 3a [0-80] 8b 74 24 02 81 c7 ?? ?? ?? ?? [0-16] 89 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ13_2147815590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ13!MTB"
        threat_id = "2147815590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stood.pdb" ascii //weight: 1
        $x_1_2 = {83 c5 04 0f [0-16] 81 fd ?? ?? ?? ?? 73 ?? [0-16] [0-96] 8b 3d ?? ?? ?? ?? [0-32] 8b b4 2f ?? ?? ?? ?? [0-48] 81 c6 ?? ?? ?? ?? [0-16] 89 b4 ?? ?? ?? ?? [0-16] 83 c5 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ14_2147815993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ14!MTB"
        threat_id = "2147815993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "careMan.pdb" ascii //weight: 1
        $x_1_2 = {83 c2 04 89 55 ?? 81 7d 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 8a 01 8b 15 ?? ?? ?? ?? 03 55 00 8b 82 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 01 8b 15 08 81 c2 ?? ?? ?? ?? 89 15 08 a1 05 03 45 00 8b 0d 08 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ15_2147816067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ15!MTB"
        threat_id = "2147816067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "singlegood.exe" wide //weight: 1
        $x_1_2 = {8b 44 24 10 ?? ?? ?? ?? [0-80] 8b 44 24 10 [0-16] 83 44 24 10 04 81 c7 ?? ?? ?? ?? 89 38 [0-32] ff 4c 24 ?? [0-16] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ16_2147816068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ16!MTB"
        threat_id = "2147816068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "BedTry.pdb" ascii //weight: 1
        $x_1_2 = {83 c1 04 89 4c 24 ?? 81 f9 ?? ?? ?? ?? [0-224] 8b 15 ?? ?? ?? ?? 03 54 24 00 8b 8a ?? ?? ?? ?? [0-32] 81 c1 ?? ?? ?? ?? [0-16] 89 8a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ17_2147816069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ17!MTB"
        threat_id = "2147816069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 4c 8d 05 ?? ?? ?? ?? 80 44 24 ?? ?? c0 64 24 01 ?? 8a 4c 24 01 88 4c 24 ?? 41 8a 4c 50 ?? 88 4c 24 01 80 44 24 01 ?? 8a 4c 24 01 08 4c 24 06 8a 4c 24 ?? 30 4c 24 06 fe 44 24 0d 8a 4c 24 06 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ18_2147816070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ18!MTB"
        threat_id = "2147816070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Happen.pdb" ascii //weight: 1
        $x_1_2 = {83 c7 04 81 ff ?? ?? ?? ?? [0-16] [0-96] 8b 2d ?? ?? ?? ?? [0-32] 8b b4 2f ?? ?? ?? ?? [0-48] 81 c6 d0 10 08 01 89 b4 2f ?? ?? ?? ?? 83 c7 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBJ19_2147816071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBJ19!MTB"
        threat_id = "2147816071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "swim.pdb" ascii //weight: 1
        $x_1_2 = {04 ff 4c 24 ?? [0-16] 8b 15 ?? ?? ?? ?? 89 11 [0-96] 8b 44 24 ?? [0-16] 8b 00 [0-16] a3 02 [0-224] 81 05 02 ?? ?? ?? ?? [0-16] 8b 4c 24 ?? 83 44 24 ?? 04 ff 4c 24 ?? [0-16] 8b 15 02 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBN_2147816498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBN!MTB"
        threat_id = "2147816498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Division.pdb" ascii //weight: 1
        $x_1_2 = {83 c5 04 8b [0-16] 81 fd ?? ?? ?? ?? 73 ?? [0-32] [0-165] 8b 3d ?? ?? ?? ?? [0-10] 8b b4 2f ?? ?? ?? ?? [0-48] 81 c6 ?? ?? ?? ?? [0-32] 89 b4 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBN_2147816498_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBN!MTB"
        threat_id = "2147816498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "keepVoice\\wentlotHair.pdb" ascii //weight: 1
        $x_1_2 = {83 c7 04 0f [0-16] 89 7c 24 ?? [0-16] 83 6c 24 28 01 [0-149] 8b 54 24 01 [0-16] 8b 12 [0-16] 81 c2 ?? ?? ?? ?? [0-16] 89 15 ?? ?? ?? ?? [0-128] 8b 7c 24 01 [0-16] a1 0a [0-16] 89 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBM_2147816499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBM!MTB"
        threat_id = "2147816499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Industry.pdb" ascii //weight: 1
        $x_1_2 = {58 89 44 24 ?? 8b 3b [0-80] 8b 44 24 00 81 c7 ?? ?? ?? ?? 89 3b 83 c3 04 48 [0-16] 89 44 24 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBM3_2147816805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBM3!MTB"
        threat_id = "2147816805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ExperienceExercise" ascii //weight: 1
        $x_1_2 = {83 c2 04 89 55 ?? 81 7d 00 ?? ?? ?? ?? 0f 83 ?? ?? ?? ?? 80 01 8b 0d ?? ?? ?? ?? 03 4d 00 8b 91 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? f0 01 8b 15 08 81 c2 ?? ?? ?? ?? 89 15 08 a1 05 03 45 00 8b 0d 08 89 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBM4_2147816815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBM4!MTB"
        threat_id = "2147816815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Populate" ascii //weight: 1
        $x_1_2 = {83 c5 04 69 [0-16] 81 fd ?? ?? ?? ?? 73 ?? [0-16] [0-128] 8b 15 ?? ?? ?? ?? [0-16] 8b 8c 2a ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? [0-16] 89 8c 2a 08 83 c5 04 [0-16] 81 fd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBM5_2147817100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBM5!MTB"
        threat_id = "2147817100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 02 c1 c9 ?? 80 3a 61 [0-16] 72 ?? 48 03 c8 48 83 e9 ?? eb ?? 48 03 c8 0f b6 44 24 ?? 48 ff c2 66 44 03 c5 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c0 0f b6 0a [0-16] c1 c8 ?? 48 8d 52 01 0f be c9 03 c1 0f b6 0a 84 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_SIBP_2147817101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.SIBP!MTB"
        threat_id = "2147817101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Suggeststep" wide //weight: 1
        $x_1_2 = {04 ff 4c 24 ?? [0-16] [0-176] 8b 54 24 ?? 8b 12 [0-48] 8b 7c 24 ?? 81 c2 ?? ?? ?? ?? 89 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_EC_2147831658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.EC!MTB"
        threat_id = "2147831658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c0 0e 66 89 44 24 30 3a db 74 d9 66 89 44 24 36 b8 1b 00 00 00 e9 1c 01 00 00 48 83 ec 68 48 c7 44 24 20 00 00 00 00 3a d2 74 00 48 c7 44 24 28 00 00 00 00 b8 23 00 00 00 3a ed 74 c2}  //weight: 5, accuracy: High
        $x_1_2 = "fuadsyguasgduhaisudjyuagsdua" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_EC_2147831658_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.EC!MTB"
        threat_id = "2147831658"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "far.dll" ascii //weight: 1
        $x_1_2 = "Desert" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "Fruitblow" ascii //weight: 1
        $x_1_5 = "Whatpiece" ascii //weight: 1
        $x_1_6 = "GetEnvironmentVariableW" ascii //weight: 1
        $x_1_7 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedId_PAB_2147939514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedId.PAB!MTB"
        threat_id = "2147939514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedId"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 0c 50 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

