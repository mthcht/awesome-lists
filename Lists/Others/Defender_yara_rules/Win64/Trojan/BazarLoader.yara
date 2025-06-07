rule Trojan_Win64_BazarLoader_A_2147766797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.A!ibt"
        threat_id = "2147766797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 98 48 03 [0-2] 8b 55 [0-2] 48 63 [0-2] 48 03 [0-2] 0f b6 [0-2] 4c 8b 05 [0-4] 0f b6 [0-2] 4c 01 [0-2] 0f b6 [0-2] 31 ca 88 10 83 45 [0-2] 01 8b 45 [0-2] 3b 45 [0-2] 0f 9c c0 84 c0 0f 85}  //weight: 10, accuracy: Low
        $x_10_2 = {e8 14 a2 00 00 49 8d 44 ?? ?? 49 b9 61 61 61 61 61 61 61 61 49 ba 61 61 61 61 61 61 61 61 49 bb 61 61 61 61 61 61 61 61 48 ba 61 61 61 61 61 61 61 61 48 b9 61 61 61 61 61 61 61 61 4c 89 ?? ?? 45 8d ?? ?? 49 b8 61 61 61 61 61 61 61 61 48 bf 61 61 61 61 61 61 61 61 48 89 10 48 89 ?? ?? 4c 89 ?? ?? 4c 89 ?? ?? 48 63 db 4c 89 ?? ?? 4c 89 ?? ?? 31 d2 48 89 ?? ?? 49 63 c4 31 c9 c6 ?? ?? ?? 00 4d 89 f8 c6 44 1c 20 00 ff 15 71 dc 5e 00 c6 ?? ?? ?? 2d 48 89 c7}  //weight: 10, accuracy: Low
        $x_10_3 = {48 63 d0 48 8b [0-2] 48 01 c2 8b 45 [0-2] 48 63 c8 48 8b 45 [0-2] 48 01 c8 0f b6 08 4c 8b 05 [0-4] 0f b6 45 [0-2] 4c 01 c0 0f b6 00 31 c8 88 02 83 45 [0-2] 01 8b 45 [0-2] 3b 45 [0-2] 0f 8c}  //weight: 10, accuracy: Low
        $x_1_4 = "VirtualAllocExNuma" ascii //weight: 1
        $x_1_5 = "CryptAcquireContextA" ascii //weight: 1
        $x_1_6 = "GetCurrentProcess" ascii //weight: 1
        $x_1_7 = "CreateMutexA" ascii //weight: 1
        $x_1_8 = "C:\\ProgramData\\12345.dll" ascii //weight: 1
        $x_1_9 = "FuckDef" ascii //weight: 1
        $x_1_10 = "memcpy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BazarLoader_D_2147767092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.D!MTB"
        threat_id = "2147767092"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Cannot read remote PEB: %lu" ascii //weight: 5
        $x_5_2 = "Process Doppelganging test!" wide //weight: 5
        $x_5_3 = "Cookie: group=five" ascii //weight: 5
        $x_5_4 = "%s.bazar" ascii //weight: 5
        $x_1_5 = "https://185.65.202.62/" ascii //weight: 1
        $x_1_6 = "https://185.234.72.230/" ascii //weight: 1
        $x_1_7 = "https://146.185.219.101/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BazarLoader_SBB_2147782795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.SBB!MTB"
        threat_id = "2147782795"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 83 ec 48 c7 44 24 30 e4 ff ee 31 45 33 d2 c7 44 24 34 ?? ?? ?? ?? 8b 44 24 30 44 88 54 24 38 8a 44 24 38 84 c0 75}  //weight: 10, accuracy: Low
        $x_3_2 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_3 = "GetKeyboardLayout" ascii //weight: 3
        $x_3_4 = "XwJANiJTYzZDwNq0" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_MZK_2147783109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MZK!MTB"
        threat_id = "2147783109"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 ff c2 c1 c2 [0-1] 4d 03 d1 0f be c9 33 d1 41 ff c0 41 8a 0a 84 c9 75}  //weight: 1, accuracy: Low
        $x_1_2 = {45 33 c9 48 03 cf 45 33 c0 33 d2 e8 [0-4] 41 3b c7 74 [0-1] 48 83 c5 [0-1] 48 83 c6 [0-1] 41 ff c6 44 3b 73 [0-1] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_BazarLoader_MYK_2147783860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MYK!MTB"
        threat_id = "2147783860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 41 8b c1 4d 63 c1 f7 f7 45 88 0c 18 44 8b 15 [0-4] 0f b6 14 32 41 83 c1 01 45 3b ca 43 88 14 18 72}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 63 cf 33 d2 83 c7 01 45 0f b6 04 19 43 0f be 04 19 03 c5 41 03 c0 41 f7 f2 48 63 ea 0f b6 44 1d 00 41 88 04 19 44 88 44 1d 00 44 8b 15 [0-4] 41 3b fa 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_BazarLoader_AF_2147786452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AF!MTB"
        threat_id = "2147786452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 83 ec 58 c7 44 24 40 3f 10 f5 27 45 33 db c7 44 24 44 18 33 94 55 45 8b d1 8b 44 24 40 44 88 5c 24 48 8a 44 24 48 84 c0 75 1b}  //weight: 10, accuracy: High
        $x_3_2 = "StartW" ascii //weight: 3
        $x_3_3 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_4 = "GetTextExtentPoint32A" ascii //weight: 3
        $x_3_5 = "GetCommandLineA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AR_2147787526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AR!MTB"
        threat_id = "2147787526"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {50 c7 44 24 04 00 00 00 00 b8 b0 7a 01 00 48 03 05 23 20 00 00 41 5a 48 ff e0}  //weight: 10, accuracy: High
        $x_3_2 = "MehexdnYbwecgnhgt" ascii //weight: 3
        $x_3_3 = "RwtzucqhGmdtofnpyzac" ascii //weight: 3
        $x_3_4 = "YdtyjlynvqwRnvghjfx" ascii //weight: 3
        $x_3_5 = "ZuqxakwnpZaxbilvhzcpVcikimivf" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DA_2147787600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DA!MTB"
        threat_id = "2147787600"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 1f 41 88 1f 0f b6 5c 4a 01 88 1f 80 07 97 0f b6 1f 41 08 1f 41 0f b6 1c 24 41 30 1f 41 80 04 24 01 41 0f b6 1f 88 1c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AK_2147788055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AK!MTB"
        threat_id = "2147788055"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "nAVcrAbKlMNi.pdb" ascii //weight: 3
        $x_3_2 = "CLUVGHcZGzcNqDERGbgpqLg" ascii //weight: 3
        $x_3_3 = "FGnkJqLIVyDcJmrkBSHUNmLgFmDc" ascii //weight: 3
        $x_3_4 = "StartServer" ascii //weight: 3
        $x_3_5 = "StartW" ascii //weight: 3
        $x_3_6 = "StopServer" ascii //weight: 3
        $x_3_7 = "UnregisterApplicationRecoveryCallback" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AV_2147788056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AV!MTB"
        threat_id = "2147788056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 48 83 ec 20 48 63 41 3c 8b fa 4c 8b d9 8b 9c 08 88 00 00 00 8b ac 08 8c 00 00 00 48 03 d9 8b c2 c1 e8 10 66 85 c0 75 08 0f b7 c7 2b 43 10 eb 72 44 8b 43 20 45 33 c9 44 8b 53 24 4d 03 c3 8b 73 18 4d 03 d3 85 f6 74 3f}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AV_2147788056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AV!MTB"
        threat_id = "2147788056"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ENOnmF.pdb" ascii //weight: 3
        $x_3_2 = "CnINePcxy" ascii //weight: 3
        $x_3_3 = "DkxKPgByzItSjYNanM" ascii //weight: 3
        $x_3_4 = "IsProcessorFeaturePresent" ascii //weight: 3
        $x_3_5 = "FindFirstFileExW" ascii //weight: 3
        $x_3_6 = "GetConsoleOutputCP" ascii //weight: 3
        $x_3_7 = "D_KGetModuleHandleW AOMWL@TxNHANs" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AL_2147788951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AL!MTB"
        threat_id = "2147788951"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 2b 23 08 c9 7e 29 3d 9a e9 f7 e2 7e 67 3d 7d 51 dc 06 0f ?? ?? ?? ?? ?? 3d af 4e d6 0d 0f ?? ?? ?? ?? ?? 3d 9b e9 f7 e2 75 d5}  //weight: 10, accuracy: Low
        $x_10_2 = {8d 50 ff 0f af d0 b8 ff ff ff ff 31 c2 83 ca fe 39 c2 0f 94 45 07 83 f9 0a 0f 9c 45 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QW_2147794353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QW!MTB"
        threat_id = "2147794353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 89 ce 44 29 c6 44 0f af ce 41 83 e1 01 41 83 f9 00 0f 94 c3 80 e3 01 88 9d 06 03 00 00 41 83 fb 0a 0f 9c c3 80 e3 01 88 9d 07 03 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QW_2147794353_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QW!MTB"
        threat_id = "2147794353"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 94 c0 83 f9 0a 0f 9c c3 30 c3 b8 7a 98 4f 76 41 0f 45 c5}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 5d 57 0f b6 4d 56 89 da 30 ca ba ?? ?? ?? ?? 41 0f 45 d4 84 c9 89 d1 41 0f 45 cc 84 db 0f 44 ca eb ac}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QQ_2147795268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QQ!MTB"
        threat_id = "2147795268"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8b 84 24 c0 00 00 00 8a 00 48 8b 8c 24 b8 00 00 00 88 01 0f b6 44 24 37 4c 89 54 24 38 48 8b 4c 24 38}  //weight: 10, accuracy: High
        $x_10_2 = {89 c1 2b 4c 24 28 0f af 4c 24 28 83 c1 fd 89 4c 24 28 b9 ?? ?? ?? ?? e9 ?? ?? ?? ?? 48 8b 44 24 38 8a 44 24 4e 48 8b 0d ?? ?? ?? ?? 88 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QB_2147795269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QB!MTB"
        threat_id = "2147795269"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 4c 24 32 8a 44 24 32 f6 e1 88 44 24 32 8b 44 24 2c 8b 44 24 48 0f af 44 24 54 89 44 24 50 8b 44 24 2c 8b 44 24 2c 01 44 24 50 8b 44 24 2c 8b 44 24 50 48 8b 8c 24 80 00 00 00 8a 04 01 88 44 24 3a 8b 44 24 2c 8a 44 24 3a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QV_2147795336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QV!MTB"
        threat_id = "2147795336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 87 dd 4c 89 6c 24 08 49 87 dd 49 87 ed 4c 89 6c 24 10 4c 87 ed 48 89 74 24 18 48 87 f9 48 89 4c 24 20 48 87 f9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QV_2147795336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QV!MTB"
        threat_id = "2147795336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 0d 8b ca 41 ff c0 c1 e9 10 88 08 48 ff c0 49 63 c8 48 3b ce 73 0d 8b ca 41 ff c0 c1 e9 08 88 08 48 ff c0 49 63 c8 48 3b ce 73 08 41 ff c0 88 10}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QV_2147795336_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QV!MTB"
        threat_id = "2147795336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 85 7e 01 00 00 8a 8d 7f 01 00 00 88 ca 80 f2 ff 41 88 c0 41 30 d0 41 20 c0 88 c2 80 f2 ff 41 88 c9 41 20 d1 80 f1 ff 20 c8 41 08 c1 44 88 c0 34 ff 44 88 c9 80 f1 ff b2 01 80 f2 01 41 88 c2 41 80 e2 ff 41 20 d0 41 88 cb 41 80 e3 ff 41 20 d1 45 08 c2 45 08 cb 45 30 da 08 c8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QV_2147795336_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QV!MTB"
        threat_id = "2147795336"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 04 01 6b c0 71 83 c0 26 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 28 88 01}  //weight: 10, accuracy: High
        $x_1_2 = "PauseW" ascii //weight: 1
        $x_1_3 = "ResumeServer" ascii //weight: 1
        $x_1_4 = "ResumeW" ascii //weight: 1
        $x_1_5 = "StartServer" ascii //weight: 1
        $x_1_6 = "StartW" ascii //weight: 1
        $x_1_7 = "StopServer" ascii //weight: 1
        $x_1_8 = "SuspendServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AS_2147795456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AS!MTB"
        threat_id = "2147795456"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 04 01 6b c0 2f 83 c0 21 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 20 88 41 0a b8 01 00 00 00 48 6b c0 0b}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 01 6b c0 71 83 c0 62 99 b9 7f 00 00 00 f7 f9 8b c2 48 8b 4c 24 28 88 41 01 b8 01 00 00 00 48 6b c0 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_EG_2147797025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.EG!MTB"
        threat_id = "2147797025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 44 24 20 0f b6 c0 83 e8 ?? 88 44 24 20 8a 44 24 20 0f b6 c0 8a 4c 24 21 0f b6 c9 0b c8 8b c1 88 44 24 21 8a 44 24 22 0f b6 c0 8a 4c 24 21 0f b6 c9 33 c8 8b c1 88 44 24 21 8a 44 24 22 fe c0 88 44 24 22 48 8b 44 24 30 8a 4c 24 21 88 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DECV_2147797375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DECV!MTB"
        threat_id = "2147797375"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b 4c 24 30 48 8d 84 08 08 01 00 00 48 89 44 24 40 48 8b 44 24 28 8b 40 50 41 b9 40 00 00 00 41 b8 00 30 00 00 8b d0 48 8b 44 24 28 48 8b 48 30}  //weight: 5, accuracy: High
        $x_5_2 = {44 6b c2 7c b9 17 00 00 00 c1 e2 05 8b c2 41 83 e8 2c 4c 0f af c0 49 8b c2 49 f7 e0 48 c1 ea 07 48 69 c2 ff 00 00 00 4c 2b c0 41 0f b6 c0 0f 45 c8 33 d2 41 88 0c 39 ff c2 81 fa f0 49 02 00}  //weight: 5, accuracy: High
        $x_5_3 = {41 c6 06 4d 8a 45 a9 34 d9 41 88 46 01 be 02 00 00 00 b1 37 bb 03}  //weight: 5, accuracy: High
        $x_1_4 = "EnterDll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BazarLoader_DW_2147798405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DW!MTB"
        threat_id = "2147798405"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 c0 07 48 8d 52 01 0f be c9 33 c1 0f b6 0a 84 c9}  //weight: 10, accuracy: High
        $x_3_2 = "urmfxnoysm.dll" ascii //weight: 3
        $x_3_3 = "axusrtbgd" ascii //weight: 3
        $x_3_4 = "bqzvarvtqkaqxq" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPY_2147799425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPY!MTB"
        threat_id = "2147799425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 f6 74 0b 83 fe 01 75 0a 41 01 3c 91 eb 04 41 89 3c 91 41 8d 04 28 41 8b ce 03 f8 23 cd 41 8b c0 48 ff c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPY_2147799425_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPY!MTB"
        threat_id = "2147799425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cd 03 d8 23 ce 41 8b c0 48 ff c2 0b c3 03 f0 41 8b c0 03 f1 33 c6 ff c0 03 e8 8b c6 33 c3 8b cd 44 03 c0 33 ce 44 03 c1 49 3b d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPY_2147799425_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPY!MTB"
        threat_id = "2147799425"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ThroughSlowly" wide //weight: 1
        $x_1_2 = "RegularlyPlay" wide //weight: 1
        $x_1_3 = "FastBy" wide //weight: 1
        $x_1_4 = "DifferentBelow" wide //weight: 1
        $x_1_5 = "BecauseBig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_MBK_2147805252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MBK!MTB"
        threat_id = "2147805252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 0b 8b c2 48 33 c8 48 ff c3 0f b6 c1 8b ca c1 e9 [0-1] 8b 14 84 33 d1 45 03 d8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AN_2147805518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AN!MTB"
        threat_id = "2147805518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 09 89 ca f6 d2 20 c2 f6 d0 20 c8 08 d0 48 8b 4d ?? 88 01 48 8b 45 ?? 0f b6 00 04 01 48 8b 4d ?? 88 01 2f 00 48 8b 45 ?? 0f b6 00 48 8b 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_MCK_2147805561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MCK!MTB"
        threat_id = "2147805561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "home/kali/Tools/payloads/NimHollow/injector.nim" ascii //weight: 1
        $x_1_2 = "hollowShellcode" ascii //weight: 1
        $x_1_3 = "injector" ascii //weight: 1
        $x_1_4 = "@[*] Applying patch" ascii //weight: 1
        $x_1_5 = "@[X] Failed to get the address of 'EtwEventWrite'" ascii //weight: 1
        $x_1_6 = "@[+] ETW Patched" ascii //weight: 1
        $x_1_7 = "@[-] VirtualAllocExNuma did not pass the check, exiting" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPI_2147805656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPI!MTB"
        threat_id = "2147805656"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 88 6c 24 46 c7 44 24 6c 42 00 00 00 8a 54 24 37 80 ea b4 80 c2 01 80 c2 b4 88 54 24 37 c7 44 24 68 6a 00 00 00 8a 54 24 46 48 8b 4c 24 38 88 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPT_2147806382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPT!MTB"
        threat_id = "2147806382"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 11 88 54 24 21 80 44 24 21 c7 c0 64 24 21 04}  //weight: 1, accuracy: High
        $x_1_2 = {30 54 24 22 fe 44 24 23 8a 54 24 22 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPU_2147806383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPU!MTB"
        threat_id = "2147806383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 80 f3 ff 44 88 d3 80 f3 ff 40 b6 01 40 80 f6 00 44 88 df 40 80 e7 00 41 20 f1 40 88 dd 40 80 e5 00 41 20 f2 44 08 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPX_2147807209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPX!MTB"
        threat_id = "2147807209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 8b 04 87 43 89 04 8b 41 8d 40 01 41 ff c1 45 33 c0 3b c3 44 0f 45 c0 45 3b ca 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPX_2147807209_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPX!MTB"
        threat_id = "2147807209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c2 7f 89 d7 c1 ef 1f c1 fa 06 01 fa 89 d7 c1 e7 07 29 fa 01 f2 83 c2 7f 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPX_2147807209_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPX!MTB"
        threat_id = "2147807209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 0f b6 0c 01 41 32 0c 3e 88 0c 38 89 f9 83 e1 1f 42 0f b6 14 01 41 32 14 3e 88 14 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DE_2147807261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DE!MTB"
        threat_id = "2147807261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xll-transfer.xll" ascii //weight: 3
        $x_3_2 = "DllMain" ascii //weight: 3
        $x_3_3 = "SetExcel12EntryPt" ascii //weight: 3
        $x_3_4 = "XLCallVer" ascii //weight: 3
        $x_3_5 = "ClangCompileZ.dll" ascii //weight: 3
        $x_3_6 = "MdCallBack" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DE_2147807261_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DE!MTB"
        threat_id = "2147807261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xll-transfer.xll" ascii //weight: 3
        $x_3_2 = "DllMain" ascii //weight: 3
        $x_3_3 = "SetExcel12EntryPt" ascii //weight: 3
        $x_3_4 = "XLCallVer" ascii //weight: 3
        $x_3_5 = "JavaObjectReflective" ascii //weight: 3
        $x_3_6 = "Save wget.exe to" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DE_2147807261_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DE!MTB"
        threat_id = "2147807261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "xll-transfer.xll" ascii //weight: 3
        $x_3_2 = "SetExcel12EntryPt" ascii //weight: 3
        $x_3_3 = "JetBrains" ascii //weight: 3
        $x_3_4 = "BoagElpyDjmqcxa" ascii //weight: 3
        $x_3_5 = "EikcaTyejkjUjlna" ascii //weight: 3
        $x_3_6 = "FpczxnahPibbqaxfaueg" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DE_2147807261_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DE!MTB"
        threat_id = "2147807261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "CurrentVersion\\Policies\\Explorer" ascii //weight: 3
        $x_3_2 = "RestrictRun" ascii //weight: 3
        $x_3_3 = "NoNetConnectDisconnect" ascii //weight: 3
        $x_3_4 = "NoRecentDocsHistory" ascii //weight: 3
        $x_3_5 = "cdweewr" ascii //weight: 3
        $x_3_6 = "jkreere" ascii //weight: 3
        $x_3_7 = "GetNativeSystemInfo" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DE_2147807261_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DE!MTB"
        threat_id = "2147807261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "l2v9yglkmi" ascii //weight: 3
        $x_3_2 = "YOUR DOCTOR IS FIRED!!!!!!" ascii //weight: 3
        $x_3_3 = "VirtualProtect" ascii //weight: 3
        $x_3_4 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_5 = "HttpAddRequestHeadersA" ascii //weight: 3
        $x_3_6 = "FormatMessageW" ascii //weight: 3
        $x_3_7 = "InterlockedPushEntrySList" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QE_2147807262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QE!MTB"
        threat_id = "2147807262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 4c 24 37 41 88 c1 41 28 c9 88 c1 80 e9 01 41 00 c9 44 28 c8 88 44 24 37}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QE_2147807262_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QE!MTB"
        threat_id = "2147807262"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2c 0a 88 44 0d 87 48 ff c1 48 83 f9 0d 72 ec}  //weight: 10, accuracy: High
        $x_10_2 = {0f b6 44 15 b7 8d 4a 4f 32 c8 88 4c 15 b7 48 ff c2 48 83 fa 0c 72 e9}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_GE_2147807325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.GE!MTB"
        threat_id = "2147807325"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4c 89 64 24 38 4c 89 64 24 30 48 2b fb 48 d1 ff 4c 8b c3 33 d2 44 8d 4f 01 33 c9 44 89 64 24 28 4c 89 64 24 20}  //weight: 10, accuracy: High
        $x_3_2 = "vW2zDSMKTjz&QrJNojrUKhCyj00B" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_MZB_2147809097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MZB!MTB"
        threat_id = "2147809097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 60 b8 08 00 00 00 48 6b c0 [0-1] 48 8b 4c 24 28 48 8b 54 24 40 8b 04 02 8b 49 20 2b c8 8b c1 8b c0 48 8b 4c 24 28 48 03 c8 48 8b c1 48 89 44 24 48 c7 44 24 [0-5] 48 8b 44 24 28 8b 40 18 89 44 24 24 8b 44 24 24 d1 e8 89 44 24 20 8b 44 24 24 ff c0 89 44 24 34 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_ER_2147809477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.ER!MTB"
        threat_id = "2147809477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 0f af d2 83 e2 01 83 fa 00 41 0f 94 c3 41 83 f8 0a 0f 9c c3 40 88 de 40 80 f6 ff 44 88 df 40 30 f7 44 20 df 44 88 de 40 80 f6 ff 41 88 de 41 20 f6 80 f3 ff}  //weight: 10, accuracy: High
        $x_3_2 = "ZrjyqysHjygbhoejyzRjmhozrjt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DG_2147809977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DG!MTB"
        threat_id = "2147809977"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 28 c1 e8 10 8b 4c 24 34 83 c1 01 89 8c 24 a4 00 00 00 48 8b 4c 24 50 48 8b 94 24 90 00 00 00 88 04 11}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DEN_2147810490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DEN!MTB"
        threat_id = "2147810490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 c0 07 48 8d 52 01 0f be c9 33 c1 0f b6 0a 84 c9 75 ed}  //weight: 10, accuracy: High
        $x_3_2 = "lwtzrvzbihvt.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPL_2147810769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPL!MTB"
        threat_id = "2147810769"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 53 01 c0 e2 03 8a 0b 80 e1 07 0a d1 c0 e2 03 8a 43 ff 24 07 0a d0 43 88 14 08 49 ff c0 48 8d 5b 03 49 81 f8 00 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_DC_2147810947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.DC!MTB"
        threat_id = "2147810947"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DllRegisterServer" ascii //weight: 3
        $x_3_2 = "PluginInit" ascii //weight: 3
        $x_3_3 = "RunObject" ascii //weight: 3
        $x_3_4 = "BmtpzhlDhedaxtCsdupdywbab" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_CM_2147811419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.CM!MTB"
        threat_id = "2147811419"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 c0 6d 4e c6 41 05 39 30 00 00 48 c1 e8 10 48 99 49 23 d0 48 03 c2 49 23 c0 48 2b c2}  //weight: 10, accuracy: High
        $x_3_2 = "LIBRARY.dll" ascii //weight: 3
        $x_3_3 = "7ce3e80173264ea19b05306b865eadf9" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPW_2147811597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPW!MTB"
        threat_id = "2147811597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 85 c0 74 0b 88 18 ff cf 48 ff c0 85 ff 7f f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPK_2147811603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPK!MTB"
        threat_id = "2147811603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xll-transfer.xll" ascii //weight: 1
        $x_1_2 = "SetExcel12EntryPt" ascii //weight: 1
        $x_1_3 = "XLCallVer" ascii //weight: 1
        $x_1_4 = "xlAutoOpen" ascii //weight: 1
        $x_1_5 = "XLCall32.dll" ascii //weight: 1
        $x_1_6 = "rundll32" wide //weight: 1
        $x_1_7 = "JavaObjectReflectR.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_MAK_2147811794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.MAK!MTB"
        threat_id = "2147811794"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 6b 00 00 00 66 89 44 24 50 b8 65 00 00 00 66 89 44 24 52 b8 72 00 00 00 66 89 44 24 54 b8 6e 00 00 00 66 89 44 24 56 b8 65 00 00 00 66 89 44 24 58 b8 6c 00 00 00 66 89 44 24 5a b8 33 00 00 00 66 89 44 24 5c b8 32 00 00 00 66 89 44 24 5e b8 2e 00 00 00 66 89 44 24 60 b8 64 00 00 00 66 89 44 24 62 b8 6c 00 00 00 66 89 44 24 64 b8 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 30 4c c6 44 24 31 6f c6 44 24 32 61 c6 44 24 33 64 c6 44 24 34 4c c6 44 24 35 69 c6 44 24 36 62 c6 44 24 37 72 c6 44 24 38 61 c6 44 24 39 72 c6 44 24 3a 79 c6 44 24 3b 41}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 40 47 c6 44 24 41 65 c6 44 24 42 74 c6 44 24 43 50 c6 44 24 44 72 c6 44 24 45 6f c6 44 24 46 63 c6 44 24 47 41 c6 44 24 48 64 c6 44 24 49 64 c6 44 24 4a 72 c6 44 24 4b 65 c6 44 24 4c 73 c6 44 24 4d 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QA_2147811816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QA!MTB"
        threat_id = "2147811816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 8b 49 f8 49 ff ca 41 8b 11 49 03 ce 45 8b 41 fc 48 03 d6 4d 85 c0 74 19 0f 1f 80 00 00 00 00 0f b6 02 48 ff c2 88 01 48 8d 49 01 49 83 e8 01 75 ee 49 83 c1 28 4d 85 d2 75 c5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QA_2147811816_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QA!MTB"
        threat_id = "2147811816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 e5 05 c6 45 e6 14 c6 45 e7 2f c6 45 e8 10 c6 45 e9 05 c6 45 ea 0e c6 45 eb 26 c6 45 ec 09 c6 45 ed 0c c6 45 ee 05 c6 45 ef 2e c6 45 f0 01 c6 45 f1 0d c6 45 f2 05 c6 45 f3 21 88 45 f4}  //weight: 10, accuracy: High
        $x_3_2 = "WTL_CmdBar_InternalAutoPopupMsg" ascii //weight: 3
        $x_3_3 = "Module_Raw" ascii //weight: 3
        $x_3_4 = "GetOpenFileNameA" ascii //weight: 3
        $x_3_5 = "WTL_CommandBar" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QM_2147812237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QM!MTB"
        threat_id = "2147812237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 01 00 00 00 83 c0 00 eb 00 48 83 c4 18 c3 48 89 4c 24 08 48 83 ec 18 eb 00 8b 44 24 28 89 04 24 eb dd 44 89 4c 24 20 4c 89 44 24 18 eb 0b}  //weight: 10, accuracy: High
        $x_3_2 = "vE4HPNQDcW1qRo" ascii //weight: 3
        $x_3_3 = "ax64.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QM_2147812237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QM!MTB"
        threat_id = "2147812237"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 44 24 70 48 8d 84 24 ac 00 00 00 48 89 44 24 78 48 8b 4c 24 78 48 8d 94 24 98 00 00 00 48 89 94 24 80 00 00 00 48 8b 8c 24 80 00 00 00 48 c7 02 ?? ?? ?? ?? 4c 8d 8c 24 b0 00 00 00 4c 89 8c 24 88 00 00 00 48 8b 8c 24 88 00 00 00 48 8b 4c 24 48 48 83 c1 18 48 89 8c 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 63 09 49 89 09 48 8b 4c 24 48 48 83 c1 10 48 89 4c 24 50 48 8b 4c 24 50 4c 8b 01 48 8b 4c 24 70}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_M_2147813310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.M!MTB"
        threat_id = "2147813310"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {44 8d 34 13 f7 eb 41 c1 fe 05 8b c2 41 8b ce c1 f8 04 c1 e9 1f 44 03 f1 8b c8 c1 e9 1f 03 c1 89 44 24 28}  //weight: 10, accuracy: High
        $x_3_2 = "czacesnozxvg.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_QC_2147813925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.QC!MTB"
        threat_id = "2147813925"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 95 48 8b 2b 48 95 48 85 c0 0f 84 05 00 00 00 4d 87 ff ff d0}  //weight: 5, accuracy: High
        $x_5_2 = {48 c1 e2 07 48 c1 e2 0c 48 c1 e2 06 48 c1 e2 03 48 d1 e2 48 c1 e2 03 48 0b c2 c7 44 24 c4 32 48 bc 6d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_RPR_2147815542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.RPR!MTB"
        threat_id = "2147815542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b6 0c 00 48 8d 40 01 80 f1 ba ff c2 88 48 ff 81 fa a0 7a 00 00 72 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AA_2147815827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AA!MTB"
        threat_id = "2147815827"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 84 0c ?? ?? ?? ?? 83 e8 [0-4] 6b c0 d4 99 41 f7 f8 8d 42 ?? 99 41 f7 f8 88 94 0c ?? ?? ?? ?? 48 ff c1 48 83 f9 ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AH_2147846823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AH!MTB"
        threat_id = "2147846823"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "F$Iduiz4" ascii //weight: 3
        $x_3_2 = "Gemplus GemSAFE Card CSP v1.0" ascii //weight: 3
        $x_3_3 = "System32\\DRIVERS\\asyncmac.sys" ascii //weight: 3
        $x_3_4 = "_itoa" ascii //weight: 3
        $x_3_5 = "MpVregOpenKeySuccess" ascii //weight: 3
        $x_3_6 = "testsvc.exe" ascii //weight: 3
        $x_3_7 = "Windows Beep Service" ascii //weight: 3
        $x_3_8 = "advapi32.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_AGH_2147896078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.AGH!MTB"
        threat_id = "2147896078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 5c 24 08 48 89 7c 24 10 55 48 8d ac 24 70 fd ff ff 48 81 ec 90 03 00 00 8b 85 c0 02 00 00 83 a5 34 01 00 00 00 89 85 30 01 00 00 48 8b 85 c8 02}  //weight: 10, accuracy: High
        $x_3_2 = "CreateMutexA" ascii //weight: 3
        $x_3_3 = "ActivateKeyboardLayout" ascii //weight: 3
        $x_3_4 = "GetKeyboardLayout" ascii //weight: 3
        $x_3_5 = "GetCommandLineA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_SA_2147898721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.SA!MTB"
        threat_id = "2147898721"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 f1 0f b6 44 14 ?? 41 8b d0 33 d0 8b 8c 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 03 c1 03 84 24 ?? ?? ?? ?? 8b 4c 24 ?? 0f af 8c 24 ?? ?? ?? ?? 03 c1 48 63 c8 48 8b 84 24 ?? ?? ?? ?? 88 14 08 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_SB_2147899926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.SB!MTB"
        threat_id = "2147899926"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 45 d8 41 8b 4e ?? 4c 8d 8c 24 ?? ?? ?? ?? 41 8b 56 ?? 8b c3 0f ba e8 ?? 41 81 e0 ?? ?? ?? ?? 0f 44 c3 48 03 ce 44 8b c0 8b d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_KAA_2147901163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.KAA!MTB"
        threat_id = "2147901163"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 58 89 07 b8 ?? ?? ?? ?? 48 8d 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BazarLoader_ABZR_2147943043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BazarLoader.ABZR!MTB"
        threat_id = "2147943043"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 99 c1 ea 18 01 d0 0f b6 c0 29 d0 89 45 fc 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 0f b6 d0 8b 45 f8 01 d0 99 c1 ea 18 01 d0 0f b6 c0 29 d0 89 45 f8 8b 45 fc 48 63 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

