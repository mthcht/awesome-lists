rule Trojan_Win32_IcedID_A_2147735313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.A!!IcedID.A"
        threat_id = "2147735313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "IcedID: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "203"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 4d 77 61 (75|74) 05 00 04 01 01 01 01 3d fb f9 fa}  //weight: 1, accuracy: Low
        $x_1_2 = {58 65 6e 56 (75|74) 05 00 04 01 01 01 01 3d fb f9 fa}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 69 63 72 (75|74) 05 00 04 01 01 01 01 3d fb f9 fa}  //weight: 1, accuracy: Low
        $x_1_4 = {4b 56 4d 4b (75|74) 05 00 04 01 01 01 01 3d fb f9 fa}  //weight: 1, accuracy: Low
        $x_1_5 = {56 42 6f 78 (75|74) 05 00 04 01 01 01 01 3d fb f9 fa}  //weight: 1, accuracy: Low
        $x_100_6 = {43 8b d0 46 59 8a 0c 37 32 ca 88 0e}  //weight: 100, accuracy: High
        $x_100_7 = {d1 c8 f7 d0 d1 c8 2d 20 01 00 00 d1 c0 f7 d0 2d 01 91 00 00}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_100_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_IcedID_DSK_2147742670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.DSK!MTB"
        threat_id = "2147742670"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 10 05 cc cb e5 01 89 02 a3 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? a1 a4 4c 42 00 2b c7 83 c2 04 83 6c 24 14 01 0f b7 c8 89 54 24 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_VDSK_2147745110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.VDSK!MTB"
        threat_id = "2147745110"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b cd 83 e9 09 0f b7 f9 05 dc a5 ed 01 a3 ?? ?? ?? ?? 89 02 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 55 f8 8b ca b8 05 00 00 00 03 c1 83 e8 05 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedID_PDSK_2147745262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PDSK!MTB"
        threat_id = "2147745262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 10 05 20 ab 8f 01 89 02 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e0 05 bd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVK_2147749788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVK!MTB"
        threat_id = "2147749788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 10 05 9c 29 cd 01 a3 ?? ?? ?? ?? 89 02 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b d7 b8 7c 00 00 00 03 c2 83 e8 7c a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 4d 0c 8b 45 fc 33 d2 03 c8 f7 75 14 8b 45 08 8a 04 50 30 01}  //weight: 2, accuracy: High
        $x_2_4 = {8a 04 0e 8b 4c 24 60 81 c1 66 d4 e1 0e 30 f8 89 4c 24 60 8b 4c 24 44 88 04 11}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedID_KDS_2147750847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.KDS!MTB"
        threat_id = "2147750847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 d8 69 c0 db 02 03 00 a3 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b f7 05 d0 18 68 01 2b f1 83 ee 2f a3 ?? ?? ?? ?? 66 89 35 07 00 66 89 35}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 44 15 fc 32 04 0e 47 88 01 3b 7d 10 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_IcedID_2147751159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID!MTB"
        threat_id = "2147751159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {49 44 41 54 30 00 0b c1 c1 ?? 08 c1 ?? 08 0b d0 30 00 0b d0 8b c1 [0-32] 00 ff 00 00}  //weight: 50, accuracy: Low
        $x_50_2 = {49 44 41 54 50 00 0b c1 c1 ?? 08 c1 ?? 08 0b d0 30 00 0b d0 8b c1}  //weight: 50, accuracy: Low
        $x_1_3 = "WinHttpQueryDataAvailable" ascii //weight: 1
        $x_1_4 = "WinHttpConnect" ascii //weight: 1
        $x_1_5 = "WinHttpSendRequest" ascii //weight: 1
        $x_1_6 = "WinHttpCloseHandle" ascii //weight: 1
        $x_1_7 = "WinHttpSetOption" ascii //weight: 1
        $x_1_8 = "WinHttpOpenRequest" ascii //weight: 1
        $x_1_9 = "WinHttpReadData" ascii //weight: 1
        $x_1_10 = "WinHttpQueryHeaders" ascii //weight: 1
        $x_1_11 = "WinHttpOpen" ascii //weight: 1
        $x_1_12 = "WinHttpReceiveResponse" ascii //weight: 1
        $x_1_13 = "WINHTTP.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 5 of ($x_1_*))) or
            ((2 of ($x_50_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_IcedID_PKV_2147752587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PKV!MTB"
        threat_id = "2147752587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c2 5c 60 2d 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 fc 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ff ff 06 00 8b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_DSP_2147752812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.DSP!MTB"
        threat_id = "2147752812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 01 03 fe 89 3d ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 76 ?? 29 35 ?? ?? ?? ?? 05 28 57 93 01 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVR_2147753515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVR!MTB"
        threat_id = "2147753515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 89 15 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 10 4c 08 02 6b ed 1f 8b 44 24 24 03 6c 24 28 8b 0d ?? ?? ?? ?? 89 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVP_2147753663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVP!MTB"
        threat_id = "2147753663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c7 50 96 26 01 89 3d ?? ?? ?? ?? 89 bc 30 ?? ?? ff ff 83 c6 04 8b 15 ?? ?? ?? ?? 8a c2 2a 05 ?? ?? ?? ?? 04 04 81 fe a2 13 00 00 0f 82 05 00 a1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVE_2147753812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVE!MTB"
        threat_id = "2147753812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 03 de 66 89 15 ?? ?? ?? ?? 8b 74 24 18 66 89 1d ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 81 c3 ac f5 ff ff 89 06 05 00 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MM_2147755334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MM!MTB"
        threat_id = "2147755334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 4c 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 48 83 c4 ?? 8a 54 14 14 32 da 88 5d 00 45 48 89 44 24 10 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVA_2147759368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVA!MTB"
        threat_id = "2147759368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 38 88 04 3e 8b 75 fc 0f b6 c0 03 c2 0f b6 c0 88 0c 3e 8b 4d 08 8a 04 38 32 04 0b 88 01}  //weight: 1, accuracy: High
        $x_1_2 = "qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PVB_2147759773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PVB!MTB"
        threat_id = "2147759773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "06WYp4KuV4611XwjqHdiuB1jb0JNhUZLhzUQ6V4M2S6I1gFXpyxE2MQBfJu4iigy" ascii //weight: 1
        $x_1_2 = "qxnVX5YRonia5LIknkLQUcfLO8NYvkcx1mo4ns1VH0y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MB_2147759899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MB!MTB"
        threat_id = "2147759899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b df 81 c1 20 f3 8e 01 03 c3 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 8c 16 5f de ff ff a1 ?? ?? ?? ?? 8b 2d ?? ?? ?? ?? bb 53 00 00 00 2b d8 8b cd 2b cb 83 c1 1d 89 1d ?? ?? ?? ?? 3b c8 75}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateSemaphoreA" ascii //weight: 1
        $x_1_3 = "RegisterHotKey" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MB_2147759899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MB!MTB"
        threat_id = "2147759899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "shellexecute=AutoRun.exe" ascii //weight: 3
        $x_3_2 = "prop:System.Security.EncryptionOwners" ascii //weight: 3
        $x_3_3 = "ResolveDelayLoadedAPI" ascii //weight: 3
        $x_3_4 = "DelayLoadFailureHook" ascii //weight: 3
        $x_3_5 = "DuplicateEncryptionInfoFile" ascii //weight: 3
        $x_3_6 = "lpValueName->Hidden" ascii //weight: 3
        $x_3_7 = "C:\\AUTOEXEC.BAT.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_GC_2147760545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GC!MTB"
        threat_id = "2147760545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 33 f9 c7 05 [0-48] 01 3d [0-48] 8b ff a1 [0-48] 8b 0d [0-48] 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_GG_2147772934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GG!MTB"
        threat_id = "2147772934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "loader_dll_64.dll" ascii //weight: 10
        $x_1_2 = "aws.amazon.com" ascii //weight: 1
        $x_1_3 = "Cookie: __gads=" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "; _gat=" ascii //weight: 1
        $x_1_6 = "; _ga=" ascii //weight: 1
        $x_1_7 = "; _u=" ascii //weight: 1
        $x_1_8 = "; __io=" ascii //weight: 1
        $x_1_9 = "; _gid=" ascii //weight: 1
        $x_1_10 = "LookupAccountNameW" ascii //weight: 1
        $x_1_11 = "WINHTTP.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_IcedID_GG_2147772934_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GG!MTB"
        threat_id = "2147772934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sadl_32.dll" ascii //weight: 1
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
        $x_1_3 = "WINHTTP.dll" ascii //weight: 1
        $x_1_4 = "?id=%0.2X%0.8X%0.8X%s" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "WriteFile" ascii //weight: 1
        $x_1_7 = "%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X" ascii //weight: 1
        $x_1_8 = "%0.2X%0.2X%0.2X%0.2X%0.2X%0.2X%0.8X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_Win32_IcedID_PAA_2147773281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PAA!MTB"
        threat_id = "2147773281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 89 44 24 10 8b 54 24 10 0f b6 c3 0f b6 da 0f af d8 8b 15 ?? ?? ?? ?? c0 e3 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PAA_2147773281_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PAA!MTB"
        threat_id = "2147773281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<command:parameter required=\"false\" variableLength=\"false\" globbing=\"false\" pipelineInput=\"false\" position=\"named\">" ascii //weight: 1
        $x_1_2 = "GetCurrentProcessId" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CreateProcessA" ascii //weight: 1
        $x_1_6 = "GetProcAddress" ascii //weight: 1
        $x_1_7 = "GetTickCount" ascii //weight: 1
        $x_1_8 = "WriteFile" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = ".pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_AF_2147783905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.AF!MTB"
        threat_id = "2147783905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 4c 24 07 2a c2 2a 44 24 08 02 c9 55 2a c1 0f b6 e9 56 2c 69 57 88 44 24 13}  //weight: 10, accuracy: High
        $x_10_2 = {89 4d fc 8b 15 ?? ?? ?? ?? 81 c2 79 8f 0e 00 89 55 fc 6b 45 0c 4e 0f af 45 fc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_AF_2147783905_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.AF!MTB"
        threat_id = "2147783905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 41 24 8b 08 8d 51 01 89 10 8a 44 24 04 88 01 0f b6 c0 eb 0b}  //weight: 10, accuracy: High
        $x_3_2 = "DoWhit" ascii //weight: 3
        $x_3_3 = "GetTempPathA" ascii //weight: 3
        $x_3_4 = "MoveFileExA" ascii //weight: 3
        $x_3_5 = "ImageList_DragShowNolock" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_AHB_2147788266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.AHB!MTB"
        threat_id = "2147788266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "eccc___ce_s__" ascii //weight: 3
        $x_3_2 = "efehjunlopkju" ascii //weight: 3
        $x_3_3 = "bsitmjasdo" ascii //weight: 3
        $x_3_4 = "iseusbrsaorptirh" ascii //weight: 3
        $x_3_5 = "FindResourceW" ascii //weight: 3
        $x_3_6 = "OleFlushClipboard" ascii //weight: 3
        $x_3_7 = "CopyFileA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_M_2147794454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.M!MTB"
        threat_id = "2147794454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 00 a0 01 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 e4 68 00 a0 01 00 68 48 72 f3 05}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 55 ba 02 00 00 00 6b c2 00 8b 4d fc 8d 54 01 04 52 6a 5c 68 00 04 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d fc 81 c1 b4 00 00 00 51 8b 55 fc 83 c2 04 52 51 f3 0f 10 05 ?? 34 f3 05 f3 0f 11 04 24 6a 05 6a 00 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_GZ_2147794718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GZ!MTB"
        threat_id = "2147794718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b c8 66 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 84 12 ae 58 00 00 2b 05 ?? ?? ?? ?? 83 c4 04 03 c6 66 a3 ?? ?? ?? ?? 0f b7 c0 6b c0 1d 5f 0f b7 c9 5e 03 c1 8b 8c 24 b0 08 00 00 5d 5b 33 cc}  //weight: 1, accuracy: Low
        $x_1_2 = "salt\\who\\When\\numberSight.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_C_2147797893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.C!MTB"
        threat_id = "2147797893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c f6 8b 1d ?? ?? ?? ?? 03 c9 8b c5 6b fe 0d f7 d8 c7 44 24 28 d8 f2 4b 00 2b c1 83 c4 0c 8b 0d ?? ?? ?? ?? 03 c8 b8 83 be a0 2f f7 e3 03 fb c1 ea 03 81 fa c5 e3 00 00 74 08 81 c3 11 df 93 22 eb 09 0f af d9 81 c3 c5 e3 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_AQ_2147798738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.AQ!MTB"
        threat_id = "2147798738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c3 8b c8 2b c3 81 c1 ?? ?? ?? ?? 83 e8 06 03 cb}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 5c 24 10 2b ce 03 c1 83 c3 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_Q_2147811674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.Q!MTB"
        threat_id = "2147811674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Desert\\near\\Dark" ascii //weight: 3
        $x_3_2 = "classUntil.pdb" ascii //weight: 3
        $x_3_3 = "GetVolumeInformationA" ascii //weight: 3
        $x_3_4 = "GetStartupInfoA" ascii //weight: 3
        $x_3_5 = "PostMessageA" ascii //weight: 3
        $x_3_6 = "GetUserObjectInformationA" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_QM_2147811916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.QM!MTB"
        threat_id = "2147811916"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 4a 04 89 01 8b ca 81 c1 f0 ff 13 00 8b f1 83 ee 04 c7 06 02 00 00 00 be e0 ff 13 00 2b f3}  //weight: 10, accuracy: High
        $x_3_2 = "103.175.16.113" ascii //weight: 3
        $x_3_3 = "htons" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_UR_2147812160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.UR!MTB"
        threat_id = "2147812160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 c1 f9 05 8d 1c 8d 40 03 42 00 8b f0 83 e6 1f 6b f6 38 8b 0b 0f b6 4c 31 04 83 e1 01 74 bf}  //weight: 10, accuracy: High
        $x_1_2 = "AokvcOigngi" ascii //weight: 1
        $x_1_3 = "UqmqcWzfin" ascii //weight: 1
        $x_1_4 = "QfpQnumhnHcczjhe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_NC_2147813752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.NC!MTB"
        threat_id = "2147813752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2c 07 8a d9 2a 1e 2a da 80 c3 40 02 c3 0f b6 f8}  //weight: 10, accuracy: High
        $x_3_2 = "55\\47\\oh.pdb" ascii //weight: 3
        $x_3_3 = "Suitprove" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_GZM_2147813761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GZM!MTB"
        threat_id = "2147813761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 31 ff 2b 39 f7 df 83 c1 ?? 83 ef ?? 31 c7 83 ef ?? 31 c0 29 f8 f7 d8 89 3a 83 ea ?? 83 c6 ?? 83 fe ?? 75 dc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MA_2147822278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MA!MTB"
        threat_id = "2147822278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "paint.dll" ascii //weight: 1
        $x_1_2 = "\\simple\\Solution\\Post\\paint.pdb" ascii //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
        $x_1_4 = "Trycommon" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "OpenMutexA" ascii //weight: 1
        $x_1_8 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_9 = "Expect SameWrite Teach" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_BC_2147828682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.BC!MSR"
        threat_id = "2147828682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EknZMRKx" ascii //weight: 2
        $x_2_2 = "FRamboa" ascii //weight: 2
        $x_2_3 = "KMphtTLJ" ascii //weight: 2
        $x_2_4 = "MpOQBh" ascii //weight: 2
        $x_2_5 = "RjSbqa" ascii //weight: 2
        $x_2_6 = "bNsYaRx" ascii //weight: 2
        $x_2_7 = "chPXRMwNa" ascii //weight: 2
        $x_2_8 = "gTSqdVgbWSK" ascii //weight: 2
        $x_2_9 = "lkieAUWAz" ascii //weight: 2
        $x_2_10 = "xvILnJMr" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_PCA_2147831118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.PCA!MTB"
        threat_id = "2147831118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 48 63 0c 24 eb 08 8b c2 48 98 3a c9 74 16 48 8b 54 24 40 88 04 0a eb 2e eb 3e 8b 4c 24 04 33 c8 3a c9 74 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_BE_2147832069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.BE!MSR"
        threat_id = "2147832069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ETPCAnWrBci" ascii //weight: 2
        $x_2_2 = "IPwUAQIxYJcCj" ascii //weight: 2
        $x_2_3 = "IkHhuDeyJOLdzc" ascii //weight: 2
        $x_2_4 = "QzMQEDDloTvmr" ascii //weight: 2
        $x_2_5 = "VEJjEZeIWqDCZ" ascii //weight: 2
        $x_2_6 = "XCYhbvLyeCLW" ascii //weight: 2
        $x_2_7 = "XFHOOPcEKQlF" ascii //weight: 2
        $x_2_8 = "YDslUHhNONkMRU" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_RG_2147834545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.RG!MTB"
        threat_id = "2147834545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "gyuasfniuhaygsbdhjasfuhadsdjkfdkls" ascii //weight: 5
        $x_5_2 = "0ba54d579ab5cd6d" ascii //weight: 5
        $x_5_3 = "951d605d26f9a353" ascii //weight: 5
        $x_1_4 = "GetConsoleScreenBufferInfo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MC_2147834850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MC!MTB"
        threat_id = "2147834850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f9 cd 02 8c 9e 90 9c 92 97 91 8c 9f 47 64 9e 80 31 84 88 86 8f 8d 90 83 ec 8f 8a 94 85 88 84 8a bb b9 a4 b7 90 b3 b6 a8 b1 bc b0 be b7 b5 a8 bb}  //weight: 10, accuracy: High
        $x_10_2 = {30 b6 81 eb fc d8 91 f5 73 45 43 46 da de 8f e6 74 57 52 4c 5d 50 5c 52 53 51 4c 5f 78 5b 5e 40 19 01 48 46 03 4c 54 43 69 91 0c 08 45 48 44 4a}  //weight: 10, accuracy: High
        $x_5_3 = "Jipoker" wide //weight: 5
        $x_5_4 = "Kiopfjejdgyk" wide //weight: 5
        $x_1_5 = "frmWebBrowser" ascii //weight: 1
        $x_1_6 = "txtPassWord" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_MD_2147838213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.MD!MTB"
        threat_id = "2147838213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {cc 31 00 09 c0 41 1d 54 b6 58 2e 4b 92 83 65 fc 53 45 9f 60 20 fb 94 52 b7 e3 b6 49 83 52 8e e5 2b c7 19 76 3a 4f}  //weight: 5, accuracy: High
        $x_2_2 = "BOX" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_AZ_2147838769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.AZ!MTB"
        threat_id = "2147838769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e0 89 45 ?? 8b 45 ?? 01 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 90 01 45 ?? 8b 45 ?? 89 45 ?? 8b 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 33 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? ff 4d ?? 0f 85 ?? ?? ?? ?? 8b 45 ?? 89 7b 04 5f 89 03 5e c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_GJT_2147849973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.GJT!MTB"
        threat_id = "2147849973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 28 83 ef ?? 8b cf 2b ce 2b ca 83 e9 ?? 88 45 ?? 8b d1 2b d3 83 c2 ?? 8b c1 2b c7 83 e8 ?? 83 c5 ?? 03 f2 83 54 24 ?? ?? 8b d0 2b d6 2b d1 85 ff 75}  //weight: 10, accuracy: Low
        $x_1_2 = "Listopen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_HM_2147900385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.HM!MTB"
        threat_id = "2147900385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 ?? 75 ?? 8b 5d ?? 66 01 da f6 da 6b d2 ?? c1 ca ?? 89 55 ?? 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_HN_2147900541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.HN!MTB"
        threat_id = "2147900541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 ?? 75 ?? bb ?? ?? ?? ?? 89 fb 66 01 da f6 da 6b d2 ?? c1 ca ?? 66 81 c7 ?? ?? 89 d7 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_KQ_2147906450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.KQ!MTB"
        threat_id = "2147906450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 db 8a 4c 1c ?? 0f b6 d1 02 c2 0f b6 c0 89 44 24 ?? 8a 44 04 ?? 88 44 1c ?? 8b 44 24 ?? 88 4c 04 ?? 8a 44 1c ?? 02 c2 0f b6 c0 8a 44 04 ?? 32 04 3e 88 07 47 8b 44 24 ?? 83 ed}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_RT_2147907820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.RT!MTB"
        threat_id = "2147907820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 ?? 75 ?? 8b 5d ?? 66 01 da 6b d2 ?? c1 ca ?? 89 55 ?? 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_BHL_2147913542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.BHL!MTB"
        threat_id = "2147913542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 04 88 45 dc 0f b6 4c 9d da 0f b6 89 ?? ?? ?? ?? 30 4d dd 0f b6 4c 9d db 0f b6 89 60 a6 02 01 30 4d de 0f b6 4c 9d d8 32 46 fc 0f b6 89 ?? ?? ?? ?? 30 4d df 88 45 dc 89 75 cc b8 01 00 00 00 83 fb 08 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_IcedID_STR_2147913637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IcedID.STR!MTB"
        threat_id = "2147913637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IcedID"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d1 33 d5 66 0f b6 6c 24 ?? 81 e2 ff 00 00 00 66 33 2c 55 c0 93 45 00 80 f9 7e 89 6c 24 1c 74}  //weight: 1, accuracy: Low
        $x_1_2 = {40 80 f1 20 8b 16 88 0c 10 8b 4c 24 ?? 40 47 3b f9 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

