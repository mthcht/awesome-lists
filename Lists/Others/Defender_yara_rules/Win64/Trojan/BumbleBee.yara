rule Trojan_Win64_BumbleBee_AK_2147819178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AK!MTB"
        threat_id = "2147819178"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HSoh05Iq6" ascii //weight: 2
        $x_2_2 = "PzzD469R0" ascii //weight: 2
        $x_2_3 = "rib god dedicate" ascii //weight: 2
        $x_2_4 = "konrad repair" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AK_2147819178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AK!MTB"
        threat_id = "2147819178"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TXI073Byz" ascii //weight: 2
        $x_2_2 = "EdHVntqdWt" ascii //weight: 2
        $x_2_3 = "PeekNamedPipe" ascii //weight: 2
        $x_2_4 = "HeapWalk" ascii //weight: 2
        $x_2_5 = "IsDebuggerPresent" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AK_2147819178_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AK!MTB"
        threat_id = "2147819178"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "nxhUOYzfac" ascii //weight: 2
        $x_2_2 = "rank without stuck" ascii //weight: 2
        $x_2_3 = "circular nightmare gale" ascii //weight: 2
        $x_2_4 = "SuspendThread" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AM_2147819317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AM!MTB"
        threat_id = "2147819317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Eei15i" ascii //weight: 2
        $x_2_2 = "LiRNN5F" ascii //weight: 2
        $x_2_3 = "XZrEX92261" ascii //weight: 2
        $x_2_4 = "dolls them scientific" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AM_2147819317_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AM!MTB"
        threat_id = "2147819317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "damp farrier" ascii //weight: 2
        $x_3_2 = "curl stern" ascii //weight: 3
        $x_2_3 = "jazz napoleon" ascii //weight: 2
        $x_2_4 = "jpHgEctOOP" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BumbleBee_AM_2147819317_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AM!MTB"
        threat_id = "2147819317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RWHwy6R" ascii //weight: 2
        $x_2_2 = "lFJUNkxGhL" ascii //weight: 2
        $x_2_3 = "SetCurrentDirectoryA" ascii //weight: 2
        $x_2_4 = "uggy recover politeness" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AM_2147819317_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AM!MTB"
        threat_id = "2147819317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CoSetProxyBlanket" ascii //weight: 1
        $x_1_2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii //weight: 1
        $x_1_3 = "LdrAddx64.exe" ascii //weight: 1
        $x_1_4 = "ProcessLoad" ascii //weight: 1
        $x_1_5 = "objShell.Run \"my_application_path\"" ascii //weight: 1
        $x_1_6 = "Windows Photo Viewer\\ImagingDevices.exe" ascii //weight: 1
        $x_1_7 = "Windows Mail\\wab.exe" ascii //weight: 1
        $x_1_8 = "Z:\\hooker2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AA_2147819383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AA"
        threat_id = "2147819383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {b8 01 00 00 00 87 05 ?? ?? ?? ?? 83 f8 01 74 f0 48 83 3d ?? ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_10_3 = {33 c9 ba 58 02 00 00 41 b8 00 30 00 00 44 8d 49 04 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_DA_2147819462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DA!MTB"
        threat_id = "2147819462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iym324mr7.dll" ascii //weight: 1
        $x_1_2 = "WqpKlgNbCN" ascii //weight: 1
        $x_1_3 = "ZPvDzN715n" ascii //weight: 1
        $x_1_4 = "YVK077c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_DB_2147819531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DB!MTB"
        threat_id = "2147819531"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "cggojx289ci0.dll" ascii //weight: 10
        $x_10_2 = "amaefjj183xi.dll" ascii //weight: 10
        $x_10_3 = "slw189nj21.dll" ascii //weight: 10
        $x_1_4 = "IsSystemResumeAutomatic" ascii //weight: 1
        $x_1_5 = "QueryIdleProcessorCycleTime" ascii //weight: 1
        $x_1_6 = "DeleteFiber" ascii //weight: 1
        $x_1_7 = "IternalJob" ascii //weight: 1
        $x_1_8 = "SetPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BumbleBee_DC_2147819551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DC!MTB"
        threat_id = "2147819551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nwklrw884rg70.dll" ascii //weight: 1
        $x_1_2 = "QXYuok660" ascii //weight: 1
        $x_1_3 = "quBoNSmTSl" ascii //weight: 1
        $x_1_4 = "Mfr07A74" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AN_2147819637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AN!MTB"
        threat_id = "2147819637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "YVK077c" ascii //weight: 2
        $x_2_2 = "ZPvDzN715n" ascii //weight: 2
        $x_2_3 = "PeekNamedPipe" ascii //weight: 2
        $x_2_4 = "GetStdHandle" ascii //weight: 2
        $x_2_5 = "CreateFileA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AN_2147819637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AN!MTB"
        threat_id = "2147819637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BKuENphAxN" ascii //weight: 2
        $x_2_2 = "CreateFiber" ascii //weight: 2
        $x_2_3 = "HeapReAlloc" ascii //weight: 2
        $x_2_4 = "SetStdHandle" ascii //weight: 2
        $x_2_5 = "SetFilePointerEx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AG_2147819730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AG!MTB"
        threat_id = "2147819730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "oFWkRTFwjm" ascii //weight: 2
        $x_2_2 = "ant bearing" ascii //weight: 2
        $x_2_3 = "ransom treacherous" ascii //weight: 2
        $x_2_4 = "SwitchToFiber" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AG_2147819730_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AG!MTB"
        threat_id = "2147819730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Mfr07A74" ascii //weight: 2
        $x_2_2 = "QXYuok660" ascii //weight: 2
        $x_2_3 = "quBoNSmTSl" ascii //weight: 2
        $x_2_4 = "ConnectNamedPipe" ascii //weight: 2
        $x_2_5 = "DisconnectNamedPipe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BV_2147819927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BV!MTB"
        threat_id = "2147819927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DlZEUEB" ascii //weight: 2
        $x_2_2 = "RAXxyL88MD" ascii //weight: 2
        $x_1_3 = "GetStdHandle" ascii //weight: 1
        $x_1_4 = "CreateFileA" ascii //weight: 1
        $x_1_5 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_6 = "WaitNamedPipeA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_DD_2147819952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DD!MTB"
        threat_id = "2147819952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 c2 44 8b cf 48 8b 93 38 01 00 00 48 33 d0 48 63 c7 48 23 93 e8 02 00 00 48 3b c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_DD_2147819952_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DD!MTB"
        threat_id = "2147819952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qmt264tz3.dll" ascii //weight: 1
        $x_1_2 = "oFWkRTFwjm" ascii //weight: 1
        $x_1_3 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_6 = "SwitchToFiber" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EK_2147820356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EK!MTB"
        threat_id = "2147820356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PAoN2047" ascii //weight: 1
        $x_1_2 = "QZcv685w" ascii //weight: 1
        $x_1_3 = "CreateTask" ascii //weight: 1
        $x_1_4 = "LockFile" ascii //weight: 1
        $x_1_5 = "CreateFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EK_2147820356_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EK!MTB"
        threat_id = "2147820356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HnmzDB983O8l" ascii //weight: 1
        $x_1_2 = "OuvPd16" ascii //weight: 1
        $x_1_3 = "Qra3897" ascii //weight: 1
        $x_1_4 = "CreateFileW" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EK_2147820356_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EK!MTB"
        threat_id = "2147820356"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nHqRHTKVae" ascii //weight: 1
        $x_1_2 = "CreateFileMappingA" ascii //weight: 1
        $x_1_3 = "CreateNamedPipeA" ascii //weight: 1
        $x_1_4 = "WaitNamedPipeA" ascii //weight: 1
        $x_1_5 = "MapViewOfFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_DE_2147820438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.DE!MTB"
        threat_id = "2147820438"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uyhrw140wb3.dll" ascii //weight: 1
        $x_1_2 = "EVJb68J" ascii //weight: 1
        $x_1_3 = "TyfCn627" ascii //weight: 1
        $x_1_4 = "XuRMl636KaQf" ascii //weight: 1
        $x_1_5 = "ajwGwRKhLi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ME_2147820462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ME!MTB"
        threat_id = "2147820462"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 8b 85 c8 03 00 00 81 f1 cf 30 00 00 44 2b d1 41 8b ca d3 ea 8a 88 e0 01 00 00 49 8b 45 40 80 f1 38 22 d1 49 63 8d b0 03 00 00 88 14 01 41 ff 85 b0 03 00 00 45 85 d2 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BN_2147823118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BN!MTB"
        threat_id = "2147823118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ocqa75" ascii //weight: 1
        $x_1_2 = "QEpzKb6" ascii //weight: 1
        $x_1_3 = "UzduUOtRZB" ascii //weight: 1
        $x_1_4 = "CallNamedPipeA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BN_2147823118_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BN!MTB"
        threat_id = "2147823118"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IiYW9395F" ascii //weight: 1
        $x_1_2 = "Oigfx0w8" ascii //weight: 1
        $x_1_3 = "UHpwju3346NV" ascii //weight: 1
        $x_1_4 = "PjyJGGCvQs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BM_2147823544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BM!MTB"
        threat_id = "2147823544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FLAI3" ascii //weight: 1
        $x_1_2 = "GHjacudR" ascii //weight: 1
        $x_1_3 = "GxBlOO" ascii //weight: 1
        $x_5_4 = "SetVPACon" ascii //weight: 5
        $x_1_5 = "YClhj634fxgz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BM_2147823544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BM!MTB"
        threat_id = "2147823544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MloOEEiHj" ascii //weight: 1
        $x_1_2 = "PvhgOq" ascii //weight: 1
        $x_1_3 = "NyGlisDIKN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BM_2147823544_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BM!MTB"
        threat_id = "2147823544"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EWY72" ascii //weight: 1
        $x_1_2 = "QCYZn6747H" ascii //weight: 1
        $x_1_3 = "QOUXI31" ascii //weight: 1
        $x_1_4 = "RoOEiztJvW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_PACD_2147829602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.PACD!MTB"
        threat_id = "2147829602"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {43 8a 0c 0c 2a 8c 24 ?? ?? ?? ?? 32 8c 24 ?? ?? ?? ?? 49 8b 42 ?? 41 88 0c 01 83 fe ?? 0f 84 ?? ?? ?? ?? 49 8b 52 ?? 8b ce b8 ?? ?? ?? ?? 44 8b ee d2 e0 fe c8 41 8a 0c 11 49 8b 92 ?? ?? ?? ?? 22 c8 88 4c 24 ?? 48 8b c5}  //weight: 6, accuracy: Low
        $x_1_2 = "CgK62" ascii //weight: 1
        $x_1_3 = "LvqKMn698" ascii //weight: 1
        $x_1_4 = "ODIVN1Ad4" ascii //weight: 1
        $x_1_5 = "TncgHC876XY3" ascii //weight: 1
        $x_1_6 = "UQrAAa715Sp8" ascii //weight: 1
        $x_1_7 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BumbleBee_AB_2147830172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AB"
        threat_id = "2147830172"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_5_2 = {48 83 ec 38 31 d2 48 89 4c 24 30 48 8b 4c 24 30 48 89 c8 48 83 c0 10 48 89 4c 24 28 48 89 c1 41 b8 08 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 28 c7 00 01 23 45 67 c7 40 04 89 ab cd ef c7 40 08 fe dc ba 98 c7 40 0c 76 54 32 10 48 83 c4 38 c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_FA_2147830772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.FA!MTB"
        threat_id = "2147830772"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pipe\\boost_process_auto_pipe_" ascii //weight: 1
        $x_1_2 = "sys_version" ascii //weight: 1
        $x_1_3 = "System32\\wscript.exe" wide //weight: 1
        $x_1_4 = "SetPath" ascii //weight: 1
        $x_1_5 = "SELECT * FROM Win32_ComputerSystemProduct" ascii //weight: 1
        $x_1_6 = "ProcessHacker.exe" wide //weight: 1
        $x_1_7 = "ollydbg.exe" wide //weight: 1
        $x_1_8 = "ImmunityDebugger.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_WMS_2147831749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.WMS!MTB"
        threat_id = "2147831749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {4d 8b 81 70 03 00 00 49 63 81 34 05 00 00 49 63 91 30 05 00 00 41 8b 0c 80 41 31 0c 90 41 8b 89 4c 05 00 00 81 e1 1f 00 00 80 7d 07}  //weight: 10, accuracy: High
        $x_1_2 = "CSSCode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AD_2147831862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AD!MTB"
        threat_id = "2147831862"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b 81 d0 04 00 00 49 8b 89 90 03 00 00 48 05 d9 05 00 00 48 09 81 20 01 00 00 03 d6 49 8b 81 c0 01 00 00 8b 48 50 48 81 f1 cb 11 00 00 48 63 c2 48 3b c1 72 ca}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b 03 41 ff c0 48 35 c9 21 00 00 48 0b d0 49 63 c0 49 89 91 c8 01 00 00 41 8b 8a e0 00 00 00 41 2b ce 48 3b c1 76 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_PCA_2147833208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.PCA!MTB"
        threat_id = "2147833208"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 55 53 56 57 41 54 41 55 41 56 41 57 48 8d 6c 24 ?? 48 81 ec ?? ?? ?? ?? 8b d9 ff 15 ?? ?? ?? ?? bf ?? ?? ?? ?? 33 d2 48 8b c8 44 8b c7 ff 15 ?? ?? ?? ?? 44 8b c7 33 d2 48 8b c8 48 89 05 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ULS_2147833209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ULS!MTB"
        threat_id = "2147833209"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b ce 89 6c 24 28 4c 8b c6 41 8b d7 89 44 24 20 48 8b cf 41 ff d4}  //weight: 1, accuracy: High
        $x_1_2 = "CreateEvent" ascii //weight: 1
        $x_1_3 = "QOmPHh9WO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_PCC_2147833249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.PCC!MTB"
        threat_id = "2147833249"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b ce 89 74 24 28 4c 8b c5 41 8b d7 89 44 24 20 48 8b cf 41 ff d4}  //weight: 1, accuracy: High
        $x_1_2 = {4d 8b cf 44 89 74 24 28 4c 8b c5 41 8b d4 89 44 24 20 48 8b ce 41 ff d5}  //weight: 1, accuracy: High
        $x_1_3 = "CreateEvent" ascii //weight: 1
        $x_1_4 = "QOmPHh9WO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_BumbleBee_MAT_2147833551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.MAT!MTB"
        threat_id = "2147833551"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c9 41 8b d2 d3 ea 8a 88 ?? ?? ?? ?? 48 8b 43 ?? 80 f1 1c 22 d1 48 63 8b 04 01 00 00 88 14 01 48 c7 c0 ?? ?? ?? ?? ff 83 ?? ?? ?? ?? 48 2b 83 ?? ?? ?? ?? 48 01 83 ?? ?? ?? ?? 45 85 c9 75 ?? 48 8b 83 ?? ?? ?? ?? 49 83 c0 04 48 0d ?? ?? ?? ?? 48 89 83 ?? ?? ?? ?? 49 81 f8 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SC_2147833603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SC!MTB"
        threat_id = "2147833603"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 43 08 48 81 f1 ?? ?? ?? ?? 48 89 48 ?? 48 8b 43 ?? 4c ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? 8b 8b ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {44 8b 04 88 48 ?? ?? ?? ?? ?? ?? 44 03 ce 48 ?? ?? ?? ?? ?? ?? 44 01 04 88 44 3b 8b ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_3 = "HQLQyAOTfz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SD_2147833880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SD!MTB"
        threat_id = "2147833880"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b 86 b8 02 00 00 35 ?? ?? ?? ?? 44 0f af f8 49 63 cf 48 8b c1 49 0f af 86 ?? ?? ?? ?? 48 3b c8 0f 86 ?? ?? ?? ?? 41 8b be}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 94 24 c0 00 00 00 41 33 8e ?? ?? ?? ?? 44 0f af f9 49 8b 8e ?? ?? ?? ?? ff c2 48 81 c1 ?? ?? ?? ?? 48 63 c2 49 23 8e ?? ?? ?? ?? 89 94 24 ?? ?? ?? ?? 48 3b c1 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = "regtask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SE_2147834041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SE!MTB"
        threat_id = "2147834041"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 e3 22 23 00 00 81 f2 ?? ?? ?? ?? 44 89 6d ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? c7 45 ef ?? ?? ?? ?? c7 45 eb ?? ?? ?? ?? 3b ca 77}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 88 e0 02 00 00 48 ?? ?? ?? ?? ?? ?? 49 8b 87 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 8b 87 ?? ?? ?? ?? 41 bb ?? ?? ?? ?? 4d 8b 4f ?? 69 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 8b 89}  //weight: 1, accuracy: Low
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SF_2147834068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SF!MTB"
        threat_id = "2147834068"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 8b c2 48 31 83 ?? ?? ?? ?? 48 8b 43 ?? 48 ?? ?? ?? ?? ?? ?? 48 01 8b ?? ?? ?? ?? 48 8b 83 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 83 e9 ?? 41 ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 82 48 01 00 00 48 ?? ?? ?? ?? ?? ?? 48 0f af c1 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 4c ?? ?? ?? ?? ?? ?? 41 ?? ?? 48 c7 80 ?? ?? ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = "KJtYlq" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SG_2147834150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SG!MTB"
        threat_id = "2147834150"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 07 48 0d ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 49 81 bd ?? ?? ?? ?? ?? ?? ?? ?? 74 ?? 49 8b 85 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 41 ba ?? ?? ?? ?? 4d ?? ?? ?? ?? ?? ?? 69 ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 8b 88 ?? ?? ?? ?? 41 03 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "regtask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EA_2147834380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EA!MTB"
        threat_id = "2147834380"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LdrAddx64.dll" ascii //weight: 1
        $x_1_2 = "aCmHmjrptS" ascii //weight: 1
        $x_1_3 = "SetPath" ascii //weight: 1
        $x_1_4 = "Z:\\hooker2" wide //weight: 1
        $x_1_5 = "CreateDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAB_2147834674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAB!MTB"
        threat_id = "2147834674"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 48 ?? ?? ?? ?? ?? ?? 42 31 04 21 49 83 c4 ?? 8b 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAC_2147834782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAC!MTB"
        threat_id = "2147834782"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 89 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 01 43 ?? 8b 8b ?? ?? ?? ?? 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 48 ?? ?? ?? ?? ?? ?? 31 04 11 48 ?? ?? ?? 8b 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAD_2147834846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAD!MTB"
        threat_id = "2147834846"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 8b 04 01 00 00 8d 41 ?? 31 43 ?? 8d 04 4d ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 48 ?? ?? ?? ?? ?? ?? 42 ?? ?? ?? 49 83 c1 ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAE_2147835123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAE!MTB"
        threat_id = "2147835123"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 48 8b 8b ?? ?? ?? ?? 01 43 ?? 8b 83 ?? ?? ?? ?? 42 ?? ?? ?? 49 83 c0 ?? 8b 8b ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 33 43 ?? 83 f0 ?? 89 43 ?? 8b 83 ?? ?? ?? ?? 01 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAF_2147835273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAF!MTB"
        threat_id = "2147835273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b c8 8b 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 44 ?? ?? ?? ?? ?? ?? 33 c8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c1 8b 0d ?? ?? ?? ?? 33 ca 89 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 c8 b8 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_BumbleBee_SAG_2147835274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAG!MTB"
        threat_id = "2147835274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 33 8b ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 03 8b 93 ?? ?? ?? ?? 33 93 ?? ?? ?? ?? 0f af c1 81 ea ?? ?? ?? ?? 01 93 ?? ?? ?? ?? 89 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAI_2147835694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAI!MTB"
        threat_id = "2147835694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 43 70 48 ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 83 ?? ?? ?? ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 01 43 ?? 48 ?? ?? ?? ?? ?? ?? 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAJ_2147835788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAJ!MTB"
        threat_id = "2147835788"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 ff 83 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 44 ?? ?? ?? 8b 83 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 8b 4b ?? 35 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 33 43 ?? 8b 93}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAK_2147836364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAK!MTB"
        threat_id = "2147836364"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 ff 43 ?? 8b 43 ?? 2b 43 ?? 48 ?? ?? ?? 05 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 8b 43 ?? 2b 83 ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 43 ?? 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAL_2147836720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAL!MTB"
        threat_id = "2147836720"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 01 49 ff 82 ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 33 c1 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 48 69 81 ?? ?? ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAM_2147836814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAM!MTB"
        threat_id = "2147836814"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 8b 0c 19 49 ?? ?? ?? 8b 48 ?? 2b 48 ?? 33 88 ?? ?? ?? ?? 44 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 89 88}  //weight: 1, accuracy: Low
        $x_1_2 = {44 88 0c 0a ff 40 ?? 8b 88 ?? ?? ?? ?? 8b 50 ?? 83 e9 ?? 01 48 ?? 81 c2 ?? ?? ?? ?? 03 50 ?? 31 ?? ?? ?? ?? ?? 49 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAN_2147836815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAN!MTB"
        threat_id = "2147836815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 83 ?? ?? ?? ?? 31 4b ?? 35 ?? ?? ?? ?? 01 43 ?? b8 ?? ?? ?? ?? 2b 03 01 83}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c2 2b 43 ?? 01 83 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 83 ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAO_2147836982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAO!MTB"
        threat_id = "2147836982"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 11 48 ?? ?? ?? 8b 83 ?? ?? ?? ?? 01 43 ?? 8b 43 ?? 83 e8 ?? 31 83 ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JK_2147837185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JK!MTB"
        threat_id = "2147837185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 01 2d ?? ?? ?? ?? 8b 4b ?? 33 8b ?? ?? ?? ?? 2b c1 01 05 ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 43 ?? 8b 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? 09 83 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JK_2147837185_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JK!MTB"
        threat_id = "2147837185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 41 b8 00 30 00 00 8b 53 ?? 44 8d 49 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 82 94 00 00 00 35 ?? ?? ?? ?? 2b c8 48 8d 05 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 48 89 42 ?? 89 4a}  //weight: 1, accuracy: Low
        $x_1_3 = "VIDRVState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAP_2147837625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAP!MTB"
        threat_id = "2147837625"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 2b c0 44 ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 31 43 ?? 8d 82 ?? ?? ?? ?? 44 ?? ?? ?? ff 43 ?? 0f af c8 41 ?? ?? ?? ?? ?? ?? 89 4b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAQ_2147838025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAQ!MTB"
        threat_id = "2147838025"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c6 44 33 e0 69 c5 ?? ?? ?? ?? 48 ?? ?? 41 ?? ?? 33 43 ?? 48 ?? ?? ?? 2b e8 8b 43}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 0f af 83 ?? ?? ?? ?? 33 cd 23 4b ?? 41 ?? ?? ?? 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAR_2147839597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAR!MTB"
        threat_id = "2147839597"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 0f b6 c9 48 ?? ?? ?? ?? 0f b6 4c 0a 02 48 ?? ?? ?? ?? 0f b6 04 02 33 c1 48 ?? ?? ?? ?? 48 ?? ?? ?? ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EB_2147840386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EB!MTB"
        threat_id = "2147840386"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uvf180te6.dll" ascii //weight: 1
        $x_1_2 = "JzGbEU8m" ascii //weight: 1
        $x_1_3 = "QUk024" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "RtlLookupFunctionEntry" ascii //weight: 1
        $x_1_6 = "RtlVirtualUnwind" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_IDA_2147840401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.IDA!MTB"
        threat_id = "2147840401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 0f 1f 44 00 00 8b 8b ?? ?? ?? ?? 8b 83 ?? ?? ?? ?? 83 f1 ?? 0f af c1 48 63 4b ?? 89 83 ?? ?? ?? ?? 48 8b 43 ?? 45 8b 04 01 49 83 c1 ?? 44 0f af 43 ?? 48 8b 83 ?? ?? ?? ?? 41 8b d0 c1 ea ?? 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_CD_2147840558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.CD!MTB"
        threat_id = "2147840558"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8b 04 01 49 83 c1 04 8b 86 38 01 00 00 44 0f af 46 54 0f af c1 41 8b d0 89 86 38 01 00 00 8b 86 d8 00 00 00 35 f7 bf 37 5b c1 ea 10 29 86 00 01 00 00 48 63 4e 74 48 8b 86 90 00 00 00 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAT_2147841287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAT!MTB"
        threat_id = "2147841287"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 31 4b ?? 8b 83 ?? ?? ?? ?? 8b 4b ?? 05 ?? ?? ?? ?? 03 4b ?? 03 c8 48 ?? ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 45 ?? ?? 89 4b ?? 8b 83 ?? ?? ?? ?? 03 43 ?? 35 ?? ?? ?? ?? 09 43 ?? 8b 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAU_2147841288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAU!MTB"
        threat_id = "2147841288"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 04 0a 48 ?? ?? ?? 8b 8f ?? ?? ?? ?? 8b c1 44 ?? ?? ?? ?? ?? ?? 41 ?? ?? 2d ?? ?? ?? ?? 09 87 ?? ?? ?? ?? 8d 41 ?? 8b 8f ?? ?? ?? ?? 0f af c8 89 8f ?? ?? ?? ?? 8b 8f ?? ?? ?? ?? 01 8f ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAV_2147841447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAV!MTB"
        threat_id = "2147841447"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 31 8b ?? ?? ?? ?? 8b 4b ?? 48 ?? ?? ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 d1 45 ?? ?? ?? 49 ?? ?? ?? 8b 83 ?? ?? ?? ?? 44 ?? ?? ?? ?? 0f af c2 41 ?? ?? 89 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAW_2147841448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAW!MTB"
        threat_id = "2147841448"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 31 4b ?? 8b 4b ?? 8b 43 ?? 83 e9 ?? 0f af c1 41 ?? ?? c1 ea ?? 89 43}  //weight: 1, accuracy: Low
        $x_1_2 = {ff c1 0f af c1 8b 8b ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 43 ?? 8b 83 ?? ?? ?? ?? 0f af c1 89 83 ?? ?? ?? ?? 49 ?? ?? ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SAY_2147842218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SAY!MTB"
        threat_id = "2147842218"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c1 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 41 ?? ?? ?? 41 ?? ?? ?? ?? ?? ?? 83 e8 ?? 41 ?? ?? ?? 49 ?? ?? ?? 49 ?? ?? ?? 46 ?? ?? ?? 49 ?? ?? ?? 45 ?? ?? ?? ?? 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_CAFK_2147845477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.CAFK!MTB"
        threat_id = "2147845477"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 5c 24 08 43 0f b6 0c 19 89 ca 83 f2 ff 81 e2 ?? ?? ?? ?? be ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 21 f1 89 c7 83 f7 ff 81 e7 ?? ?? ?? ?? 21 f0 09 ca 09 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ZA_2147847159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ZA!MTB"
        threat_id = "2147847159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 a0 be a2 b6 7d 46 5d 95 4f 2e d5 ed 95 50 de b6 df dc 05 8a e5 95 cd d5 62 32 ec 19 80 be e8 d7 ba ce 96 38 c7 33 7d 83 4c f1 a5 b9 bb cb b5 35 8d d3 39 15 55 9d 94 c2 86 fb 1f 13 a1 77 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ZA_2147847159_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ZA!MTB"
        threat_id = "2147847159"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 ?? 48 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b 04 81 33 c2 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 48 8b 92 ?? ?? ?? ?? 89 04 8a b8 ?? ?? ?? ?? 48 6b c0 ?? 48 8d 0d ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 8b 52 ?? 81 ea ?? ?? ?? ?? 8b 04 01 2b c2 b9 ?? ?? ?? ?? 48 6b c9 ?? 48 8d 15 ?? ?? ?? ?? 89 04 0a b8 ?? ?? ?? ?? 48 6b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_EM_2147847199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.EM!MTB"
        threat_id = "2147847199"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 89 c4 00 00 00 0f af c8 8b c1 48 8b 8c 24 20 01 00 00 89 81 c4 00 00 00 8b 44 24 5c 0f af 44 24 54 0f af 44 24 50 48 8b 8c 24 20 01 00 00 8b 89}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_CRUN_2147848673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.CRUN!MTB"
        threat_id = "2147848673"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" wide //weight: 1
        $x_1_2 = "ProcessHacker.exe" wide //weight: 1
        $x_1_3 = "procmon.exe" wide //weight: 1
        $x_1_4 = "idaq64.exe" wide //weight: 1
        $x_1_5 = "Wireshark.exe" wide //weight: 1
        $x_1_6 = "windbg.exe" wide //weight: 1
        $x_1_7 = "x64dbg.exe" wide //weight: 1
        $x_1_8 = "VIRTUALBOX" wide //weight: 1
        $x_1_9 = "HARDWARE\\ACPI\\DSDT\\VBOX" wide //weight: 1
        $x_1_10 = "SELECT * FROM Win32_ComputerSystemProduct" ascii //weight: 1
        $x_1_11 = "SELECT * FROM Win32_ComputerSystem" ascii //weight: 1
        $x_1_12 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AZ_2147849203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AZ!MTB"
        threat_id = "2147849203"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8b 04 01 49 83 c1 04 44 0f af 83 90 00 00 00 48 8b 83 08 01 00 00 41 8b d0 c1 ea 10 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_TM_2147849420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.TM!MTB"
        threat_id = "2147849420"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 31 04 18 48 83 c3 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ZB_2147889345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ZB!MTB"
        threat_id = "2147889345"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 02 33 4b ?? 48 8b 83 ?? ?? ?? ?? 89 0c 02 48 83 c2 04 8b 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 31 8b ?? ?? ?? ?? 48 81 fa ?? ?? ?? ?? 7c 60 00 48 8b 05 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 0f af 48 ?? 89 8b ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_PC_2147899745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.PC!MTB"
        threat_id = "2147899745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USk5" ascii //weight: 1
        $x_1_2 = "IePFl" ascii //weight: 1
        $x_1_3 = "BtH14i" ascii //weight: 1
        $x_1_4 = "SGBNFa0" ascii //weight: 1
        $x_1_5 = "BnkcQ8bBX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_HJ_2147899929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.HJ!MTB"
        threat_id = "2147899929"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 89 5c 24 ?? 44 8b 88 ?? ?? ?? ?? 44 2b 4b ?? 44 03 8b ?? ?? ?? ?? 44 8b 80 ?? ?? ?? ?? 44 0f af c2 8b 93 ?? ?? ?? ?? 33 93 ?? ?? ?? ?? 44 89 54 24 ?? 81 e2 ?? ?? ?? ?? 44 89 4c 24 ?? 4c 8b cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ZC_2147901896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ZC!MTB"
        threat_id = "2147901896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 2b c8 49 0b 8c 24 40 01 00 00 48 03 c8 49 8b 84 24 98 03 00 00 49 03 84 24 d0 04 00 00 49 33 84 24 30 03 00 00 49 33 04 24 49 89 84 24 30 03 00 00 49 89 8c 24 70 04 00 00 8b 4d ff}  //weight: 1, accuracy: High
        $x_1_2 = "EPTsswwiRJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_HK_2147902496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.HK!MTB"
        threat_id = "2147902496"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 44 33 db 4c 89 54 24 ?? 4c 23 c0 49 8b cc 44 89 5c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 83 c6 ?? 2b 88 ?? ?? ?? ?? 41 2b ce 31 0d ?? ?? ?? ?? 41 3b f7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_HL_2147902572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.HL!MTB"
        threat_id = "2147902572"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 14 0a ff 40 ?? 48 8b 0d ?? ?? ?? ?? 8b 91 ?? ?? ?? ?? 2b ?? ?? ?? ?? ?? 8b 48 ?? 83 f2 ?? 0f af ca 89 48 ?? 48 8b 0d ?? ?? ?? ?? 8b 51 ?? 2b ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 31 50 ?? 48 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_HM_2147902795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.HM!MTB"
        threat_id = "2147902795"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 b8 ?? ?? ?? ?? ff 05 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? 01 83 ?? ?? ?? ?? 48 8b 43 ?? 48 63 0d ?? ?? ?? ?? 44 88 0c 01 ff 05 ?? ?? ?? ?? 48 8b 15 ?? ?? ?? ?? 8b 4a ?? 33 8b ?? ?? ?? ?? 8b 82 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 0f af c1 89 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_LA_2147903557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.LA!MTB"
        threat_id = "2147903557"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b ce 83 64 24 ?? ?? 49 8b e8 48 81 f5 ?? ?? ?? ?? 41 81 c0 ?? ?? ?? ?? 48 8b d5}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 6c 24 ?? 48 8b 74 24 ?? 48 29 98 ?? ?? ?? ?? 49 8b 8f ?? ?? ?? ?? 49 8b 87 ?? ?? ?? ?? 48 8b 5c 24 ?? 48 2b c7 48 31 81 ?? ?? ?? ?? 49 8b 87 ?? ?? ?? ?? 49 8b 8f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_LB_2147903626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.LB!MTB"
        threat_id = "2147903626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 8b 45 08 49 8b 95 ?? ?? ?? ?? 48 69 88 ?? ?? ?? ?? ?? ?? ?? ?? 48 01 8a ?? ?? ?? ?? 49 8b 45 ?? 49 8b 8d ?? ?? ?? ?? 48 81 f1 ?? ?? ?? ?? 48 89 88 ?? ?? ?? ?? 49 8b 8d ?? ?? ?? ?? 48 69 81 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 81 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BL_2147903627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BL!MTB"
        threat_id = "2147903627"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8a fc 49 01 80 ?? ?? ?? ?? 49 8b 80 ?? ?? ?? ?? 48 2d ?? ?? ?? ?? 48 31 81 ?? ?? ?? ?? 41 8d 4f ?? 41 8a 80 ?? ?? ?? ?? 40 d2 ef 34 ?? 40 22 f8 49 8b 80 ?? ?? ?? ?? 48 8b 88}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JT_2147905137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JT!MTB"
        threat_id = "2147905137"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 48 8b 05 ?? ?? ?? ?? ff 80 ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 8b ?? ?? ?? ?? 33 4b ?? 2b c1 01 83 ?? ?? ?? ?? 8b 83}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af c8 89 8a ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 33 83 ?? ?? ?? ?? 2d ?? ?? ?? ?? 09 41 ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_KJ_2147905980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.KJ!MTB"
        threat_id = "2147905980"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 0a 41 ff 81 ?? ?? ?? ?? 41 8b 49 ?? 41 33 89 ?? ?? ?? ?? 2b c1 41 01 81 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 41 8b 81 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 41 31 49 ?? 05 ?? ?? ?? ?? 09 05 ?? ?? ?? ?? 41 8b 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_TK_2147907238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.TK!MTB"
        threat_id = "2147907238"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c9 0f af c1 89 05 ?? ?? ?? ?? b8 ?? ?? ?? ?? 41 2b 42 ?? 41 01 42 ?? 48 8b 0d ?? ?? ?? ?? 8b 81 ?? ?? ?? ?? 29 81 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? 0f af c8 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_MKB_2147909747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.MKB!MTB"
        threat_id = "2147909747"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 8b 84 24 64 02 00 00 44 8b 8c 24 9c 02 00 00 44 8b 94 24 a0 02 00 00 44 8b 9c 24 a4 02 00 00 48 8b 8c 24 48 02 00 00 48 8d 94 24 98 02 00 00 44 89 84 24 20 02 00 00 45 89 d8 44 89 8c 24 1c 02 00 00 45 89 d1 44 8b 94 24 1c 02 00 00 44 89 54 24 20 44 8b 94 24 20 02 00 00 44 89 54 24 28 c7 44 24 30 0c 00 00 00 c7 44 24 38 2a c6 87 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JF_2147909801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JF!MTB"
        threat_id = "2147909801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 63 c0 0f b7 05 ?? ?? ?? ?? 41 0f af c1 41 ff c1 99 42 f7 3c 81 41 89 02 4d 8d 52 ?? 4c 8b 05}  //weight: 1, accuracy: Low
        $x_1_2 = {41 0f b6 0e 48 8d 04 4e 32 1c 01 41 0f b6 00 4d 8d 40 ?? 49 0b c1 49 89 04 d3 48 ff c2 49 3b d2 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JH_2147910136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JH!MTB"
        threat_id = "2147910136"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 ff 43 ?? 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? ff c9 01 8b ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 48 ?? 33 8b ?? ?? ?? ?? 83 e9 ?? 09 8b ?? ?? ?? ?? 49 81 f9 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_JI_2147910787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.JI!MTB"
        threat_id = "2147910787"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 88 04 01 ff 05 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 33 88 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 01 8b ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 8b 88 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 03 4b ?? 01 8b ?? ?? ?? ?? 48 8b 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_TJ_2147912607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.TJ!MTB"
        threat_id = "2147912607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d fe 49 8d 0c 2e 48 8b 87 ?? ?? ?? ?? 48 03 cf 8b 50 ?? 48 8b 87 ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 89 94 01 ?? ?? ?? ?? 48 8d 8f ?? ?? ?? ?? 48 8b 87}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 63 c5 48 c7 80 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 87 ?? ?? ?? ?? 48 35 ?? ?? ?? ?? 4c 3b c0 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_FEM_2147920051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.FEM!MTB"
        threat_id = "2147920051"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff c0 48 63 c8 48 8b 44 24 60 ff c3 42 0f b6 8c 01 d0 89 01 00 48 ff c2 42 32 8c 02 4f 8a 01 00 88 4c 02 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_OKZ_2147921717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.OKZ!MTB"
        threat_id = "2147921717"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 05 8e a0 04 00 48 8b 0d bb a0 04 00 31 04 31 48 83 c6 04 4c 8b 05 15 a0 04 00 8b 05 af a0 04 00 01 05 6d a0 04 00 8b 15 e7 a0 04 00 01 15 51 a0 04 00 41 8b 48 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_AMZ_2147922783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.AMZ!MTB"
        threat_id = "2147922783"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 4f 40 8b 8f 8c 00 00 00 48 8b 05 f6 f8 09 00 2b 48 2c 83 f1 f8 01 8f 18 01 00 00 44 0f af 87 84 00 00 00 48 63 0d 7b f9 09 00 48 8b 05 d4 f9 09 00 41 8b d0 c1 ea 10 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_FOR_2147923307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.FOR!MTB"
        threat_id = "2147923307"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 83 88 00 00 00 45 8b 04 01 49 83 c1 04 48 8b 05 8a d3 03 00 8b 88 c0 00 00 00 81 e9 f8 c1 15 00 01 4b 5c 48 63 4b 70 44 0f af 43 6c 48 8b 83 90 00 00 00 41 8b d0 c1 ea 08 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_KYI_2147923886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.KYI!MTB"
        threat_id = "2147923886"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 0f af 41 54 48 63 4b 74 41 8b d0 c1 ea 10 88 14 01 41 8b d0 ff 43 74 48 63 4b 74 48 8b 05 00 79 18 00 c1 ea 08 88 14 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_ZZ_2147924578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.ZZ!MTB"
        threat_id = "2147924578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 00 10 a3 dc 81 00 10 83 3d d8 81 00 10 00 75 10 68 34 63 00 10 ff 15 34 60 00 10 a3 d8 81 00 10 68 48 63 00 10 8b 15 d8 81 00 10 52 ff 15 1c 60 00 10 a3 04 82 00 10 68 5c 63 00 10 a1 d8 81 00 10 50 ff 15 1c 60 00 10 a3 10 82 00 10 68 6c 63 00 10 8b 0d d8 81 00 10 51 ff 15 1c 60 00 10 a3 08 82 00 10 68 7c 63 00 10 8b 15 d8 81 00 10 52 ff 15 1c 60 00 10 a3 fc 81 00 10 68 88 63 00 10 a1 d8 81 00 10 50 ff 15 1c 60 00 10 a3 18 82 00 10 68 90 63 00 10 8b 0d d8 81 00 10 51}  //weight: 1, accuracy: High
        $x_1_2 = {ff 15 1c 60 00 10 a3 1c 82 00 10 68 a8 63 00 10 8b 15 d8 81 00 10 52 ff 15 1c 60 00 10 a3 20 82 00 10 68 c0 63 00 10 a1 d8 81 00 10 50 ff 15 1c 60 00 10 a3 24 82 00 10 68 cc 63 00 10 8b 0d dc 81 00 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_MBWA_2147926110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.MBWA!MTB"
        threat_id = "2147926110"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 63 c8 48 8b 05 ?? ?? ?? ?? 44 ?? ?? ?? ff 05 ?? ?? ?? ?? 8b 05 ?? ?? ?? ?? ff c8 31 05 ?? ?? ?? ?? 49 81 fb ?? ?? ?? ?? 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = {2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 59 59 52 39 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BPD_2147927755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BPD!MTB"
        threat_id = "2147927755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 8b 0c 02 49 83 c2 04 44 0f af 4f 64 8b 05 c9 c8 0d 00 2b 82 94 00 00 00 2d 83 f4 26 00 09 42 6c 48 8b 05 60 c8 0d 00 45 8b c1 48 63 15 d6 c8 0d 00 41 c1 e8 08 48 8b 88 a0 00 00 00 44 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_SHL_2147935875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.SHL!MTB"
        threat_id = "2147935875"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 89 b3 88 00 22 00 49 81 83 90 00 22 00 a6 fe 00 00 49 8b b3 88 00 22 00 48 81 c4 48 00 00 00 49 bc 78 04 36 b4 02 03 81 4b 4c 29 e6 4c 01 de 48 ff e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_TL_2147940840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.TL!MTB"
        threat_id = "2147940840"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 bd bb bb 54 a7 f8 f7 51 92 49 ba 00 c4 17 00 00 00 00 00 44 30 2e 48 81 c6 01 00 00 00 49 81 c5 1c 77 11 09 49 81 ea 01 00 00 00 0f 85 e2 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BumbleBee_BH_2147941332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BumbleBee.BH!MTB"
        threat_id = "2147941332"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BumbleBee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 8b 00 48 33 c1 48 89 84 24 ?? ?? 00 00 8b 84 24 ?? ?? 00 00 99 48 8b 8c 24 ?? ?? 00 00 f7 39 48 8b 8c 24 ?? ?? 00 00 89 01}  //weight: 2, accuracy: Low
        $x_2_2 = {48 03 c8 48 8b c1 48 89 84 24 ?? 00 00 00 48 8b 44 24 ?? 0f bf 00 0f bf 4c 24 ?? 33 c1 48 8b 4c 24 ?? 66 89 01 48}  //weight: 2, accuracy: Low
        $x_1_3 = "lW6z\\Machopolyp\\Coyish\\8jFmgk\\dQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

