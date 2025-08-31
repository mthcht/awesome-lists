rule Trojan_Win32_Staser_DHA_2147752692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.DHA!MTB"
        threat_id = "2147752692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 60 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 89 0d 02 a1 ?? ?? ?? ?? 2b 05 02 a3 ?? ?? ?? ?? 8b 85 01 99 b9 40 42 0f 00 f7 f9 85 d2 75 21 8b 85 ?? ?? ?? ?? 83 c0 03 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 03 85 01 89 85 ?? ?? ?? ?? eb 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RTA_2147798844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RTA!MTB"
        threat_id = "2147798844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 53 83 ec 0c 8b 5d 14 6a 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_CD_2147811619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.CD!MTB"
        threat_id = "2147811619"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 c9 f6 d5 33 5c 24 04 80 d9 [0-4] f6 d9 8b cf e9}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_BB_2147818041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.BB!MTB"
        threat_id = "2147818041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 08 8b 10 31 15 [0-4] c7 45 d8 01 00 00 00 eb 10}  //weight: 2, accuracy: Low
        $x_2_2 = {33 4a 01 bb d0 f6 46 00 3b c8 75 24}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_PEF_2147826863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.PEF!MTB"
        threat_id = "2147826863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2}  //weight: 5, accuracy: High
        $x_5_2 = {3d 47 65 6e 75 75 1b 8b 45 f0 3d 69 6e 65 49 75 11 8b 45 ec 3d 6e 74 65 6c}  //weight: 5, accuracy: High
        $x_5_3 = {8b 84 24 00 02 00 00 83 c8 40 89 84 24 00 02 00 00 0f ae 94 24 00 02 00 00 81 c4 08 02 00 00}  //weight: 5, accuracy: High
        $x_1_4 = "@.selb" ascii //weight: 1
        $x_1_5 = ".sela" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Staser_HQ_2147827352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.HQ!MTB"
        threat_id = "2147827352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 0f a2 89 45 fc 89 5d f8 89 4d ec 89 55 f0 b8 01 00 00 00 0f a2}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f8 3d 47 65 6e 75 75 1b 8b 45 f0 3d 69 6e 65 49 75 11 8b 45 ec 3d 6e 74 65 6c}  //weight: 1, accuracy: High
        $x_1_3 = "@.virt" ascii //weight: 1
        $x_1_4 = "AlphaBlend" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_ER_2147828894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.ER!MTB"
        threat_id = "2147828894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 d3 04 0f bb fb 1c ?? 66 0f ba fa ?? 8d 76 05 2b 5d e6 1b 4d f0}  //weight: 5, accuracy: Low
        $x_1_2 = "@.vlizer" ascii //weight: 1
        $x_1_3 = "DiskInfoA" ascii //weight: 1
        $x_1_4 = "CreateILockBytesOnHGlobal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_NE_2147831769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.NE!MTB"
        threat_id = "2147831769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "sggkmnnoppqqrrssu" ascii //weight: 5
        $x_5_2 = "srliloqtvu" ascii //weight: 5
        $x_5_3 = "ykghjkkknruz" ascii //weight: 5
        $x_4_4 = "LdrRegisterDllNotificatio" ascii //weight: 4
        $x_4_5 = "ApiSetQueryApiSetPresence" ascii //weight: 4
        $x_4_6 = "Sub3DiskOpenA" ascii //weight: 4
        $x_4_7 = "RegisterClipboardFormatA" ascii //weight: 4
        $x_3_8 = "SMTPFromNL" ascii //weight: 3
        $x_3_9 = "fication" ascii //weight: 3
        $x_3_10 = "GetDCEx" ascii //weight: 3
        $x_2_11 = "GetClipboardData" ascii //weight: 2
        $x_2_12 = "GetTickCount" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_GKU_2147835859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.GKU!MTB"
        threat_id = "2147835859"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 00 83 e0 0f 33 c2 0f b6 db 33 c3 83 f8 72 75 ?? 33 c0 5b 5e c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_NEAA_2147835909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.NEAA!MTB"
        threat_id = "2147835909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5d 89 1c 24 bb 04 00 00 00 01 d8 5b 53 57 ff 74 24 04 5f 8f 04 24 57 ff 0c 24 5f 31 3c 24 33 3c 24 31 3c 24 5b e9 99 ff ff ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_EN_2147836949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.EN!MTB"
        threat_id = "2147836949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 56 53 8b 75 14 8d 85 d8 f9 ff ff 0c 01 56 ff 15 ?? ?? ?? ?? 6a 14 6a 40 ff 15 ?? ?? ?? ?? 8b d8 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_NEAB_2147836981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.NEAB!MTB"
        threat_id = "2147836981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "kOwA#OwDdOw" ascii //weight: 5
        $x_5_2 = "TOwqlOw" ascii //weight: 5
        $x_5_3 = ".dmc102" ascii //weight: 5
        $x_5_4 = "PhotoRenamer.exe" wide //weight: 5
        $x_5_5 = "4.1.3.102" wide //weight: 5
        $x_5_6 = "TGMDev" wide //weight: 5
        $x_1_7 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_EH_2147837118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.EH!MTB"
        threat_id = "2147837118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 8b 75 14 3b 7d 0c a9 00 00 80 00 56}  //weight: 7, accuracy: High
        $x_1_2 = "GetKeyboardLayoutNameA" ascii //weight: 1
        $x_1_3 = "GetKeyboardState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RB_2147838339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RB!MTB"
        threat_id = "2147838339"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 e8 ?? ?? ?? ?? 59 ff 75 14 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 05 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 59 a3 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 31 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 c0 50 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RI_2147842345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RI!MTB"
        threat_id = "2147842345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 6a 29 ff 15 dc 93 65 00 85 c0 a3 e0 ca 65 00 74 0a 8b 45 14 50 ff 15 58 90 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RJ_2147842346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RJ!MTB"
        threat_id = "2147842346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff 15 68 95 65 00 a1 e0 ca 65 00 85 c0 74 13 68 a8 bb 45 01 56 ff 15 5c 90 65 00 56 ff 15 58 90 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RK_2147842544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RK!MTB"
        threat_id = "2147842544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 b8 01 00 00 00 59 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RK_2147842544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RK!MTB"
        threat_id = "2147842544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 06 58 ff 75 08 57 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RK_2147842544_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RK!MTB"
        threat_id = "2147842544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec ff 15 d8 63 65 00 6a ff 6a 00 6a 00 ff 15 c8 66 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RK_2147842544_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RK!MTB"
        threat_id = "2147842544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 14 50 ff 15 78 66 65 00 6a 00 6a 00 ff 15 9c 66 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RK_2147842544_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RK!MTB"
        threat_id = "2147842544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 f6 c4 01 b8 0c 01 0b 80 ff 35 3c 44 08 01 ff 15 b0 f3 46 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RL_2147842545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RL!MTB"
        threat_id = "2147842545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 56 8b 75 14 56 ff 15 34 66 65 00 6a 00 6a 00 ff 15 0c 63 65 00 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RL_2147842545_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RL!MTB"
        threat_id = "2147842545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3b 7d 0c a9 00 00 80 00 ff 75 14 e8 ?? 8f 06 00 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RL_2147842545_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RL!MTB"
        threat_id = "2147842545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 6a 01 56 ff 15 20 f0 46 00 56 ff 15 74 f0 46 00 ff 15 18 f0 46 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RE_2147842688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RE!MTB"
        threat_id = "2147842688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 6a 03 33 c0 33 db 90 59 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RE_2147842688_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RE!MTB"
        threat_id = "2147842688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 8b 44 24 10 8b f1 85 c0 6a 14 6a 40 ff 15 ?? ?? 46 00 8b f0 6a 01 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RF_2147842689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RF!MTB"
        threat_id = "2147842689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 33 ff 3b c7 33 c0 59 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RG_2147842690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RG!MTB"
        threat_id = "2147842690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 0c 01 b8 02 00 00 00 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RH_2147842691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RH!MTB"
        threat_id = "2147842691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3d 02 01 00 00 0c 01 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RM_2147843687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RM!MTB"
        threat_id = "2147843687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 6a 00 6a 00 ff 15 78 f4 46 00 ff 15 70 f0 46 00 e9}  //weight: 5, accuracy: High
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RO_2147843970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RO!MTB"
        threat_id = "2147843970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 [0-16] 8b 75 14 56 ff 15 ?? ?? 46 00 56 ff 15 ?? ?? 46 00 3d ?? ?? ?? ?? 5e 75 05 e8 ?? 29 ff ff e9}  //weight: 5, accuracy: Low
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
        $x_1_3 = "Acebyte" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RP_2147843971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RP!MTB"
        threat_id = "2147843971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 ff 15 ?? f0 46 00 8b 75 14 68 50 2c 27 01 56 ff 15 ?? f0 46 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RQ_2147843972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RQ!MTB"
        threat_id = "2147843972"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 68 50 3c 27 01 56 ff 15 68 f0 46 00 56 ff 15 5c f6 46 00 6a 00 6a 00 ff 15 58 f6 46 00}  //weight: 5, accuracy: High
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RS_2147844003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RS!MTB"
        threat_id = "2147844003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 8b 45 14 50 e8 fc 44 04 00 85 c0 74 05 e8 6b d7 00 00 e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_ASR_2147845733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.ASR!MTB"
        threat_id = "2147845733"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c7 8b cf c1 f8 05 83 e1 1f 8b 04 85 e0 68 08 01 8d 04 c8 8b 0b 89 08 8a 4d 00 88 48 04 47 45 83 c3 04 3b fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_RR_2147846402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.RR!MTB"
        threat_id = "2147846402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 56 8b 75 14 68 50 ?? 27 01 56 ff 15 ?? f0 46 00 56 ff 15 ?? f6 46 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "ShutdownScheduler.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_ARA_2147846442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.ARA!MTB"
        threat_id = "2147846442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 64 24 00 8b 96 ?? ?? ?? ?? 8a 14 0a 32 96 ?? ?? ?? ?? 41 88 54 01 ff 3b 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_BW_2147846456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.BW!MTB"
        threat_id = "2147846456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 57 56 8b 7d 14 3b 7d 0c a9 00 00 80 00 57 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_BX_2147847151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.BX!MTB"
        threat_id = "2147847151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 56 56 3b 7d 0c a9 00 00 80 00 6a 14 6a 40 ff 15 [0-4] 8b f0 6a 01 56 ff 15 [0-4] e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_AS_2147847997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.AS!MTB"
        threat_id = "2147847997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 0f b7 db 83 c4 10 66 f7 d6 5b e9 ?? ?? ?? ?? 33 c2 1b d6 d2 f6 0f ac fa 57 8b 54 24 18 88 04 2a 80 c4 5b 3a cd d2 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_DP_2147850017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.DP!MTB"
        threat_id = "2147850017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 03 83 e4 f8 83 c4 04 3b 7d 0c a9 00 00 80 00 ff 15 ?? ?? ?? 00 6a 01 ff 75 14 ff 15 ?? ?? ?? 00 85 c0 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Staser_LM_2147950905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Staser.LM!MTB"
        threat_id = "2147950905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Staser"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 04 58 8b 5d c8 89 03 8b 5d ec e8 ?? ?? ?? ?? b8 02 00 00 00 3b c1 7c ?? 68 55 03 00 00 68 ce 1f 01 04 68 01 00 00 00 e8}  //weight: 10, accuracy: Low
        $x_5_2 = "xcomw.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

