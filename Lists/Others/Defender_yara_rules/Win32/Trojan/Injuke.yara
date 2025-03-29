rule Trojan_Win32_Injuke_RJ_2147776072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RJ!MTB"
        threat_id = "2147776072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 03 f0 03 eb 33 f5 33 74 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RM_2147808754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RM!MTB"
        threat_id = "2147808754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "This program cannot be run in 9KW" ascii //weight: 1
        $x_1_2 = "SetKeyboardState" ascii //weight: 1
        $x_1_3 = "GetKeyboardState" ascii //weight: 1
        $x_1_4 = "IsRectEmpty" ascii //weight: 1
        $x_1_5 = "j1QQjmSj1j@" ascii //weight: 1
        $x_1_6 = "Spermatogenetic.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RW_2147812766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RW!MTB"
        threat_id = "2147812766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 7e 00 00 00 89 45 ?? 6a 01 ff 15 ?? ?? ?? ?? 89 45 ?? 6a 01 ff 15 ?? ?? ?? ?? 89 45 ?? b8 64 00 00 00 81 f0 cc fe a6 ac 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_DG_2147816636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.DG!MTB"
        threat_id = "2147816636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 db 01 c0 31 c0 01 c0 29 c0 29 c3 01 c3 83 f3 5c 83 c3 0f 81 f3}  //weight: 2, accuracy: High
        $x_2_2 = {83 f0 71 29 c3 83 f3 11 2d c8 00 00 00 29 c0}  //weight: 2, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_R_2147828088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.R!MTB"
        threat_id = "2147828088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "boonfellow geomancies" wide //weight: 1
        $x_1_2 = "firefly 650" wide //weight: 1
        $x_1_3 = "mishearing" wide //weight: 1
        $x_1_4 = "quiteve" wide //weight: 1
        $x_1_5 = "firebed" wide //weight: 1
        $x_1_6 = "boondoggling" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_MA_2147836530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.MA!MTB"
        threat_id = "2147836530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4c 24 10 8b 15 7c 7e 48 00 50 51 52 6a 00 ff 15 7c 07 47 00 6a 00 6a 00 ff 15 54 04 47 00 6a 00 ff 15 64 07 47 00 e8 ff 26 ff ff 31 05 a0 4c 47 00 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = "GNSearch.exe" wide //weight: 5
        $x_1_3 = "GetTickCount" ascii //weight: 1
        $x_1_4 = "CreateMutexW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_EC_2147837765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.EC!MTB"
        threat_id = "2147837765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadProcessMemory" ascii //weight: 1
        $x_1_2 = "GetComputerNameW" ascii //weight: 1
        $x_1_3 = "rYPbdhokzkNTYswJ" wide //weight: 1
        $x_1_4 = "TqrBrIJsdbHmLhPkrziTkBGCDKbsC" wide //weight: 1
        $x_1_5 = "PBNYLWJWcGHwuEV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_NEAB_2147837970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.NEAB!MTB"
        threat_id = "2147837970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "$Unit_MonitorJunkFiles_GlobalVar" ascii //weight: 4
        $x_4_2 = "Unit_Form_SystemJunkFiles_Monitor" ascii //weight: 4
        $x_4_3 = "Junk Files Monitor V1.0" ascii //weight: 4
        $x_4_4 = "Submenu_JunkFilesMonitorClick" ascii //weight: 4
        $x_4_5 = "AlpcRegisterCompletionListWorkerThread" ascii //weight: 4
        $x_2_6 = "1.0.3.118" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 05 c4 bd 65 00 e8 ?? 55 17 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a8 bc 65 00 e8 2b 00 00 00 6a 00 6a 01 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 03 c8 89 0d e4 cd 46 00 e8 ?? 63 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 8b 1d c8 ?? 46 00 f7 f1 33 d8 89 1d c8 cc 46 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 05 bc 1d 47 00 e8 ?? 8c 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a0 1c 47 00 e8 ?? 48 fe ff 8b 15 a8 1a 47 00 a1 b8 1a 47 00 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 05 bc 3d 47 00 e8 ?? 8c 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a0 3c 47 00 e8 ?? 47 fe ff 8b 15 a8 3a 47 00 a1 b8 3a 47 00 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 02 8b 04 08 89 45 e4 69 45 e4 ?? ?? ?? ?? 89 45 e4 8b 45 e4 c1 e8 18 33 45 e4 89 45 e4 69 45 e4 ?? ?? ?? ?? 89 45 e4 69 45 f4 ?? ?? ?? ?? 89 45 f4 8b 45 e4 33 45 f4 89 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RB_2147838901_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RB!MTB"
        threat_id = "2147838901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 05 bc 3d 47 00 e8 c3 8c 02 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 a0 3c 47 00 e8 ?? ?? fe ff 8b 15 a8 3a 47 00 a1 b8 3a 47 00 52 50 e8 ?? ?? 03 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Delete Empty Folders.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RC_2147839273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RC!MTB"
        threat_id = "2147839273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 f9 8b 45 dc 2b 50 14 8b 45 dc 8b 40 0c 0f b6 04 10 03 c6 99 b9 00 01 00 00 f7 f9 89 55 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RC_2147839273_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RC!MTB"
        threat_id = "2147839273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 32 33 c8 89 0d ?? ?? ?? 00 e8 ?? ?? ?? 00 01 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 8b c8 b8 ?? ?? ?? ?? 33 d2 f7 f1 a3 ?? ?? ?? 00 e8 ?? ?? ?? ff 8b 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 52 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RC_2147839273_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RC!MTB"
        threat_id = "2147839273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 85 50 ff ff ff 3c 00 00 00 c7 85 54 ff ff ff 00 04 00 00 b8 ?? ?? ?? ?? 89 85 60 ff ff ff 8d 85 50 ff ff ff 50 e8 99 38 f6 ff b8 c4 7e 00 00 b8 c4 7e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 c4 7e 00 00 ff 75 f4 ff 35 ?? ?? ?? ?? ff 75 ec 31 c9 03 4d e8 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RD_2147846825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RD!MTB"
        threat_id = "2147846825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 08 8b 55 08 03 55 fc 0f b6 02 83 f0 6b 8b 4d 08 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RD_2147846825_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RD!MTB"
        threat_id = "2147846825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 83 e0 03 8a 04 38 30 04 0a 41 8b 46 04 8b 16 2b c2 3b c8 72 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RD_2147846825_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RD!MTB"
        threat_id = "2147846825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 08 ac 34 76 aa 3c 00 75 f8 5f 5e c9 c2 04 00}  //weight: 1, accuracy: High
        $x_1_2 = "acmvrwuqxfn7.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_MBCP_2147847608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.MBCP!MTB"
        threat_id = "2147847608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 88 45 d3 0f b6 4d d3 51 8d 4d e4 e8 ?? ?? ?? ?? 0f b6 10 8b 45 08 03 45 d4 0f b6 08 33 ca 8b 55 08 03 55 d4 88 0a e9}  //weight: 1, accuracy: Low
        $x_1_2 = "azpjpuedhejdojyuzsegtvyxrodcfgxpiz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RE_2147847737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RE!MTB"
        threat_id = "2147847737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 11 81 f2 ?? ?? ?? ?? 89 11 83 c0 04 3b f0 77 ed [0-48] 50 6a 40 8b 45 f4 50 8b 45 fc 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RF_2147847756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RF!MTB"
        threat_id = "2147847756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ff 8a 84 1d ?? fe ff ff 88 84 3d ?? fe ff ff 88 8c 1d ?? fe ff ff 0f b6 84 3d ?? fe ff ff 03 c2 0f b6 c0 8a 84 05 ?? fe ff ff 32 86 ?? ?? ?? ?? 88 86}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GHN_2147849932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GHN!MTB"
        threat_id = "2147849932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 11 33 c2 8b 8d ?? ?? ?? ?? 88 01 8b 95 ?? ?? ?? ?? 0f bf 02 99 b9 6d 02 00 00 f7 f9 66 a3 ?? ?? ?? ?? 0f bf 95 0c ed ff ff 0f bf 8d ?? ?? ?? ?? d3 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_ABT_2147850822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.ABT!MTB"
        threat_id = "2147850822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 18 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 04 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 45 f8 3b 05}  //weight: 5, accuracy: Low
        $x_5_2 = "22ylku8yh049yu034hkofw42h4ryj02g940g9vrghw08" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNZ_2147852854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNZ!MTB"
        threat_id = "2147852854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c bb 31 30 33 66 b8 87 0b 89 44 24 0d 8d 34 b5 ?? ?? ?? ?? 8f 44 24 09 b9 ?? ?? ?? ?? 66 ff 74 24 08}  //weight: 10, accuracy: Low
        $x_10_2 = {20 53 68 69 65 6c 64 65 6e 20 76 32 2e 34 2e 30 2e 30 00 eb}  //weight: 10, accuracy: High
        $x_1_3 = "DCkhmE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_MBHT_2147889315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.MBHT!MTB"
        threat_id = "2147889315"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {39 f6 74 01 ea ?? ?? ?? ?? ?? ?? 81 c3 04 00 00 00 39 d3 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GME_2147890057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GME!MTB"
        threat_id = "2147890057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 d0 88 c6 45 d1 f9 c6 45 d2 d4 c6 45 d3 60 c6 45 d4 3a c6 45 d5 53 c6 45 d6 43 c6 45 d7 1a c6 45 d8 b5 c6 45 d9 6c c6 45 da e0 c6 45 db 47 c6 45 dc 47 8d 55 e0 89 15}  //weight: 10, accuracy: High
        $x_10_2 = {6a 40 68 0d 80 01 00 8d 95 d0 7f fe ff 52 ff 15}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_NI_2147895794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.NI!MTB"
        threat_id = "2147895794"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 44 19 fc 29 f9 29 ce 01 d9 c1 e9 ?? f3 a5 eb bc 0f b7 84 1d ?? ?? ?? ?? 66 89 44 19 fe e9 36 fd ff ff 0f b7 84 1d ?? ?? ?? ?? 66 89 44 19 fe eb 9b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GMD_2147897368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GMD!MTB"
        threat_id = "2147897368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d0 65 e5 00 62 00 00 00 01 00 35 00 13 74 92 67 a3 d2 3e}  //weight: 10, accuracy: High
        $x_1_2 = "PeMemoryRun20.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNF_2147897722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNF!MTB"
        threat_id = "2147897722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 01 00 00 00 0f 1f 2f 00 ac 7d 2b 00 00 da 0a 00}  //weight: 10, accuracy: High
        $x_1_2 = "Voicemeeter Setup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNG_2147897766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNG!MTB"
        threat_id = "2147897766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 61 d1 30 00 fe 2f 2d ?? ?? ?? ?? 00 73 5b 0d ?? ?? ?? ?? 00 00 d4 00 00 59 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNH_2147897771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNH!MTB"
        threat_id = "2147897771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 9d ?? ?? ?? ?? 48 78 00 00 da 0a 00 73}  //weight: 10, accuracy: Low
        $x_1_2 = "STDConio Setup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNI_2147897893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNI!MTB"
        threat_id = "2147897893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2a 01 00 00 00 38 38 7c 00 d5 96 78 00 00 da 0a 00 73}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GNJ_2147897894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GNJ!MTB"
        threat_id = "2147897894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 a4 a4 ?? ?? ?? ?? 2c 00 00 ae ?? ?? ?? ?? 28 5f 15 cc 2b 00 00 2a}  //weight: 10, accuracy: Low
        $x_10_2 = {00 18 00 4e 23 00 00 01 00 30 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_ASA_2147898261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.ASA!MTB"
        threat_id = "2147898261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a 01 00 00 00 be [0-4] 2d 79 00 00 da 0a 00 73 5b 0d ca 1b f0 78}  //weight: 5, accuracy: Low
        $x_5_2 = {2a 01 00 00 00 5a 05 7c 00 f7 63 78 00 00 da 0a 00 73 5b 0d ca b3 26 78}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Injuke_GAA_2147898262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GAA!MTB"
        threat_id = "2147898262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 d6 02 2c 00 73 ?? 28 00 00 da 0a 00 73 ?? 0d ca 0b 3b 28 00 00 2a 01 00 fd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GAB_2147898377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GAB!MTB"
        threat_id = "2147898377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 fe 58 2f 00 9b ?? ?? ?? ?? da 0a 00 73 5b 0d ca 36 91 2b 00 00 d4 00 00 f3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GAC_2147898413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GAC!MTB"
        threat_id = "2147898413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2a 01 00 00 00 27 bf ?? ?? ?? ?? ?? ?? 00 da 0a 00 73 ?? 0d ca 70 e0 78 00 00 d4 00 00 5d 58}  //weight: 10, accuracy: Low
        $x_10_2 = {2a 01 00 00 00 bf ?? ?? ?? ?? 17 81 00 00 da 0a 00 73 ?? 0d ca ?? ?? ?? 00 00 d4 00 00 34 fc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Injuke_ASB_2147898454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.ASB!MTB"
        threat_id = "2147898454"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2a 01 00 00 00 99 ca 84 00 36 29 81 00 00 da 0a 00 73 5b 0d ca f9 eb 80 00 00 d4 00 00 69 a6 15 46 00 00 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_ASC_2147898466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.ASC!MTB"
        threat_id = "2147898466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2a 01 00 00 00 c6 5f 33 00 63 be [0-4] 0a 00 73 5b 0d ca d2 82 2f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_RH_2147899625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.RH!MTB"
        threat_id = "2147899625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 83 ff 0f 75 12 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_NA_2147900910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.NA!MTB"
        threat_id = "2147900910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6c 73 74 72 63 61 74 41 00 e8 69 52 ce ?? ?? ?? ?? 65 74 46 75 6c}  //weight: 5, accuracy: Low
        $x_1_2 = "it's infected by a Virus or cracked. This file won't work anymore" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_SA_2147902119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.SA!MTB"
        threat_id = "2147902119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d3 2a d1 80 e2 ?? 32 13 32 d0 88 13 03 df 3b 5d ?? 72 ?? 46 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_CCHS_2147902983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.CCHS!MTB"
        threat_id = "2147902983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 06 01 d1 b9 ?? ?? ?? ?? 81 c6 04 00 00 00 39 fe 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GXZ_2147903168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GXZ!MTB"
        threat_id = "2147903168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b d0 88 15 ?? ?? ?? ?? 0f bf 8d ?? ?? ?? ?? 0f bf 95 ?? ?? ?? ?? 33 ca 66 89 0d ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 2d ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 0f bf 8d ?? ?? ?? ?? 0f bf 95 ?? ?? ?? ?? 23 ca 66 89 8d ?? ?? ?? ?? 0f be 05 ?? ?? ?? ?? 0f be 4d ?? d3 f8 88 45 ?? 81 bd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_HNA_2147912445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.HNA!MTB"
        threat_id = "2147912445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 68 74 74 fb df b6 ff 70 3a 2f 2f 38 39 2e 31 31 06 36 37 0c 35 34 2f 74 65 73 74 6f 35 2f 39 bf bd dd 0e 6b 75 02 74 72 75 26 6e 65 74 37 00 2e 69 6e 66 6f 2f 4a 1e 60 ff 68 6f 6d 65 2e 67 69 66 49 38 38 38 8b 6a a1 9d 39 38 93 01 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_GXM_2147913810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.GXM!MTB"
        threat_id = "2147913810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {54 83 fe 1a 2b 43 fe 09 0d ?? ?? ?? ?? 1e fe 0b 0a 09 fe 0b 11 1c ff 4b 56 73 ?? 09 08 08 11}  //weight: 10, accuracy: Low
        $x_1_2 = "HeroDun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_AMAD_2147918877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.AMAD!MTB"
        threat_id = "2147918877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 8b 45 ?? 31 10 83 45 ?? 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_AMAI_2147920102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.AMAI!MTB"
        threat_id = "2147920102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 3b 83 45 ec 04 6a 00 e8 [0-30] 8b 45 ec 3b 45 dc 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_AMP_2147923577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.AMP!MTB"
        threat_id = "2147923577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 13 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 8b f0 83 c6 04 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_SACF_2147935887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.SACF!MTB"
        threat_id = "2147935887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {31 c0 83 c9 ff 31 d2 f2 ae 0f be 83 ?? ?? ?? ?? f7 d1 49 89 44 24 04 89 d8 f7 f1 0f be 84 15 ?? ?? ?? ?? 89 04 24 e8 ?? ?? ?? ?? 88 04 1e 43 81 fb}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Injuke_CCJW_2147937317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Injuke.CCJW!MTB"
        threat_id = "2147937317"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Injuke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 82 ?? ?? ?? ?? 03 c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 03 c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 8d 87 ?? ?? ?? ?? 03 c1 83 e0 0f 8a 80 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 83 c1 04 81 f9 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

