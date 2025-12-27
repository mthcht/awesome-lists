rule Trojan_Win32_ICLoader_DSK_2147742671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.DSK!MTB"
        threat_id = "2147742671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d 0c 03 4d 08 8b 15 ?? ?? ?? ?? 8a 04 11 32 05 ?? ?? ?? ?? 8b 4d 0c 03 4d 08 8b 15 ?? ?? ?? ?? 88 04 11 8b 45 08 83 c0 01 89 45 08 81 7d 08 44 07 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_PDSK_2147744125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PDSK!MTB"
        threat_id = "2147744125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 54 24 0c 53 8a 1c 01 32 da 88 1c 01 8b 44 24 0c 83 f8 10 5b 75}  //weight: 2, accuracy: High
        $x_2_2 = {8a 1c 06 8a 14 0a 41 32 da 88 1c 06 8b c1 83 e8 10 5e f7 d8 1b c0 5b 23 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_VDSK_2147744557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.VDSK!MTB"
        threat_id = "2147744557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 55 0c 03 c1 8a 0d ?? ?? ?? ?? 03 c2 8a 10 32 d1 8b 4d 08 88 10 83 3d ?? ?? ?? ?? 03 76}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 0c 11 88 0c 06 8a 8a ?? ?? ?? ?? 84 c9 75 ?? 8b 0d ?? ?? ?? ?? 03 ca 03 c1 8a 0d ?? ?? ?? ?? 30 08 83 3d ?? ?? ?? ?? 03 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_PVD_2147751663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PVD!MTB"
        threat_id = "2147751663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 7c 24 10 8b f5 c1 ee 05 03 74 24 34 81 3d ?? ?? ?? ?? b4 11 00 00 75 0a 00 c7 05}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 08 8d 34 07 e8 ?? ?? ?? ?? 30 06 83 65 fc 00 c1 eb 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_PVS_2147754537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.PVS!MTB"
        threat_id = "2147754537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7d 0c 03 7d 08 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 f8 66 33 c0 8a 65 ff 80 c9 ?? 0c ?? 30 27 61 ff 45 08 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_JL_2147838024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.JL!MTB"
        threat_id = "2147838024"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {8b 55 fc 8a 04 1a 32 04 0e 32 c1 42 83 fa 0f 89 55 fc 76 09 81 e2 00 01 00 00 89 55 fc 88 04 0e 41 3b cf 72 db}  //weight: 6, accuracy: High
        $x_1_2 = "NetworkMiner" ascii //weight: 1
        $x_1_3 = "Wireshark" ascii //weight: 1
        $x_1_4 = "roxifier" ascii //weight: 1
        $x_1_5 = "HTTP Analyzer" ascii //weight: 1
        $x_1_6 = "/c taskkill /im" ascii //weight: 1
        $x_1_7 = "/f & erase" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_6_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_JLK_2147838685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.JLK!MTB"
        threat_id = "2147838685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {c1 e9 04 c1 e2 04 0b ca eb 05 33 c9 8a 0c 18 8b 55 f4 8b 75 08 88 0c 32 42 89 55 f4 40 8b 75 ec 8a 55 ff 46 d0 e2 83 fe 08 89 75 ec 88 55 ff 0f 8c 9b fd ff ff eb 6e 8a 4d f8 84 c9 74 14 8a 4c 18 fc c6 45 f8 00 81 e1 fc 00 00 00 c1 e1 05 40 eb 0d}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {56 57 8b 3d 78 01 65 00 68 7c 32 65 00 ff d7 8b 35 74 01 65 00 a3 70 41 a5 00 85 c0 0f 84 ff 00 00 00 68 64 32 65 00 50 ff d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 16 66 00 83 c4 04 03 ?? 89 ?? d0 16 66 00 e8 ?? ?? 00 00 e9}  //weight: 5, accuracy: Low
        $x_1_2 = "burningstudio.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RD_2147851719_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RD!MTB"
        threat_id = "2147851719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9}  //weight: 1, accuracy: High
        $x_1_2 = "CortexLauncherService.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RE_2147851734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RE!MTB"
        threat_id = "2147851734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 57 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RH_2147852570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RH!MTB"
        threat_id = "2147852570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 51 53 56 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GMC_2147853180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GMC!MTB"
        threat_id = "2147853180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a1 04 28 46 01 89 35 1c 13 46 01 8b fe 38 18 74 ?? 8b f8 8d 45 f8 50 8d 45 fc}  //weight: 10, accuracy: Low
        $x_1_2 = "@.dcs811" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_EM_2147888905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.EM!MTB"
        threat_id = "2147888905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".aqrsvtt.1.12264" ascii //weight: 1
        $x_1_2 = "WNetGetConnectionW" ascii //weight: 1
        $x_1_3 = "BringWindowToTop" ascii //weight: 1
        $x_1_4 = "CsrClientCallServer" ascii //weight: 1
        $x_1_5 = "alizeThunk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_EM_2147888905_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.EM!MTB"
        threat_id = "2147888905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "_rstefgh_6_11221_" ascii //weight: 5
        $x_5_2 = "_qrsabcd_3_11201_" ascii //weight: 5
        $x_5_3 = "_qrsabcd_2_11202_" ascii //weight: 5
        $x_1_4 = "AlphaBlend" ascii //weight: 1
        $x_1_5 = "CsrNewThread" ascii //weight: 1
        $x_1_6 = "NtAccessCheckByTypeResultListAndAuditAlarm" ascii //weight: 1
        $x_1_7 = "CsrClientCallServer" ascii //weight: 1
        $x_1_8 = "DbgPrompt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPX_2147897491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 33 ff 57 ff d6 83 f8 07 75 1f 6a 01 ff d6 25 00 ff 00 00 3d 00 0d 00 00 74 07 3d 00 04 00 00 75 08 5f b8 01 00 00 00 5e c3 8b c7 5f 5e c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {62 c3 5a 00 ff 21 57 00 00 da 0a 00 73 5b 0d ca ac c1 56 00 00 d4 00 00 29 42 b3 73}  //weight: 1, accuracy: High
        $x_1_2 = "MIXAudio" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 87 33 00 25 e6 2f 00 00 da 0a 00 73 5b 0d ca 92 aa 2f 00 00 d4 00 00 55 63 05 9b}  //weight: 1, accuracy: High
        $x_1_2 = "Qt5OpenGL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {9d 7a 74 00 14 df 70 00 00 be 0a 00 0b 33 49 b9 c7 97 70 00 00 dc 01 00 1f d0 c2 43}  //weight: 1, accuracy: High
        $x_1_2 = "QTRadioButton" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPX_2147897491_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPX!MTB"
        threat_id = "2147897491"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {d7 7b 0b 2a 01 00 00 00 99 60 49 00 b5 cb 45 00 00 ae 0a 00 23 97 28 5f 6c 90 45 00 00 d4 00 00 d8 96 a9 71}  //weight: 10, accuracy: High
        $x_10_2 = {7b 4b 49 00 97 b6 45 00 00 ae 0a 00 23 97 28 5f 3b 7b 45 00 00 d4 00 00 4d c2 0b 88}  //weight: 10, accuracy: High
        $x_1_3 = "BusinessTV" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPY_2147897492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 96 84 00 85 f5 80 00 00 da 0a 00 73 5b 0d ca 36 b8 80 00 00 d4 00 00 f8 3c 15 20}  //weight: 1, accuracy: High
        $x_1_2 = "XRECODE 3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPY_2147897492_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 55 6c 00 fa b3 68 00 00 da 0a 00 73 5b 0d ca 37 3e 68 00 00 d4 00 00 4d 7d f5 28}  //weight: 1, accuracy: High
        $x_1_2 = "AudioSwitch" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPY_2147897492_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPY!MTB"
        threat_id = "2147897492"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {14 64 74 00 8b c8 70 00 00 be 0a 00 0b 33 49 b9 78 81 70 00 00 dc 01 00 6a 8d 5e 14}  //weight: 10, accuracy: High
        $x_10_2 = {ba 73 74 00 31 d8 70 00 00 be 0a 00 0b 33 49 b9 10 91 70 00 00 dc 01 00 80 f1 86 03}  //weight: 10, accuracy: High
        $x_1_3 = "DTPanelQT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_RPZ_2147898774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPZ!MTB"
        threat_id = "2147898774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {86 5b fd cc 5a f5 d6 42 08 41 84 27 a3 72 f7 20 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_RPZ_2147898774_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.RPZ!MTB"
        threat_id = "2147898774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c6 04 57 8d 4d f8 56 8b 75 08 51 50 89 45 e0 ff 56 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_TUAA_2147918346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.TUAA!MTB"
        threat_id = "2147918346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? b2 65 00 68 ?? 5e 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 27 a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 27 a6 00 c1 e1 08 03 ca 89 0d ?? 27 a6 00 c1 e8 10 a3 ?? 27 a6 00 33 f6 56 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBXQ_2147918807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBXQ!MTB"
        threat_id = "2147918807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 08 4c 00 68 ?? a7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 02 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_VGAA_2147920113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.VGAA!MTB"
        threat_id = "2147920113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c6 65 00 68 ?? 65 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? 4d a6 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d a6 00 c1 e1 08 03 ca 89 0d ?? 4d a6 00 c1 e8 10 a3 ?? 4d a6 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BAK_2147927735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BAK!MTB"
        threat_id = "2147927735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {c1 e2 04 a1 ?? ?? ?? 00 23 c2 a3 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 e2 08 0f af ca a1 ?? ?? ?? 00 0b c1 a3}  //weight: 3, accuracy: Low
        $x_2_2 = {89 45 fc 8a 0d ?? ?? ?? 00 32 0d ?? ?? ?? 00 88 0d ?? ?? ?? 00 33 d2 8a 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWD_2147927800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWD!MTB"
        threat_id = "2147927800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 99 4f 00 68 ?? 3c 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 71 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BK_2147927958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BK!MTB"
        threat_id = "2147927958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {83 ec 14 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8d 54 24 04 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 52 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 66 00 e8 ?? ?? fb ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWE_2147928037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWE!MTB"
        threat_id = "2147928037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? 18 4c 00 68 ?? b7 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? 12 4c 00 33 d2 8a d4 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GTN_2147928052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTN!MTB"
        threat_id = "2147928052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ba ee ?? ?? ?? 6b 70 00 00 ?? 0a 00 6d f5 94 e2 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AIC_2147928054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIC!MTB"
        threat_id = "2147928054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f8 a1 34 30 4c 00 c7 44 24 10 00 00 00 00 8d 14 09 8b 1d 20 11 4c 00 0b d0 68 9c 30 4c 00 89 54 24 10 57 df 6c 24 14 dc 05 58 30 4c 00 dd 1d 58 30 4c 00 ff d3 89 06 68 88 30 4c 00 57 ff d3 89 46 04 68 74 30 4c 00 57 ff d3 89 46 08 68 64 30 4c 00 57 ff d3 8b 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AIC_2147928054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIC!MTB"
        threat_id = "2147928054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 c9 10 c0 e9 03 81 e1 ff 00 00 00 89 4c 24 00 db 44 24 00 dc 3d c8 49 8a 00 dc 05 58 10 8a 00 dd 1d 38 4a 8a 00 ff 15 ?? ?? ?? ?? 25 ff 00 00 00 83 f8 06 0f 93 c2 83 f8 06}  //weight: 2, accuracy: Low
        $x_1_2 = {56 57 68 24 4b 8a 00 68 48 48 8a 00 ff 15 ?? ?? ?? ?? a1 64 10 8a 00 8b 35 f0 e2 89 00 50 ff d6 8b 3d f4 e2 89 00 68 b8 10 8a 00 50 ff d7 8b 0d 64 10 8a 00 a3 78 49 8a 00 51 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNM_2147928072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNM!MTB"
        threat_id = "2147928072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 33 c8 8b c1 33 cf 5f 81 f9 ?? ?? ?? ?? 5e 75 ?? b9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? f7 d1 89 0d ?? ?? ?? ?? 83 c4 ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BAL_2147928239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BAL!MTB"
        threat_id = "2147928239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 0c 00 0b ca 89 4c 24 04 df 6c 24 04 dc 05 ?? ?? 4d 00 dd 1d ?? ?? 4d 00 ff 15 ?? ?? 4c 00 a3 ?? ?? 4d 00 83 c4 08 c3}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 10 53 56 57 e8 ?? ?? f5 ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWH_2147928624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWH!MTB"
        threat_id = "2147928624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e7 65 00 68 ?? 87 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e3 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWH_2147928624_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWH!MTB"
        threat_id = "2147928624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? fa 65 00 68 ?? 8c 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? f4 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AFHA_2147928966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AFHA!MTB"
        threat_id = "2147928966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c6 4c 00 68 ?? 62 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4e 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4e 4d 00 c1 e1 08 03 ca 89 0d ?? ?? 4d 00 c1 e8 10 a3 ?? 4d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AIHA_2147929021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIHA!MTB"
        threat_id = "2147929021"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? c7 4c 00 68 ?? 64 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 5d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 4d 00 c1 e1 08 03 ca 89 0d ?? 5d 4d 00 c1 e8 10 a3 ?? 5d 4d 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? b7 4c 00 68 ?? 54 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d 4d 00 c1 e1 08 03 ca 89 0d ?? 4d 4d 00 c1 e8 10 a3 ?? 4d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_MBWI_2147929039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWI!MTB"
        threat_id = "2147929039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? f9 65 00 68 ?? 8c 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? f4 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BL_2147929069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BL!MTB"
        threat_id = "2147929069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {56 8b f1 ff 15 ?? ?? 4c 00 56 ff 15 ?? ?? 4c 00 8b f0 a1 ?? ?? ?? 00 50 ff 15 ?? ?? 4c 00 68 ?? ?? 4c 00 56 ff 15 ?? ?? 4c 00 5e c3}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 4c 00 e8 ?? ?? f5 ff 0f be c0 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNT_2147929124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNT!MTB"
        threat_id = "2147929124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 8b f1 6a 62 8a 0d ?? ?? ?? ?? 32 c8 88 0d ?? ?? ?? ?? 8a 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWJ_2147929429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWJ!MTB"
        threat_id = "2147929429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? a6 4c 00 68 ?? 42 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? a2 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BM_2147929469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BM!MTB"
        threat_id = "2147929469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {56 8b f1 50 ff 15 ?? ?? 65 00 56 ff 15 ?? ?? 65 00 8b f0 6a 00 ff 15 ?? ?? 65 00 68 ?? ?? ?? 00 56 ff 15 ?? ?? 65 00 a3 ?? ?? ?? 00 56 ff 15 ?? ?? 65 00 8b 44 24 04 5e 59 c3}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 b9 ?? ?? 66 00 e8 ?? ?? fb ff 89 45 fc e9}  //weight: 1, accuracy: Low
        $x_4_3 = {56 50 ff 15 ?? ?? 65 00 8a 0d ?? ?? 66 00 a0 ?? ?? 66 00 22 c1 8b 0d ?? ?? 66 00 a2 ?? ?? 66 00 a1 ?? ?? 66 00 8b d0 6a 00 c1 ea 02 2b ca 33 d2 8a 15}  //weight: 4, accuracy: Low
        $x_1_4 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? fb ff 89 45 fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_GTK_2147929487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTK!MTB"
        threat_id = "2147929487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0c ef 0c 00 1c ef 0c 00 30 ef 0c 00 3e ef 0c 00 4a ef 0c 00 5c ef 0c 00 30 e9 0c 00 1c e9 0c 00 0c e9 0c 00}  //weight: 5, accuracy: High
        $x_5_2 = {48 f3 0c 00 5a f3 0c 00 6e f3 0c 00 82 f3 0c 00 9c f3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWZ_2147929565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWZ!MTB"
        threat_id = "2147929565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e4 65 00 68 ?? 81 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e0 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GTL_2147929612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTL!MTB"
        threat_id = "2147929612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 6a ff 68 ?? e6 65 00 68 ?? ?? 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AXHA_2147929709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AXHA!MTB"
        threat_id = "2147929709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e7 65 00 68 ?? 87 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 65 00 33 d2 8a d4 89 15 ?? cd a5 00 8b c8 81 e1 ff 00 00 00 89 0d ?? cd a5 00 c1 e1 08 03 ca 89 0d ?? cd a5 00 c1 e8 10 a3 ?? cd a5 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBWM_2147929949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBWM!MTB"
        threat_id = "2147929949"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? b6 4c 00 68 ?? 52 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? b2 4c 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GTM_2147930057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTM!MTB"
        threat_id = "2147930057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 c7 44 24 08 04 3a 5c 00 01 04 24}  //weight: 5, accuracy: High
        $x_5_2 = {8d 00 01 8d ?? ?? ?? ?? ?? 00 83 ?? ?? ?? ?? 29 ca 00 01 8d 14 d6 c7 02 ?? ?? ?? ?? c7 42}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GTM_2147930057_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTM!MTB"
        threat_id = "2147930057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 6a ff 68 ?? 57 4c 00 68 ?? f5 4b 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 ?? ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BO_2147930149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BO!MTB"
        threat_id = "2147930149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 08 a0 ?? ?? ?? 00 8a 0d ?? ?? ?? 00 32 c8 8b 15 ?? ?? ?? 00 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c 6a 01 c0 e9 02 81 e1 ff 00 00 00 52 89 4c 24 08 db 44 24 08 dc 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BQ_2147930210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BQ!MTB"
        threat_id = "2147930210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b c8 83 c9 02 2b d1 33 c9 8a 0d ?? ?? ?? 00 89 15 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 83 ca 01 0f af d1 33 c2 a3}  //weight: 3, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec 0c 53 56 57 e8 ?? ?? ?? ff 89 45 fc e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AZIA_2147931020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AZIA!MTB"
        threat_id = "2147931020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e8 89 00 68 ?? 82 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 8d c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8d c9 00 c1 e1 08 03 ca 89 0d ?? 8d c9 00 c1 e8 10 a3 ?? 8d c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GTC_2147931224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GTC!MTB"
        threat_id = "2147931224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 6a ff 68 ?? e5 89 00 68 ?? 7d 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec ?? 53 56 57 89 65 ?? ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7d 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AIJA_2147931290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AIJA!MTB"
        threat_id = "2147931290"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? a9 63 00 68 ?? 3e 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 5d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 5d 64 00 c1 e1 08 03 ca 89 0d ?? 5d 64 00 c1 e8 10 a3 ?? 5d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AOJA_2147931543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AOJA!MTB"
        threat_id = "2147931543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? a8 63 00 68 ?? 3c 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 2d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 2d 64 00 c1 e1 08 03 ca 89 0d ?? 2d 64 00 c1 e8 10 a3 ?? 2c 64 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? a8 63 00 68 ?? 3c 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 2d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 2d 64 00 c1 e1 08 03 ca 89 0d ?? 2c 64 00 c1 e8 10 a3 ?? 2c 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AQJA_2147931581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AQJA!MTB"
        threat_id = "2147931581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 87 63 00 68 ?? 29 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 1e 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1e 64 00 c1 e1 08 03 ca 89 0d ?? 1e 64 00 c1 e8 10 a3 ?? 1e 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ATJA_2147931767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ATJA!MTB"
        threat_id = "2147931767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 97 63 00 68 ?? 39 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 1d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d 64 00 c1 e1 08 03 ca 89 0d ?? 1d 64 00 c1 e8 10 a3 ?? 1d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BR_2147931797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BR!MTB"
        threat_id = "2147931797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {56 8b f1 57 8a 0d ?? ?? ?? 00 6a 00 32 c8 88 0d ?? ?? ?? 00 8a 0d ?? ?? ?? 00 80 c9 0c c0 e9 02 81 e1 ff 00 00 00 89 4c 24 0c db 44 24 0c dc 3d}  //weight: 5, accuracy: Low
        $x_5_2 = {53 56 57 6a 00 ff 15 ?? ?? ?? 00 8b 3d ?? ?? ?? 00 8b f0 6a 0c 56 ff d7 6a 0e 56 8b d8 ff d7 0f af c3 83 f8 08 56 0f 9e c0 6a 00 a2}  //weight: 5, accuracy: Low
        $x_5_3 = {c1 e9 02 8b ea 2b d9 8b 15 ?? ?? ?? 00 33 c9 8a 0d ?? ?? ?? 00 83 ca 07 0f af d1 23 c2 8b 15 ?? ?? ?? 00 57 52 89 1d ?? ?? ?? 00 a3 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 55 56 ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_CCJT_2147931937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.CCJT!MTB"
        threat_id = "2147931937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b c8 33 d0 89 4c 24 00 33 c9 89 4c 24 04 [0-6] df 6c 24 00}  //weight: 2, accuracy: Low
        $x_1_2 = {89 0e ff 15 ?? ?? 89 00 a0 ?? ?? 8a 00 8a 0d ?? ?? 8a 00 8b 15 ?? ?? 8a 00 22 c8 a1 ?? ?? 8a 00 88 0d ?? ?? 8a 00 8b c8 8b 3d ?? ?? 89 00 c1 e9 02 2b d1 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BS_2147932087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BS!MTB"
        threat_id = "2147932087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {63 00 32 c8 6a ?? 88 0d ?? ?? 63 00 8a 0d ?? ?? 63 00 80 c9 08 c0 e9 03 81 e1 ff 00 00 00 89 4c 24 04 db 44 24 04 dc 3d}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57 68 ?? ?? 63 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_CCJU_2147932238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.CCJU!MTB"
        threat_id = "2147932238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f9 8a 0d 40 ?? 8a 00 a0 4f ?? 8a 00 80 c9 0c 8a 1d 42 ?? 8a 00 c0 e9 02 81 e1 ff 00 00 00 32 d8 89 4c 24}  //weight: 2, accuracy: Low
        $x_1_2 = {32 d1 88 15 49 ?? 8a 00 8b 15 34 ?? 8a 00 8b 0d 48 ?? 8a 00 83 e2 04 03 c2 81 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GLN_2147932310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GLN!MTB"
        threat_id = "2147932310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 00 00 40 2e 64 61 74 61 00 00 00 98 43 40 00 00 00 4a 00 00 32}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 c0 2e 72 73 72 63 00 00 00 68 06 0a 00 00 50 8a}  //weight: 5, accuracy: High
        $x_5_3 = {40 00 00 40 2e 64 61 74 61 00 00 00 f8 63 00 00 00 b0 23}  //weight: 5, accuracy: High
        $x_5_4 = {40 00 00 c0 2e 72 73 72 63 00 00 00 00 e4 15}  //weight: 5, accuracy: High
        $x_10_5 = {2e 72 64 61 74 61 00 00 b4 22 00 00 00 e0 49 00 00 24 00 00 00 c6 49 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 00 00 98 53 40 00 00 10 4a 00 00 32 00 00 00 ea 49 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 72 73 72 63 00 00 00 08 f5 08 00 00 70 8a 00 00 f6 08 00 00 1c 4a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_ADKA_2147932378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ADKA!MTB"
        threat_id = "2147932378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 86 63 00 68 ?? 27 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 0d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 0d 64 00 c1 e1 08 03 ca 89 0d ?? 0d 64 00 c1 e8 10 a3 ?? 0d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNN_2147932442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNN!MTB"
        threat_id = "2147932442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 f0 03 f8 ff 24 95 ?? ?? ?? ?? 8b ff 30 3b 63 00 38 3b 63 ?? 48 3b 63 ?? 5c 3b 63 00 8b 45 ?? 5e 5f c9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNN_2147932442_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNN!MTB"
        threat_id = "2147932442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 01 58 c9 c3 33 c0 c9 c3 68 a4 d3 89 00 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 68 88 d3 89 00 50 ff 15 ?? ?? ?? ?? 85 c0 ?? ?? 6a 00 ff d0 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GRN_2147932443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GRN!MTB"
        threat_id = "2147932443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 00 00 c0 2e 72 73 72 63 00 00 00 00 7a 06 00 00 40 24}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 40 2e 64 61 74 61 00 00 00 b8 53 00 00 00 e0 23 00 00 30 00 00 00 c8 23}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BT_2147932499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BT!MTB"
        threat_id = "2147932499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 c1 8b 4c 24 0c a2 ?? ?? ?? 00 0c 30 c0 e8 04 25 ff 00 00 00 68 ?? ?? ?? 00 89 44 24 0c 6a 00 db 44 24 10 8d 54 24 1c 6a 01 52 89 4c 24 ?? dc 3d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AGKA_2147932501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AGKA!MTB"
        threat_id = "2147932501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7e 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 3c ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 3c ca 00 c1 e1 08 03 ca 89 0d ?? 3c ca 00 c1 e8 10 a3 ?? 3c ca 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7e 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 2c ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 2c ca 00 c1 e1 08 03 ca 89 0d ?? 2c ca 00 c1 e8 10 a3 ?? 2c ca 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AID_2147932572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AID!MTB"
        threat_id = "2147932572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0d 4a 10 8a 00 8a 15 4d 10 8a 00 a1 34 10 8a 00 22 d1 8b 0d 30 10 8a 00 88 15 4d 10 8a 00 8b d0 6a 10 c1 ea 02 2b ca 33 d2 8a 15 43 10 8a 00 89 0d 30 10 8a 00 8b 0d 38 10 8a 00 83 c9 07 0f af ca 23 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ALKA_2147932631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ALKA!MTB"
        threat_id = "2147932631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 86 63 00 68 ?? 29 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 1d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d 64 00 c1 e1 08 03 ca 89 0d ?? 1d 64 00 c1 e8 10 a3 ?? 1d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ANKA_2147932720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ANKA!MTB"
        threat_id = "2147932720"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7e 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 1d ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d ca 00 c1 e1 08 03 ca 89 0d ?? 1d ca 00 c1 e8 10 a3 ?? 1d ca 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? e6 89 00 68 ?? 7e 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 1d ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d ca 00 c1 e1 08 03 ca 89 0d ?? 1d ca 00 c1 e8 10 a3 ?? 1c ca 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AOKA_2147932735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AOKA!MTB"
        threat_id = "2147932735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 68 63 00 68 ?? fc 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? fd 63 00 8b c8 81 e1 ff 00 00 00 89 0d ?? fd 63 00 c1 e1 08 03 ca 89 0d ?? fd 63 00 c1 e8 10 a3 ?? fd 63 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ARKA_2147932795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ARKA!MTB"
        threat_id = "2147932795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 95 63 00 68 ?? 36 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 1d 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d 64 00 c1 e1 08 03 ca 89 0d ?? 1d 64 00 c1 e8 10 a3 ?? 1d 64 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BU_2147932881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BU!MTB"
        threat_id = "2147932881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 00 32 c1 68 ?? ?? 63 00 a2 ?? ?? 63 00 0c 30 c0 e8 04 25 ff 00 00 00 53 89 44 24 18 8d 44 24 20 db 44 24 18 6a 01 50 89 5c 24 2c 89 5c 24 30 dc 3d}  //weight: 5, accuracy: Low
        $x_5_2 = {6a 00 ff 15 ?? ?? 63 00 a0 ?? ?? 63 00 8a 0d ?? ?? 63 00 8b 15 ?? ?? 63 00 22 c8 a1 ?? ?? 63 00 88 0d ?? ?? 63 00 8b c8 c1 e9 02 2b d1 33 c9 8a 0d ?? ?? 63 00 89 15 ?? ?? 63 00 8b 15 ?? ?? 63 00 83 ca 07 0f af d1 23 c2}  //weight: 5, accuracy: Low
        $x_5_3 = {83 ec 18 a0 ?? ?? 63 00 8a 0d ?? ?? 63 00 32 c8 56 88 0d ?? ?? 63 00 8a 0d ?? ?? 63 00 80 c9 08 57 c0 e9 03 81 e1 ff 00 00 00 6a 01 89 4c 24 0c c7 44 24 18 0c 00 00 00 db 44 24 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AWKA_2147933089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AWKA!MTB"
        threat_id = "2147933089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e7 89 00 68 ?? 80 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 1c ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1c ca 00 c1 e1 08 03 ca 89 0d ?? 1c ca 00 c1 e8 10 a3 ?? 1c ca 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BV_2147933613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BV!MTB"
        threat_id = "2147933613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {3b c5 89 44 24 0c 0f 84 83 00 00 00 8b 4c 24 ?? 68 24 00 01 00 51 50 ff 15 ?? ?? ?? 00 8b f0 8b fe 3b f5 89 7c 24}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57}  //weight: 1, accuracy: High
        $x_4_3 = {32 c8 56 88 0d ?? ?? 8a 00 8a 0d ?? ?? 8a 00 80 c9 0c 6a 0a c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08 db 44 24 08 c7 44 24 08}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_ASLA_2147933717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ASLA!MTB"
        threat_id = "2147933717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e5 89 00 68 ?? 7c 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 0c ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 0c ca 00 c1 e1 08 03 ca 89 0d ?? 0c ca 00 c1 e8 10 a3 ?? 0c ca 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? e5 89 00 68 ?? 7c 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? fc c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? fc c9 00 c1 e1 08 03 ca 89 0d ?? fc c9 00 c1 e8 10 a3 ?? fc c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_MBQ_2147934042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBQ!MTB"
        threat_id = "2147934042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 6a ff 68 ?? ?? 60 00 68 ?? ?? 60 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 60 00 33 d2 8a d4 89 15 ?? ?? ?? 00 8b c8 81 e1}  //weight: 2, accuracy: Low
        $x_1_2 = {33 f6 56 e8 16 0b 00 00 59 85 c0 75 08 6a 1c e8 b0 00 00 00 59 89 75 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBR_2147934043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBR!MTB"
        threat_id = "2147934043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? e4 89 00 68 ?? ?? 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? e1 89 00 33 d2 8a d4 89 15 ?? ?? c9 00 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_MBS_2147934044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.MBS!MTB"
        threat_id = "2147934044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 6a ff 68 ?? e5 89 00 68 ?? 7c 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? ?? c9 00 8b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AAMA_2147934047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AAMA!MTB"
        threat_id = "2147934047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e5 89 00 68 ?? 7c 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? ec c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? ec c9 00 c1 e1 08 03 ca 89 0d ?? ec c9 00 c1 e8 10 a3 ?? ec c9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? e4 89 00 68 ?? 7b 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? ec c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? ec c9 00 c1 e1 08 03 ca 89 0d ?? ec c9 00 c1 e8 10 a3 ?? ec c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_BW_2147934134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BW!MTB"
        threat_id = "2147934134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {32 c8 6a 00 88 0d ?? ?? 63 00 8a 0d ?? ?? 63 00 80 c9 0c 6a 00 c0 e9 02 81 e1 ff 00 00 00 89 4c 24 08 db 44 24 08 dc 3d}  //weight: 4, accuracy: Low
        $x_1_2 = {0f af d1 23 c2 a3 ?? ?? 63 00 8b 44 24 00 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GPQ_2147934250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GPQ!MTB"
        threat_id = "2147934250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 ?? ?? ?? 00 ?? ?? ?? 00 00 64 0a 00 27 9e 49 2b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GNQ_2147934597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GNQ!MTB"
        threat_id = "2147934597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 00 40 2e 64 61 ?? ?? 00 00 00 98 ?? ?? ?? ?? f0 49 00 00 32 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ANMA_2147934638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ANMA!MTB"
        threat_id = "2147934638"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? a9 4c 00 68 ?? 49 4c 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 4c 00 33 d2 8a d4 89 15 ?? 4d 4d 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 4d 4d 00 c1 e1 08 03 ca 89 0d ?? 4d 4d 00 c1 e8 10 a3 ?? 4d 4d 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AOMA_2147934647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AOMA!MTB"
        threat_id = "2147934647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e4 89 00 68 ?? 7a 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? dc c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? dc c9 00 c1 e1 08 03 ca 89 0d ?? dc c9 00 c1 e8 10 a3 ?? dc c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_BX_2147934685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BX!MTB"
        threat_id = "2147934685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 00 8a 0d [0-10] 32 c8 [0-1] 88 0d ?? ?? 89 00 8a 0d ?? ?? 89 00 80 c9 0c c0 e9 02 81 e1 ff 00 00 00 89 4c 24 ?? db 44 24 ?? dc 3d}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 83 ec 0c 53 56 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_ABNA_2147935137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ABNA!MTB"
        threat_id = "2147935137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e4 89 00 68 ?? 7a 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? cc c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? cc c9 00 c1 e1 08 03 ca 89 0d ?? cc c9 00 c1 e8 10 a3 ?? cc c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_CCJV_2147935918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.CCJV!MTB"
        threat_id = "2147935918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f af d1 23 c2 8b 54 24 ?? 52 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b f0 56 ff 15 ?? ?? ?? ?? a0 41 b0 79 00 8a 0d 4b b0 79 00 32 c8 8b 1d 80 80 79 00 88 0d 4b b0 79 00 8a 0d 42 b0 79 00 80 c9 10 6a 0c c0 e9 03 81 e1 ff 00 00 00 56}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AXNA_2147935932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AXNA!MTB"
        threat_id = "2147935932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 26 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 9d b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9d b9 00 c1 e1 08 03 ca 89 0d ?? 9d b9 00 c1 e8 10 a3 ?? 9c b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 26 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 9c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9c b9 00 c1 e1 08 03 ca 89 0d ?? 9c b9 00 c1 e8 10 a3 ?? 9c b9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_BY_2147936094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.BY!MTB"
        threat_id = "2147936094"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {32 da 8b 15 ?? ?? 63 00 88 1d ?? ?? 63 00 bb 04 00 00 00 23 c3 81 e2 ff 00 00 00 03 f8 a1 ?? ?? 63 00 83 e0 0c 51 0f af c2 df 6c 24 1c dd 1d}  //weight: 4, accuracy: Low
        $x_1_2 = {8b d7 8b c6 5f 5e 5b 83 c4 14 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_CCJW_2147936707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.CCJW!MTB"
        threat_id = "2147936707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c8 88 0d ?? ?? 66 00 8a 0d ?? ?? 66 00 80 c9 10 c0 e9 03 0f b6 d1 89 54 24 00 56 db 44 24}  //weight: 2, accuracy: Low
        $x_1_2 = {32 d1 8b 0d ?? ?? 66 00 88 15 ?? ?? 66 00 8b 15 ?? ?? 66 00 83 e2 04 03 ca 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AZOA_2147936851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AZOA!MTB"
        threat_id = "2147936851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 83 79 00 68 ?? 20 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 7c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 7c b9 00 c1 e1 08 03 ca 89 0d ?? 7c b9 00 c1 e8 10 a3 ?? 7c b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 84 79 00 68 ?? 22 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 8c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8c b9 00 c1 e1 08 03 ca 89 0d ?? 8c b9 00 c1 e8 10 a3 ?? 8c b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 8c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8c b9 00 c1 e1 08 03 ca 89 0d ?? 8c b9 00 c1 e8 10 a3 ?? 8c b9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_ACPA_2147936943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ACPA!MTB"
        threat_id = "2147936943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 96 63 00 68 ?? 39 63 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? 1c 64 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1c 64 00 c1 e1 08 03 ca 89 0d ?? 1c 64 00 c1 e8 10 a3 ?? 1c 64 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 56 63 00 68 ?? f8 62 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 63 00 33 d2 8a d4 89 15 ?? ed 63 00 8b c8 81 e1 ff 00 00 00 89 0d ?? ed 63 00 c1 e1 08 03 ca 89 0d ?? ed 63 00 c1 e8 10 a3 ?? ed 63 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? d1 89 00 68 ?? 73 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? ac c9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? ac c9 00 c1 e1 08 03 ca 89 0d ?? ac c9 00 c1 e8 10 a3 ?? ac c9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_AKPA_2147937139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AKPA!MTB"
        threat_id = "2147937139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 85 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? bc b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? bc b9 00 c1 e1 08 03 ca 89 0d ?? bc b9 00 c1 e8 10 a3 ?? bc b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 87 79 00 68 ?? 28 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? bc b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? bc b9 00 c1 e1 08 03 ca 89 0d ?? bc b9 00 c1 e8 10 a3 ?? bc b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_3 = {55 8b ec 6a ff 68 ?? 85 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? ac b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? ac b9 00 c1 e1 08 03 ca 89 0d ?? ac b9 00 c1 e8 10 a3 ?? ac b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_4 = {55 8b ec 6a ff 68 ?? 85 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? cc b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? cc b9 00 c1 e1 08 03 ca 89 0d ?? cc b9 00 c1 e8 10 a3 ?? cc b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_5 = {55 8b ec 6a ff 68 ?? 85 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? dc b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? dc b9 00 c1 e1 08 03 ca 89 0d ?? dc b9 00 c1 e8 10 a3 ?? dc b9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_ANPA_2147937256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ANPA!MTB"
        threat_id = "2147937256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 25 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 9c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 9c b9 00 c1 e1 08 03 ca 89 0d ?? 9c b9 00 c1 e8 10 a3 ?? 9c b9 00 6a 01}  //weight: 5, accuracy: Low
        $x_5_2 = {55 8b ec 6a ff 68 ?? 86 79 00 68 ?? 26 79 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 79 00 33 d2 8a d4 89 15 ?? 8c b9 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 8c b9 00 c1 e1 08 03 ca 89 0d ?? 8c b9 00 c1 e8 10 a3 ?? 8c b9 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_ICLoader_ATPA_2147937384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.ATPA!MTB"
        threat_id = "2147937384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 6a ff 68 ?? e7 89 00 68 ?? 80 89 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 ?? ?? 89 00 33 d2 8a d4 89 15 ?? 1d ca 00 8b c8 81 e1 ff 00 00 00 89 0d ?? 1d ca 00 c1 e1 08 03 ca 89 0d ?? 1d ca 00 c1 e8 10 a3 ?? 1d ca 00 6a 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_DA_2147942631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.DA!MTB"
        threat_id = "2147942631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 00 32 c8 a1 ?? ?? 4c 00 88 0d ?? ?? 4c 00 8b 0d ?? ?? 4c 00 8b 15 ?? ?? 4c 00 83 e1 04 03 c1 83 e2 0c a3 ?? ?? 4c 00 a1 ?? ?? 4c 00 25 ff 00 00 00 8b 0d ?? ?? 4c 00 0f af d0 55 56 8b 35}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GXT_2147949691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GXT!MTB"
        threat_id = "2147949691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {32 c2 8b 4c 24 08 a2 ?? ?? ?? ?? a0 ?? ?? ?? ?? 0c 10 56 c0 e8 03 25 ff 00 00 00 51}  //weight: 10, accuracy: Low
        $x_5_2 = {0f af d1 0b c2 a3 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 5, accuracy: Low
        $x_5_3 = {0f af d1 0b c2 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 85 c0 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_ICLoader_GXS_2147950168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GXS!MTB"
        threat_id = "2147950168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {23 df 5f 89 1d ?? ?? ?? ?? 33 db 8a da 8b 15 ?? ?? ?? ?? 0f af c3 dc 05}  //weight: 5, accuracy: Low
        $x_5_2 = {32 c2 8a 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? 8a c1 0c 10 8a 1d ?? ?? ?? ?? c0 e8 03 25 ?? ?? ?? ?? 57 89 44 24 10 8a c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GSY_2147951988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GSY!MTB"
        threat_id = "2147951988"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 f9 c1 ca 05 00 00 89 74 24}  //weight: 5, accuracy: High
        $x_5_2 = {31 cf c1 ca 06 00 00 01 fb c1 ce 09}  //weight: 5, accuracy: High
        $x_5_3 = {8b 7c 24 08 31 ee 89 00 00 04 31 fd c1 ce}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GZF_2147952172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GZF!MTB"
        threat_id = "2147952172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 8d 0c c5 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0b c8 33 d0 89 4d f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_GZF_2147952172_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.GZF!MTB"
        threat_id = "2147952172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 cf c1 ca 00 00 ee 01 fb c1 ce ?? 01 e9 8b 7c 24 ?? 31 ee}  //weight: 5, accuracy: Low
        $x_5_2 = {31 f9 c1 ca 05 00 00 89 74 24 1c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ICLoader_AHB_2147959958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ICLoader.AHB!MTB"
        threat_id = "2147959958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ICLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b 55 e0 81 e2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 55 e0 8a 45 f0 34 ?? 88 45 f0 eb}  //weight: 30, accuracy: Low
        $x_20_2 = {8a 11 c1 fa ?? 8b 45 10 03 45 f8 33 c9 66 8b 48 ?? c1 e1 ?? 0b d1 89 55 c0 eb}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

