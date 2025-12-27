rule Trojan_Win32_Upatre_DSK_2147750141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.DSK!MTB"
        threat_id = "2147750141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d0 0f b6 80 ?? ?? ?? ?? 0f b6 55 ?? 31 c2 8b 45 ?? 05 ?? ?? ?? ?? 88 10 83 45 ?? 01 a1 ?? ?? ?? ?? 39 45 ?? 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {89 d0 0f b6 80 ?? ?? ?? ?? 89 c1 8b 55 f4 8b 45 08 01 d0 0f b6 55 e7 31 ca 88 10 83 45 f4 01 8b 45 f4 3b 45 0c 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Upatre_DHA_2147754111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.DHA!MTB"
        threat_id = "2147754111"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e9 02 8b 06 83 c6 04 bb 08 08 08 08 31 d8 89 07 83 c7 04 83 e9 01 83 f9 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_ACS_2147793334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.ACS!MTB"
        threat_id = "2147793334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 ?? ?? ?? ?? c3 29 08 c3 01 08 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {76 0f 8a 94 01 ?? ?? ?? ?? 88 14 30 40 3b c7 72 f1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_ACM_2147793335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.ACM!MTB"
        threat_id = "2147793335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00}  //weight: 10, accuracy: High
        $x_3_2 = "Updates downloader" ascii //weight: 3
        $x_3_3 = "ShellExecuteW" ascii //weight: 3
        $x_3_4 = "/error/9mor.exe" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_ACD_2147793358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.ACD!MTB"
        threat_id = "2147793358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 3c 07 8b f7 5f 56 59 58 8b f0 58 83 eb 01 80 f1 f1 c0 c1 04 80 e9 05 80 f1 03}  //weight: 10, accuracy: High
        $x_10_2 = {8b d0 50 4a 8b fa 03 fe 88 0f 58}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AMN_2147793413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AMN!MTB"
        threat_id = "2147793413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 c0 39 44 24 0c 76 15 8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb c2 0c 00 55 8b ec 81 ec 3c 08 00 00}  //weight: 10, accuracy: High
        $x_3_2 = "ShellExecuteW" ascii //weight: 3
        $x_3_3 = "InternetOpenW" ascii //weight: 3
        $x_3_4 = "Updates downloader" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AA_2147793771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AA!MTB"
        threat_id = "2147793771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 57 8b f9 2b c9 ac 50 8b 07 8a c8 8b c1 47 58 3b c1}  //weight: 10, accuracy: High
        $x_10_2 = {8b 56 08 6b c0 2c 89 4c 10 1c 8b 06 8b 56 08 6b c0 2c 89 4c 10 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_EF_2147794004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.EF!MTB"
        threat_id = "2147794004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 06 33 c1 8b c8 88 07 83 c6 01 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 4f ff 8a cd eb d9 47 4b 8b c3 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MD_2147821962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MD!MTB"
        threat_id = "2147821962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 ff 75 f0 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {56 8d 4d e8 51 ff 75 ec 50 ff 75 f8 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8d 44 43 04 50 ff 75 e0 ff 75 f4 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = ":\\TEMP\\hcbnaf.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MA_2147823657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MA!MTB"
        threat_id = "2147823657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 c4 18 33 c0 50 68 80 00 00 00 6a 03 50 6a 01 68 00 00 00 80 57 ff 93}  //weight: 3, accuracy: High
        $x_3_2 = {89 45 dc 6a 00 8d 4d e0 51 56 ff 75 e4 50 ff 93}  //weight: 3, accuracy: High
        $x_3_3 = {8b 45 fc c1 e1 02 03 c1 8b 00 c3}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MB_2147823659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MB!MTB"
        threat_id = "2147823659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 24 08 8a 0c 08 8b 54 24 04 88 0c 10 40 3b 44 24 0c 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {56 53 56 ff 75 fc 68 4c 21 40 00 56 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "bulkbacklinks.com" wide //weight: 1
        $x_1_4 = "hummy.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MF_2147828808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MF!MTB"
        threat_id = "2147828808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 75 fc 68 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\TEMP\\budha.exe" wide //weight: 1
        $x_1_3 = "kilf.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MG_2147831537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MG!MTB"
        threat_id = "2147831537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d c0 ba e5 3c ad d8 89 55 b4 b8 fa 55 1f 62 89 45 a8 b9 ?? ?? ?? ?? 8b d1 81 f2 dc c3 8f d7 89 95 74 ff ff ff 8b c1 35 ee b0 ab c7 89 45 e4 89 2d}  //weight: 1, accuracy: Low
        $x_1_2 = {53 53 50 50 50 50 68 00 00 ef 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 00 02 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_3 = "Xovefxu" wide //weight: 1
        $x_1_4 = "/images/new/TARGTsp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MH_2147833617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MH!MTB"
        threat_id = "2147833617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 55 f0 2b d0 89 4d f8 8a 0c 02 88 08 40 ff 4d f8 75}  //weight: 5, accuracy: High
        $x_5_2 = "hfdfjdk.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_RB_2147838873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.RB!MTB"
        threat_id = "2147838873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 43 01 0f b6 d8 8a 14 3b 0f b6 c2 03 c1 0f b6 c8 89 4d f8 0f b6 04 39 88 04 3b 88 14 39 0f b6 0c 3b 0f b6 c2 03 c8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 0f b6 04 39 8b 4d fc 30 04 0e 46 8b 4d f8 3b 75 08 72 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_RPA_2147839253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.RPA!MTB"
        threat_id = "2147839253"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 04 50 56 56 83 2c 24 01 01 04 24 5e 8b 36 56 59 58 8b f0 58 83 ea 01 80 f1 f1 c0 c1 05 80 e9 05 8a d8 fe cb 80 e3 01 32 cb 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AUP_2147847590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AUP!MTB"
        threat_id = "2147847590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 8a 06 46 8a 0f 32 c1 88 07 47 59 4b 74 07 49 75 ee 5b 5b 5f c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AUP_2147847590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AUP!MTB"
        threat_id = "2147847590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 45 20 20 00 6a 6a 30 40 68 68 ?? ?? ?? ?? ec 56 57 8b 7d 0c 33 c0 8b c8 8b 75 08 8a 0e 8a 07 3b c1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_ME_2147901376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.ME!MTB"
        threat_id = "2147901376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 53 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d f8 8d 44 41 04 50 ff 75 e4 ff 75 ec ff 15}  //weight: 1, accuracy: High
        $x_1_3 = ":\\TEMP\\samhe.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MC_2147901450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MC!MTB"
        threat_id = "2147901450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 10 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 57 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {56 8d 44 24 2c 50 ff 74 24 1c 53 ff 74 24 20 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4c 24 1c 8d 44 41 04 50 53 ff 74 24 28 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = "henis.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_HNS_2147905870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.HNS!MTB"
        threat_id = "2147905870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {c5 00 2c 86 08 d0 14 4a 4a c3 f2 ee 45 15 64 23 3d e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_HNS_2147905870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.HNS!MTB"
        threat_id = "2147905870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 14 96 89 14 81 eb db 8b 45 f8 c1 e0 02 89 45 fc 8b 4d fc 89 4d f0 eb 09 8b 55 f0 83 c2 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_A_2147906078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.A!MTB"
        threat_id = "2147906078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 4c 24 10 8d 54 24 34 51 52 ff 15 ?? 21 40 00 8b 35 ec 21 40 00 8d 44 24 3c 68 10 35 40 00 50 ff ?? 8b 8c 24 4c 01 00 00 8b d8 6a 00 51 53 ff 15 ?? 21 40 00 8b 94 24 60 01 00 00 68 0c 35 40 00 52 ff ?? 57 8b e8 ff 15 ?? 21 40 00 8b f0 83 c4 28 85 f6}  //weight: 2, accuracy: Low
        $x_2_2 = {53 6a 01 57 56 ff 15 ?? 21 40 00 55 6a 01 57 56 ff 15 ?? 21 40 00 55 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_GZY_2147906138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.GZY!MTB"
        threat_id = "2147906138"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 00 5e 03 00 00 00 00 00 60 e8 ?? ?? ?? ?? 5d 81 ed 10 00 00 00 81 ed ?? ?? ?? ?? e9 ?? ?? ?? ?? 6f 21 e3 0b b8 ?? ?? ?? ?? 03 c5 81 c0 ?? ?? ?? ?? b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 30 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_CCJF_2147917082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.CCJF!MTB"
        threat_id = "2147917082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d2 2b 13 f7 da 8d 5b 04 f7 d2 8d 52 f0 c1 ca 02 c1 ca 06 31 fa 83 c2 ff 52 5f c1 c7 02 c1 c7 06 89 11 83 c1 04 8d 76 fc 85 f6 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_BAA_2147935614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.BAA!MTB"
        threat_id = "2147935614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 db 8a 06 c6 04 1f ff 20 04 1f 46 47 49 eb eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_BAA_2147935614_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.BAA!MTB"
        threat_id = "2147935614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 09 47 8b c1 59 33 d0 59 8b c2 5a 88 27 4a 8b c2 46 85 c0 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_MR_2147945547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.MR!MTB"
        threat_id = "2147945547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 44 24 10 8b 14 ?? ?? 30 40 00 29 c0 57 59 40 c1 e9 02 3b c8 76}  //weight: 20, accuracy: Low
        $x_10_2 = {83 4c 24 10 ff c7 44 24 34 18 21 40 00 c7 44 24 38 28 21 40 00 89 74 24 3c 89 74 24 20 89 74 24 14}  //weight: 10, accuracy: High
        $x_1_3 = {32 1d 32 25 32 4a 32 5a 32 6a 32}  //weight: 1, accuracy: High
        $x_1_4 = "C:\\TEMP\\gffos.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_PGU_2147947941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.PGU!MTB"
        threat_id = "2147947941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 40 40 68 ?? ?? ?? ?? ff 00 6a 40 40 40 00 89 ?? ?? ?? ?? ff 40 40 30 68 6a 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AHB_2147948333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AHB!MTB"
        threat_id = "2147948333"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 07 8a 26 02 25 ?? ?? ?? 00 32 c4 eb ?? 00 00 00 88 07 3b f2 74 ?? 46 47 49 75}  //weight: 10, accuracy: Low
        $x_5_2 = {23 ff 6a 07 09 52 6d 30 7a 05 50 00 b4 bc 63 7c 00 00 04 1c 00 72 0a d4 00 00 41 2c 0e 3c 02 00 23 44 44}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AHC_2147948334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AHC!MTB"
        threat_id = "2147948334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 9d 64 ff ff ff 89 9d 54 ff ff ff 89 9d 44 ff ff ff 89 9d 34 ff ff ff 89 9d 30 ff ff ff c7 45 9c 4c 00 00 00 ff d7}  //weight: 10, accuracy: High
        $x_5_2 = {8b 4d e4 c7 01 01 23 45 67 8b 55 e4 c7 42 04 89 ab cd ef 8b 45 e4 c7 40 08 fe dc ba 98 8b 4d e4 c7 41 0c 76 54 32 10 8b 55 e4 52 ff 15}  //weight: 5, accuracy: High
        $x_3_3 = "Some evil things happened" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AB_2147951448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AB!MTB"
        threat_id = "2147951448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 83 ec 10 8b 45 08 25 00 00 ff ff b9 4d 5a 00 00 ?? ?? 2d 00 00 01 00 66 39 08 ?? ?? 0f b7 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_LM_2147952360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.LM!MTB"
        threat_id = "2147952360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8a c3 32 85 d7 fd ff ff 88 85 d7 fd ff ff 8b 8d a4 fd ff ff 85 c9 75 ?? 89 8d c4 fd ff ff eb ?? 0f b6 95 a4 fd ff ff 0f b6 c9 03 d1 8d 8d d8 fd ff ff 0f b6 c9 03 d1 29 95 a0 fd ff ff 8b 8d a4 fd ff ff}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_SXA_2147952582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.SXA!MTB"
        threat_id = "2147952582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 f6 01 00 00 2b 05 ?? ?? ?? ?? 46 83 c4 ?? 89 44 24 30 83 fe 08 7c d5}  //weight: 3, accuracy: Low
        $x_2_2 = {88 85 d7 fd ff ff 8b c7 0f af 45 0c 8d 1c c5 00 00 00 00 2b d8 8d 1c 9d 08 00 00 00 89 9d b0 fd ff ff}  //weight: 2, accuracy: High
        $x_1_3 = "ReductiveKillall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AC_2147952693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AC!MTB"
        threat_id = "2147952693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 56 56 56 68 a8 20 40 00 ff 15 ?? ?? ?? ?? 89 45 e4 3b c6 ?? ?? ?? ?? ?? ?? 8b 3d 5c 20 40 00 56 56 6a 03 56 56 68 ?? ?? 00 00 68 d0 20 40 00 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_SX_2147953211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.SX!MTB"
        threat_id = "2147953211"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {99 8d 76 51 f7 fe 8b b5 a4 fe ff ff 89 45 f4 b8 ?? ?? ?? ?? f7 65 c0 0f b7 45 ec c1 ea ?? 89 55 b0 89 45 d8 0f b6 55 e4}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 5d e8 8b 45 ac 2b d1 2b 55 d4 40 8d 54 1a 02 0f af 55 ec 89 45 ac}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_SXB_2147953853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.SXB!MTB"
        threat_id = "2147953853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 41 18 ff d0 8b 84 24 f8 01 00 00 8b 08 8d 94 24 f4 04 00 00 52 50 8b 41 1c ff d0 8b 94 24 f4 04 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {31 0f af 44 24 ?? 03 c6 03 84 24 ?? ?? ?? ?? f7 d8 4b 89 44 24 ?? 75 ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_LMA_2147955982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.LMA!MTB"
        threat_id = "2147955982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af c7 99 8d 71 10 f7 fe 0f b7 95 b4 84 fe ff 03 15 ?? ?? ?? ?? 0f af d1 03 c2 0f af 85 b0 84 fe ff 89 85 b0 84 fe ff}  //weight: 10, accuracy: Low
        $x_20_2 = {8b 85 b0 84 fe ff d1 e8 0f af 05 ?? ?? ?? ?? 0f b7 d7 0f af d1 03 c2 0f af 85 b0 84 fe ff 89 85 b0 84 fe ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Upatre_AHD_2147959353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Upatre.AHD!MTB"
        threat_id = "2147959353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Upatre"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 03 8b 4d 10 8b 55 0c 89 0c 90 42 89 55 0c 4e 83 fe}  //weight: 20, accuracy: Low
        $x_30_2 = {41 01 c0 e8 ?? 0f b6 c0 09 c2 0f b6 82 ?? ?? ?? ?? 88 43 ?? 89 f8 29 f0 83 f8 ?? 74}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

