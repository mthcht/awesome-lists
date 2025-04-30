rule Trojan_Win32_Grandoreiro_DA_2147816485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.DA!MTB"
        threat_id = "2147816485"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "TMethodImplementationIntercept" ascii //weight: 10
        $x_10_2 = "dbkFCallWrapperAddr" ascii //weight: 10
        $x_10_3 = "__dbk_fcall_wrapper" ascii //weight: 10
        $x_1_4 = "wwrwrw" ascii //weight: 1
        $x_1_5 = "MYPROGRESSSSSSSSSSSSSSSSSSSSS" ascii //weight: 1
        $x_1_6 = "piriogosa" ascii //weight: 1
        $x_1_7 = "CARLOSTAMBAQUISUPPLYS" ascii //weight: 1
        $x_1_8 = "tomacuzin" ascii //weight: 1
        $x_1_9 = "SENTADALENTANOCAP" ascii //weight: 1
        $x_1_10 = "huahusuhasammm" ascii //weight: 1
        $x_1_11 = "MILORDEEEEEEEEEEEEEEEEEEEEE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Grandoreiro_F_2147828242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.F"
        threat_id = "2147828242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = "DELETAKL" ascii //weight: 10
        $x_10_3 = "ATIVARCAPTURAMAG" ascii //weight: 10
        $x_10_4 = "Rein1c1aSystem" ascii //weight: 10
        $x_10_5 = "BLOQUERACESSOBANKINTER" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147836140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyB!MTB"
        threat_id = "2147836140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyB: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {34 00 73 00 49 00 41 00 41 00 41 00 41 00 41 00 41 00 41 00 45 00 41 00 46 00 32 00 54 [0-5] 53 00 33 00 65 00 62 00 4d 00 42}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyI!MTB"
        threat_id = "2147838139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyI: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {79 6e 6a 78 68 7c 00 00 ff ff ff ff 0f 00 00 00 57 69 6e 53 65 76 65 6e 55 70 64 61 74 65 72 00 55 8b ec b9 7a 00 00 00 6a 00 6a 00 49 75 f9 51 89 45 fc 8b 45 fc e8 2d ce fe ff 8d 85 a4 fe ff ff 8b 15 5c a1 40 00 [0-5] fe ff 33 c0 55 68 36 7f 41 00 64 ff 30 64 89 20 68 00 01 00 00 8d 85 a4 fd ff ff 50 6a 00 e8 47 e9 fe ff 8d 95 50 fc ff ff b8 4c 7f 41}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyK!MTB"
        threat_id = "2147838141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {90 31 13 90 90 90 83 c3 04 90 90 90 90 39 cb 90 90 90 90 7c eb}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyO!MTB"
        threat_id = "2147838845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyO: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {33 c0 55 68 b4 08 4a 00 64 ff 30 64 89 20 8b 45 fc e8 c6 fc ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 63 54 f6 ff 8b 55 fc 8b 45 fc e8 d0 00 00 00 e8 ab 58 f6 ff 8b 45 fc 80 b8 a4 00 00 00 00 74 bf}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyM!MTB"
        threat_id = "2147838846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyM: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {33 c0 55 68 ab 89 45 00 64 ff 30 64 89 20 8b 45 fc e8 9b fd ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 2c bf fa ff 8b 55 fc 8b 45 fc e8 a9 00 00 00 e8 2c c3 fa ff 8b 45 fc 80 b8 a4 00 00 00 00 74 bf}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyN!MTB"
        threat_id = "2147838847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyN: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {be 00 b0 41 00 8d be 00 60 fe ff 57 89 e5 8d 9c 24 80 c1 ff ff 31 c0 50 39 dc 75 fb 46 46 53 68 94 23 02 00 57 83 c3 04 53 68 2f 96 00 00 56 83 c3 04 53 50 c7 03 03 00 02}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyR!MTB"
        threat_id = "2147838849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyR: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 8b d8 8b 45 fc 89 18 33 c0 55 68 4a 88 45 00 64 ff 30 64 89 20 8b ce 83 ca ff 8b c3 8b 38 ff 57 2c 33 c0 5a 59 59 64 89 10 eb 16 e9 8d c0 fa ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147838850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyT!MTB"
        threat_id = "2147838850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {74 53 33 f6 3b c3 76 21 68 ff 00 00 00 6a 01 e8 2e 3b 00 00 50 53 e8 27 3b 00 00 83 c4 10 88 04 3e 8b 45 f0 46 3b f0 72 df}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147839278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyW!MTB"
        threat_id = "2147839278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyW: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {74 0f 8b 55 ec 0f af 55 fc 8b 45 fc 2b c2 89 45 fc 8b 4d e4 03 4d f4 8a 55 e0 88 11 8b 45 fc 0f af 45 ec 8b 4d fc 2b c8 89 4d fc ba 84 a7 45 00 83 7d ec 34 75 13 8b 55 fc 33 c9 3b 55 fc 0f 9d c1 8b 45 ec d3 e0 89 45 ec 8b 4d ec 33 4d ec 8b 55 fc d3 e2 89 55 fc e9 ff fe ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147839279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyX!MTB"
        threat_id = "2147839279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyX: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 81 ec 1c 02 00 00 8b 45 08 89 85 f4 fd ff ff 8b 4d 0c 89 8d e4 fd ff ff c7 85 e8 fd ff ff 05 00 00 00 c7 85 f0 fd ff ff c0 90 43 00 8b 95 f4 fd ff ff 3b 95 e4 fd ff ff 73 14 c7 85 e8 fd ff ff 05 00 00 00 8b 85 f4 fd ff ff eb 12 eb 10 c7 85 e8 fd ff ff 05 00 00 00 8b 85 e4 fd ff ff 8b e5 5d}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147839280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyZ!MTB"
        threat_id = "2147839280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyZ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {ff 25 a4 41 42 00 90 90 00 00 00 00 ff 25 b0 41 42 00 90 90 00 00 00 00 ff 25 b4 41 42 00 90 90 00 00 00 00 ff 25 b8 41 42 00 90 90 00 00 00 00 ff 25 bc 41 42 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147839685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyQ!MTB"
        threat_id = "2147839685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyQ: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {2b 09 28 a0 2e 06 57 14 16 9a 26 16 2d f9 fe 09 00 00 28 2b 00 00 0a 2a}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147839686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyS!MTB"
        threat_id = "2147839686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyS: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {33 c0 66 ad 03 c3 ab e2 f7 91 6a 04 68 00 10 00 00 68 60 ee a6 00 50 ff 93 14 11 00 00 85 c0 74 e9}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147840829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyY!MTB"
        threat_id = "2147840829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyY: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {55 8b ec 51 8b 45 08 a3 6f 42 40 00 68 c4 30 40 00 ff 15 60 30 40 00 6a 00 8b 4d 08 51 6a 00 6a 00 6a 00 68 00 00 00 80 6a 00 68 00 00 00 80 68 00 00 cf 00 68 00 40 40 00 68 0c 40 40 00 6a 00 ff 15 80 30 40 00 89 45 fc 83 7d fc 00 75 04 33 c0 eb 1b 6a 00 8b 55 fc 52 ff 15 84 30 40 00 8b 45 fc 50 ff 15 88 30 40 00 b8 01 00 00 00 8b e5 5d c3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_EC_2147841586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.EC!MTB"
        threat_id = "2147841586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45.83.236.742" wide //weight: 1
        $x_1_2 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
        $x_1_3 = "WbemScripting.SWbemLocator" wide //weight: 1
        $x_1_4 = "bds.exe" wide //weight: 1
        $x_1_5 = "GetProcessMemoryInfo" wide //weight: 1
        $x_1_6 = "Portable Network Graphics" wide //weight: 1
        $x_1_7 = "CreateToolhelp32Snapshot" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147841654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyC!MTB"
        threat_id = "2147841654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyC: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {76 34 2e 30 2e 33 30 33 31 39 00 00 00 00 05 00 6c 00 00 00 64 03 00 00 23 7e 00 00 d0 03 00 00 fc 03 00 00 23 53 74 72 69 6e 67 73 00 00 00 00 cc 07 00 00 e4}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147844893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyL!MTB"
        threat_id = "2147844893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyL: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_7_1 = {74 1c 57 8b fa 8b c1 2b f9 89 75 08 ?? ?? ?? 07 89 10 83 c0 04 ff 4d 08 75 f3 8b 55 fc 5f 03 f6}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_2147845838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.psyV!MTB"
        threat_id = "2147845838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "psyV: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {56 b9 00 00 00 00 ff 55 08 50 56 ff 95 88 00 00 00 83 c4 18 33 c0 50 68 80 00 00 00 6a 03 50 6a 01 68 00 00 00 80 57 ff 55 5c 83 f8 ff 74 e5}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_NG_2147896738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.NG!MTB"
        threat_id = "2147896738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 e3 f1 ff ff eb 10 8b cb 0f af 4d ?? 8b d6 8b 45 ?? e8 39 8f ff ff 8b 45 ?? 8b 55 f8 e8 0e 00 00 00 8b 45 08}  //weight: 5, accuracy: Low
        $x_1_2 = "Bilsync.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_DV_2147901043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.DV!MTB"
        threat_id = "2147901043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c5 fc 10 04 08 c5 fc 29 04 0a 83 c1 20 7c f1 5b c5 fc 11 0b c5 fc 11 12 c5 f8 77 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 f4 8b 55 e8 0f b7 7c 50 fe 33 fe 3b df}  //weight: 1, accuracy: High
        $x_1_3 = {8b de 8b 45 e4 40 40 89 45 e4 8b 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_PAEX_2147914493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.PAEX!MTB"
        threat_id = "2147914493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GooGle 3.2" wide //weight: 2
        $x_2_2 = "themida" ascii //weight: 2
        $x_2_3 = "19.7.4674.11" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_PAEY_2147915373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.PAEY!MTB"
        threat_id = "2147915373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GooGle 3.2" wide //weight: 2
        $x_2_2 = {8b 04 24 57 89 e7 81 c7 04 00 00 00 81 c7 04 00 00 00 33 3c 24 31 3c 24 33 3c 24 8b 24 24 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_PAFD_2147918101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.PAFD!MTB"
        threat_id = "2147918101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Dlp Loper" wide //weight: 2
        $x_2_2 = ".themida" ascii //weight: 2
        $x_2_3 = "19.7.4674.1" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Grandoreiro_AB_2147924172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Grandoreiro.AB!MTB"
        threat_id = "2147924172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Grandoreiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 8b f2 8d 7d f6 a5 66 a5 89 45 fc 8b 45 fc e8 ?? ?? ?? ?? 89 45 fc 66 83 7d f6 00 74 2a 8d 45 f0 50 6a 06 8d 45 f6 50 8b 45 fc 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 88 45 f5 66 c7 45 f6 00 00 eb 04 c6 45 f5 00 8a 45 f5 5f 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b0 04 02 00 ff ff ff ff 01 00 00 00 24 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "shellexecutew" ascii //weight: 1
        $x_1_4 = {5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3 8b c3 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 5b c3}  //weight: 1, accuracy: Low
        $x_1_5 = {85 c0 0f 84 dd 00 00 00 f6 45 89 0d 0f 85 d3 00 00 00 8a 45 88 24 08 3c 08 0f 84 c6 00 00 00 8d 45 c8 50 6a 04 8d 45 f8 50 8b 45 8c 50 8b 45 e4 50}  //weight: 1, accuracy: High
        $x_1_6 = {89 45 e4 83 7d e4 00 0f 84 85 01 00 00 6a 40 68 00 10 00 00 68 00 10 00 00 6a 00 8b 45 e4 50}  //weight: 1, accuracy: High
        $x_1_7 = {8b 0a 83 f9 40 7d 06 89 44 8a 04 ff 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

