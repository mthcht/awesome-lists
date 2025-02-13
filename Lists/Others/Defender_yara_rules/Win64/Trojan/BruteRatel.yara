rule Trojan_Win64_BruteRatel_DA_2147827936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.DA!MTB"
        threat_id = "2147827936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b cb 48 83 f8 1c 48 0f 45 c8 42 0f b6 04 09 30 02 48 8d 41 01 41 ff c0 48 8d 52 01 41 81 f8 e0 93 04 00 72}  //weight: 1, accuracy: High
        $x_1_2 = "jikoewarfkmzsdlhfnuiwaejrpaw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_A_2147829031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.A"
        threat_id = "2147829031"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "software\\classes\\clsid\\{9fc8e510-a27c-4b3b-b9a3-bf65f00256a8}\\inprocserver32" ascii //weight: 10
        $x_10_2 = "\\windows\\explorer.exe /e,::{9fc8e510-a27c-4b3b-b9a3-bf65f00256a8}" ascii //weight: 10
        $x_2_3 = "%localappdata%\\microsoft\\windowsapps\\datalayer.dll" ascii //weight: 2
        $x_1_4 = "wireshark.exe" ascii //weight: 1
        $x_1_5 = "desktop-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BruteRatel_DB_2147829274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.DB!MTB"
        threat_id = "2147829274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "] Screenshot downloaded:" ascii //weight: 1
        $x_1_2 = "] Spoofed argument:" ascii //weight: 1
        $x_1_3 = "] TCP listener started" ascii //weight: 1
        $x_1_4 = "] Wallpaper changed" ascii //weight: 1
        $x_1_5 = "] Child process not set" ascii //weight: 1
        $x_1_6 = "] Process Killed" ascii //weight: 1
        $x_1_7 = "] Directory Created" ascii //weight: 1
        $x_1_8 = "] Workstation locked" ascii //weight: 1
        $x_1_9 = "] Object pipe name:" ascii //weight: 1
        $x_1_10 = "] Download complete" ascii //weight: 1
        $x_1_11 = "] Duplicate listener:" ascii //weight: 1
        $x_1_12 = "] Injected to:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_UL_2147832641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.UL!MTB"
        threat_id = "2147832641"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8d 52 01 44 0f b6 d2 0f b6 d2 0f b6 04 14 42 8d 0c 08 44 0f b6 c9 0f b6 c9 0f b6 3c 0c 40 88 3c 14 88 04 0c 02 04 14 0f b6 c0 0f b6 04 04 42 32 04 03 42 88 04 06 4c 89 c0 49 83 c0 01 49 39 c3 75 bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_ABR_2147890049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.ABR!MTB"
        threat_id = "2147890049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c9 8b 72 20 48 01 ee 8b 34 8e 48 01 ee 48 31 ff 48 31 c0 fc ac 84 c0 74 ?? c1 cf 0d 01 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_YAA_2147893849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.YAA!MTB"
        threat_id = "2147893849"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 b9 2a 00 00 00 f7 f9 8b c2 48 98 48 8d 0d ?? ?? ?? ?? 0f be 04 01 8b 4c 24 74 33 c8 8b c1 89 84 24 a4 00 00 00 48 8d 0d 20 d6 04 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_OBS_2147917383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.OBS!MTB"
        threat_id = "2147917383"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 98 48 8d 0c c5 00 00 00 00 48 8d 05 1d 11 01 00 48 8b 04 01 48 39 c2 75 14 8b 45 fc 48 63 d0 48 8b 45 f0 48 01 d0 8b 55 f8 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_RKB_2147921718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.RKB!MTB"
        threat_id = "2147921718"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 63 c2 48 b8 93 24 49 92 24 49 92 24 45 03 d4 49 8b c8 49 f7 e0 48 2b ca 48 d1 e9 48 03 ca 48 c1 e9 04 48 6b c1 1c 4c 2b c0 42 8a 44 04 20 42 32 04 1b 41 88 03 4d 03 dc 41 81 fa 00 8c 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_MKV_2147921735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.MKV!MTB"
        threat_id = "2147921735"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {45 03 d4 48 f7 e1 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 2b c8 48 03 cb 8a 44 0c ?? 42 32 04 1f 41 88 03 4d 03 dc 41 81 fa 00 2c 04 00 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_BKC_2147923087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.BKC!MTB"
        threat_id = "2147923087"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 da 0f b6 d2 8a 04 14 46 8d 14 18 45 0f b6 da 45 0f b6 d2 42 8a 34 14 40 88 34 14 42 88 04 14 02 04 14 0f b6 c0 8a 04 04 41 30 04 08 48 ff c1 eb c5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_BKK_2147923228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.BKK!MTB"
        threat_id = "2147923228"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 0f b6 da 45 0f b6 d2 49 01 ca 45 0f b6 32 44 88 30 45 88 0a 44 02 08 45 0f b6 c9 42 0f b6 04 09 43 32 04 18 42 88 04 1a 4c 89 d8 49 83 c3 01 48 39 f8 75 b7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_MMZ_2147923752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.MMZ!MTB"
        threat_id = "2147923752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 63 c8 49 8b c7 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 1c 48 2b c8 49 0f af cc 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41 ff 49 ff c8 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_AAA_2147923993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.AAA!MTB"
        threat_id = "2147923993"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 e0 48 c1 ea 02 48 8d 04 92 48 8d 04 42 48 01 c0 48 29 c7 0f b6 44 3c ?? 42 32 04 09 48 8b 54 24 ?? 88 04 0a 48 83 c1 01 48 39 4c 24 ?? 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_CMZ_2147924915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.CMZ!MTB"
        threat_id = "2147924915"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 89 c8 49 f7 e1 48 c1 ea 04 48 8d 04 d2 48 8d 04 42 48 89 ce 48 29 c6 0f b6 84 34 ?? ?? ?? ?? 42 32 04 01 48 8b 94 24 ?? ?? ?? ?? 88 04 0a 48 83 c1 01 48 39 8c 24 ?? ?? ?? ?? 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_MUV_2147926629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.MUV!MTB"
        threat_id = "2147926629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 c7 c2 1b 00 00 00 49 c7 c4 31 a9 0f 00 4c 03 65 ?? 48 31 d2 41 f7 f2 45 8a 1c 14 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 9d d3 03 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_BSA_2147928867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.BSA!MTB"
        threat_id = "2147928867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 c1 fa 02 4d 85 d2 74 32 4c 8b c7 66 66 66 0f 1f 84 00 00 00 00 00 41 8b 08 8b c1 0f af c1 3b c3 7f 18 8b c3 99 f7 f9 85 d2 74 3e 41 ff c1 49 83 c0 04 49 63 c1 49 3b c2 72 dc 4c 3b de 74 0d 41 89 1b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BruteRatel_JZP_2147932923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BruteRatel.JZP!MTB"
        threat_id = "2147932923"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BruteRatel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 f7 f1 c5 e5 72 d4 14 45 8a 14 10 66 0f f5 d1 66 0f d9 d0 66 0f 61 de 66 0f 61 ce 66 0f fd dc 66 0f fd ca 0f 12 d1 66 0f fd ca 66 0f eb e5 66 0f ef c0 66 0f fd dc 66 0f fd ca c4 c1 5d ef e0 c5 fd fe c4 44 30 14 0f c5 dd 72 f4 ?? 48 ff c1 c5 dd ef e3 48 89 c8 c5 fd fe c4 48 81 f9 d3 47 0a 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

