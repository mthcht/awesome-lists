rule Trojan_Win32_Zenpak_JS_2147743008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.JS!MTB"
        threat_id = "2147743008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {76 1f 8b 0d ?? ?? ?? ?? 8a 8c 08 8e 1b 0c 00 8b 15 ?? ?? ?? ?? 88 0c 10 40 3b 05 ?? ?? ?? ?? 72 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DSK_2147750295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DSK!MTB"
        threat_id = "2147750295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 30 04 0e 46 3b f7 7c 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 4d fc 03 cf 33 c1 2b f0 8b 45 d8 d1 6d f4 29 45 fc ff 4d f0 0f 85}  //weight: 2, accuracy: High
        $x_2_4 = {8b 54 24 10 8b c7 c1 e8 05 03 44 24 78 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 89 2d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zenpak_G_2147751708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.G!MTB"
        threat_id = "2147751708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_G_2147751708_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.G!MTB"
        threat_id = "2147751708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 e8 0f b6 3c 06 01 d7 89 45 ?? 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_G_2147751708_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.G!MTB"
        threat_id = "2147751708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 1c 02 2b 4d ?? 8b 75 ?? 88 1c 06 01 c8 8b 4d ?? 39 c8 89 45 ?? 74 ?? 8b 45 ?? b9 ?? ?? ?? ?? 8b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {88 1c 06 83 c0 ?? c6 45 f1 ?? 8b 7d ?? 39 f8 89 45 [0-16] 8b 45 [0-16] 8b 55 ?? 8a 1c 02 [0-16] 8b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_JJ_2147752437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.JJ!MTB"
        threat_id = "2147752437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 24 66 [0-37] 89 0c 10 50 00 ff 37}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 10 66 50 00 ff 37 [0-37] 31 34 24}  //weight: 1, accuracy: Low
        $x_1_3 = {31 34 24 81 ff [0-37] 89 0c 10 50 00 ff 37}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 37 85 ff [0-37] 31 34 24 [0-37] 89 0c 10}  //weight: 1, accuracy: Low
        $x_1_5 = {89 0c 10 85 ff 50 00 ff 37 [0-37] 31 34 24}  //weight: 1, accuracy: Low
        $x_1_6 = {31 34 24 85 ff [0-37] 89 0c 10 50 00 ff 37}  //weight: 1, accuracy: Low
        $x_1_7 = {31 34 24 83 [0-37] 89 0c 10 50 00 ff 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_PVD_2147752555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PVD!MTB"
        threat_id = "2147752555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 34 07 e8 ?? ?? ?? ?? 30 06 83 6c 24 08 01 8b 44 24 08 85 c0 7d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 80 33 85 7c ff ff ff 89 45 80 8b 4d 84 8b 55 90 8b 45 80 89 04 8a e9}  //weight: 2, accuracy: High
        $x_2_3 = {8b c7 c1 e9 05 03 4d ?? c1 e0 04 03 45 ?? 33 c8 8d 04 3b 2b 5d ?? 33 c8 2b f1 83 6d fc 01 75}  //weight: 2, accuracy: Low
        $x_2_4 = {34 39 88 81 ?? a9 41 00 41 83 f9 08 72 07 00 8a 04 4d ?? a9 41 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 83 c0 09 29 c2 8d 05 ?? ?? ?? ?? 89 28 83 f2 05 83 e8 07 83 f2 09 31 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 89 88 88 88 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 ?? 29 c1 89 c8 83 e8 08 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ab aa aa aa 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 ?? 29 c1 89 c8 83 e8 04 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 cd cc cc cc 89 44 24 ?? f7 e1 c1 ea 04 6b c2 14 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24 ?? 74 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e0 50 8f 05 ?? ?? ?? ?? 31 d0 83 c2 09 83 c0 08 eb 05 e8 ?? ?? ?? ?? 29 c2 31 35 ?? ?? ?? ?? b8 03 00 00 00 89 3d ?? ?? ?? ?? 83 c0 06 01 d0 89 d8 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 31 c2 8d 05 ?? ?? ?? ?? 89 20 e8 25 00 00 00 c3 89 c2 83 f0 06 8d 05 ?? ?? ?? ?? 89 38 42 ba 0a 00 00 00 42 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ff 89 c1 88 ca 83 e8 4d 88 95 ?? fe ff ff 89 85 ?? fe ff ff 74 ?? eb 00 8a 85 ?? fe ff ff 0f b6 c8 83 e9 54 89 8d ?? fe ff ff 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 3c 0e 88 1c 16 0f b6 0c 0e 01 f9 81 e1 ?? ?? ?? ?? 8a 1c 0e 8b 4d ?? 8b 7d ?? 32 1c 39 8b 4d ?? 88 1c 39 8b 4d ?? 01 cf 8b 4d ?? 39 cf 8b 4d ?? 89 4d ?? 89 55 ?? 89 7d ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe ff ff 45 75 1e 80 bd ?? fe ff ff 4c 75 15 31 c0 80 bd ?? fe ff ff 2e 89 85 ?? fe ff ff 0f 84 ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Arfruitfulsaw.likenesscisn.t.kdon.tgreat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ugathering,creepinghadfirmamenta" ascii //weight: 1
        $x_1_2 = "mmayjwherein.u5lwatersHimage" ascii //weight: 1
        $x_1_3 = "godhimLlifev7Ourb8H" ascii //weight: 1
        $x_1_4 = "creature5upon7own0ggivenRw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RG_2147753378_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RG!MTB"
        threat_id = "2147753378"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 84 24 98 00 00 00 89 e0 8d 8c 24 98 00 00 00 89 48 0c c7 40 08 93 0a 00 00 c7 40 04 f0 07 00 00 c7 00 ba 9b 38 00 a1 10 b0 01 10 ff d0 83 ec 10 89 e1 8d 94 24 90 00 00 00 89 51 04 c7 01 05 c8 a3 00 8b 0d 38 b0 01 10}  //weight: 5, accuracy: High
        $x_1_2 = "themtheirF3Nsubduewhose1fruitfultheir" ascii //weight: 1
        $x_1_3 = "years6togetherusyieldingTreelgathered" ascii //weight: 1
        $x_1_4 = "kind.thirdlight.OandseasonsAircan.t,6dominion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PVS_2147753717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PVS!MTB"
        threat_id = "2147753717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 44 0a c5 88 45 f3 0f b7 0d ?? ?? ?? ?? 69 c9 be 00 01 00 0f b6 55 f3 0f af ca 88 4d f3 0f b6 05 ?? ?? ?? ?? 3d 76 14 00 00 75 06 00 8b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AG_2147753991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AG!MTB"
        threat_id = "2147753991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 d1 89 c8 99 f7 fe 8a bc 15 f4 fe ff ff 8b 8d b8 fe ff ff 88 bc 0d f4 fe ff ff 88 9c 15 f4 fe ff ff 0f b6 b4 0d f4 fe ff ff 8b 8d bc fe ff ff 01 ce 81 e6 ff 00 00 00 8b 8d ec fe ff ff 8b 9d c4 fe ff ff 8a 0c 19 32 8c 35 f4 fe ff ff 8b b5 e8 fe ff ff 88 0c 1e 8b 8d f0 fe ff ff 39 cf}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PVE_2147754081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PVE!MTB"
        threat_id = "2147754081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c8 8b 4d fc 89 78 04 5f 89 30 5e 33 cd 5b e8 ?? ?? ?? ?? 8b e5 5d c2 04 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DEA_2147758129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DEA!MTB"
        threat_id = "2147758129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 04 89 85 01 0f b6 94 15 ?? ?? ?? ?? 30 50 ff}  //weight: 1, accuracy: Low
        $x_1_2 = "Rl4J3cMtFriEv8cYNMdhr53tvDrSXdLW16lh6Ww" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_GA_2147758660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GA!MTB"
        threat_id = "2147758660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 44 34 ?? 81 e1 ?? ?? ?? ?? 03 c1 83 c4 ?? 25 [0-48] 48 0d ?? ?? ?? ?? 40 8a 54 04 ?? 8a 03 32 c2 88 03 43 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GM_2147759365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GM!MTB"
        threat_id = "2147759365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d3 03 c2 [0-48] 8b 85 ?? ?? ?? ?? 40 83 c4 ?? 89 85 ?? ?? ?? ?? 0f b6 94 15 [0-32] 30 50 ?? 83 7d [0-32] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DSA_2147759778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DSA!MTB"
        threat_id = "2147759778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 5c 24 30 c7 44 24 1c 42 6f 62 00 89 4c 24 2c e8 ?? ?? ?? ?? 6a 15 8d 44 24 20 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 15 8d 4c 24 2c 51 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b f0 89 5c 24 20 c7 84 24 ?? ?? ?? ?? 42 6f 62 00 89 9c 24 ?? ?? ?? ?? 89 9c 24 ?? ?? ?? ?? 89 9c 24 ?? ?? ?? ?? 89 9c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 15 8d 94 24 ?? ?? ?? ?? 52 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 6a 15 8d 84 24 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = "Hello %s, you are %d years old" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Zenpak_DED_2147761119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DED!MTB"
        threat_id = "2147761119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 2b d0 83 ea 09 0f b7 d2 0f b6 f1 0f b7 ea 2b ee 8d 5c 2b 2c 8b f3 0f af f2 2b f0 0f b7 ee 89 54 24 10 89 1d ?? ?? ?? ?? 89 6c 24 10 8b 15 ?? ?? ?? ?? 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DEE_2147761120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DEE!MTB"
        threat_id = "2147761120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d1 8b fa 04 05 69 ff 67 48 00 00 02 c0 2a 05 ?? ?? ?? ?? 01 3d ?? ?? ?? ?? 02 05 ?? ?? ?? ?? 3a c3 88 44 24 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DEF_2147762005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DEF!MTB"
        threat_id = "2147762005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a cb 0f b6 c3 2a 4c 24 34 a3 ?? ?? ?? ?? 80 c1 09 8b 3d ?? ?? ?? ?? 2a d3 0f b6 c2 6b d0 42 0f b7 c6 8b 35 ?? ?? ?? ?? 2a d3 80 c2 52 89 54 24 24 88 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DEG_2147762179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DEG!MTB"
        threat_id = "2147762179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FgbVtmd46de" ascii //weight: 1
        $x_1_2 = "jBthatusedoHd" ascii //weight: 1
        $x_1_3 = "s6jpARan" ascii //weight: 1
        $x_1_4 = "c3cmstandard9diwy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Zenpak_DEH_2147762240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DEH!MTB"
        threat_id = "2147762240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dafevoragitaja" ascii //weight: 1
        $x_1_2 = "menanufasixatupofejasinuxawifuca" ascii //weight: 1
        $x_1_3 = "zuxuwozetozofupajib" ascii //weight: 1
        $x_1_4 = "bagurokutifecafuwevirodosaxavuc %s %d %f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_RZ_2147764608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RZ!MTB"
        threat_id = "2147764608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 32 8b 55 f8 02 c2 8b 55 08 32 04 0a 88 01 41 83 6d 0c 01 89 4d 18 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SM_2147773642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SM!MSR"
        threat_id = "2147773642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 94 07 f8 94 08 00 8b 1d ?? ?? ?? 00 88 14 03 81 f9 03 02 00 00 40 3b c1}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 1e 83 ff 19 46 3b f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SM_2147773642_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SM!MSR"
        threat_id = "2147773642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 8b 15 f8 ?? ?? 02 8a 94 0a f8 94 08 00 8b 3d 3c ?? ?? 00 88 14 0f 3d 03 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = "FIZEZUBAREFOGUDUSISELIZIM" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RN_2147794058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RN!MTB"
        threat_id = "2147794058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 50 8a 45 ?? 8a 4d ?? 88 45 ?? 88 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 55 ?? 0f b6 75 ?? 31 f2 88 d0 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CA_2147814127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CA!MTB"
        threat_id = "2147814127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 04 3e 89 75 ?? b8 01 00 00 00 83 f0 04 83 6d ?? 01 8b 75 ?? 85 f6 7d e2}  //weight: 2, accuracy: Low
        $x_2_2 = {3d 32 fe 50 00 75 0c 8b 0d [0-4] 89 0d [0-4] 40 3d 32 89 93 00 7c e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_DA_2147819405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DA!MTB"
        threat_id = "2147819405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 f9 89 55 d0 8b 55 f0 8b 75 d4 0f b6 14 16 8b 75 d0 8b 7d e8 0f b6 34 37 31 f2 88 d7 8b 55 f0 8b 75 dc 88 3c 16 8b 45 f0 05 01 00 00 00 89 45 f0 8b 45 d8 39 45 f0 0f 82}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DC_2147819466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DC!MTB"
        threat_id = "2147819466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 4d dc 89 7d d8 89 55 d4 0f 84}  //weight: 2, accuracy: High
        $x_2_2 = {8b 7d ec 8b 75 d0 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 e0 89 4d dc 89 55 d8 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_DD_2147819591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DD!MTB"
        threat_id = "2147819591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 31 8b 75 c8 01 f1 81 e1 [0-4] 8b 75 ec 8b 5d cc 8a 1c 1e 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 cc 88 1c 31 8b 4d f0 39 cf 8b 4d c4 89 55 d8 89 4d d4 89 7d dc 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DE_2147820406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DE!MTB"
        threat_id = "2147820406"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 31 8b 75 ?? 01 f1 81 e1 [0-4] 8b 75 ?? 8b 5d ?? 8a 1c 1e 8b 75 ?? 32 1c 0e 8b 4d ?? 8b 75 ?? 88 1c 31 8b 4d ?? 39 cf 8b 4d ?? 89 55 ?? 89 4d ?? 89 7d ?? 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DF_2147821122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DF!MTB"
        threat_id = "2147821122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 0c 0f 01 d9 81 ee [0-4] 21 f1 8b 75 e0 8b 5d bc 8a 34 1e 32 34 0f 8b 4d d8 88 34 19 8b 4d b8 8b 75 f0 39 f1 8b 4d b0 8b 75 b8 8b 7d a8 89 4d dc 89 7d cc 89 75 d0 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BN_2147823116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BN!MTB"
        threat_id = "2147823116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LdrLoadDll" ascii //weight: 1
        $x_1_2 = "snxhk.dll" ascii //weight: 1
        $x_1_3 = "FLN=-" ascii //weight: 1
        $x_1_4 = "VirtualQuery" ascii //weight: 1
        $x_1_5 = "FreeConsole" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DG_2147823654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DG!MTB"
        threat_id = "2147823654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d4 88 1c 31 8b 4d f0 39 cf 8b 4d ?? 89 55 ?? 89 4d ?? 89 7d ?? 0f 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DH_2147825407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DH!MTB"
        threat_id = "2147825407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 fe 8b 4d e0 8a 3c 11 8b 75 c8 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 cc 01 f1 81 e1 ff 00 00 00 8b 75 e8 8b 5d d0 8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 8b 4d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SB_2147829255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SB!MTB"
        threat_id = "2147829255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d7 01 f7 81 c7 ?? ?? ?? ?? 8b 37 69 f8 ?? ?? ?? ?? 89 d3 01 fb 8b 3b 69 d8 ?? ?? ?? ?? 01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b 75 c4 01 ce 89 34 24 89 7c 24 04 89 54 24 08 89 45 b4 89 4d b0 89 55 ac e8 ?? ?? ?? ?? 8b 45 ac 8b 4d b0 01 c8 8b 55 b4 81 c2 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 89 45 b8 89 55 bc 0f 84}  //weight: 10, accuracy: Low
        $x_1_2 = "V0ESWYVp3gDrXge1TCseV.pdb" ascii //weight: 1
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BU_2147829917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BU!MTB"
        threat_id = "2147829917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 1c 06 0f b6 fb 01 cf 89 45 d8 31 c9 89 55 d4 89 ca 8b 4d f0 f7 f1 8b 4d ec 0f b6 14 11 01 d7 89 f8 99 8b 7d d4 f7 ff 8a 3c 16 8b 4d d8 88 3c 0e 88 1c 16 81 c1 01 00 00 00 81 f9 00 01 00 00 89 55 e0 89 4d dc 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BS_2147831763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BS!MTB"
        threat_id = "2147831763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75}  //weight: 3, accuracy: High
        $x_1_2 = "wasqwhereinRforthwassubdueseasons" wide //weight: 1
        $x_1_3 = "self exe" wide //weight: 1
        $x_1_4 = "PqIGZI/eSemXqTtWN.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BT_2147832129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BT!MTB"
        threat_id = "2147832129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 ce 81 e6 ff 00 00 00 8b 8d ec fe ff ff 8b 9d c0 fe ff ff 8a 0c 19 32 8c 35 f4 fe ff ff 8b b5 e8 fe ff ff 88 0c 1e 8b 8d f0 fe ff ff 39 cf 8b 8d [0-4] 89 95 [0-4] 89 8d [0-4] 89 bd [0-4] 0f}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BR_2147832142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BR!MTB"
        threat_id = "2147832142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 fe 81 e6 [0-4] 8b bd [0-4] 8b 8d [0-4] 8a 1c 0f 32 9c 35 [0-4] 8b b5 [0-4] 88 1c 0e 81 c1 01 00 00 00 8b b5 [0-4] 39 f1 8b b5}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BQ_2147832143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BQ!MTB"
        threat_id = "2147832143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 7d ec 8b 75 d0 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 d0 88 1c 31 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 e0 89 4d dc 89 55 d8 0f}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MP_2147832271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MP!MTB"
        threat_id = "2147832271"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f9 60 68 54 b1 45 0d 76 ab a7 98 eb 01 d4 34 d5 5c 4f d7 64 41 3e 34 5e 34 b1 1c de 17 f0 05 76}  //weight: 1, accuracy: High
        $x_1_2 = "l@rJQRY3CdQ_EiVbiaMEXwK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RO_2147833783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RO!MTB"
        threat_id = "2147833783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 24 0a 28 c4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 24 0e 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RB_2147833792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RB!MTB"
        threat_id = "2147833792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 20 29 c2 4a e8 21 00 00 00 c3 31 c2 01 c2 42 31 1d ?? ?? ?? ?? b8 06 00 00 00 8d 05 ?? ?? ?? ?? 01 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RB_2147833792_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RB!MTB"
        threat_id = "2147833792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e1 c7 41 08 00 00 00 00 c7 41 04 41 01 00 00 c7 01 c7 b6 ?? 00 8b 0d ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? ff d1 83 ec 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RB_2147833792_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RB!MTB"
        threat_id = "2147833792"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 f0 5c 00 00 00 89 d7 01 f7 81 c7 34 00 00 00 8b 37 69 f8 5c 00 00 00 01 fa 81 c2 30 00 00 00 0f b7 12 31 f2 01 ca 05 01 00 00 00 3d 27 03 00 00 89 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MA_2147834061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MA!MTB"
        threat_id = "2147834061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 f4 89 4d f0 89 55 ec 89 7d e8 89 75 e4 74 2b 8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2}  //weight: 10, accuracy: High
        $x_5_2 = {09 08 00 00 05 00 00 20 14 00 00 02 00 00 24 11 00 00 00 10}  //weight: 5, accuracy: High
        $x_1_3 = "GetOpenFileNameA" ascii //weight: 1
        $x_1_4 = "Module32NextW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MB_2147834148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MB!MTB"
        threat_id = "2147834148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 55 08 31 f6 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 3d 00 00 00 00 89 45 f4 89 4d f0 89 55 ec 89 75 e8 74 1e 8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75}  //weight: 10, accuracy: Low
        $x_5_2 = {0b 01 09 07 00 20 00 00 00 70 12 00 00 02 00 00 e8 11 00 00 00 10 00 00 00 30}  //weight: 5, accuracy: High
        $x_1_3 = "IsWinEventHookInstalled" ascii //weight: 1
        $x_1_4 = "GetLogicalDrives" ascii //weight: 1
        $x_1_5 = "FreeCredentialsHandle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_B_2147835428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.B!MTB"
        threat_id = "2147835428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IMoving.heavenpum" ascii //weight: 1
        $x_1_2 = "HaveDJU4EaRgmultiply" ascii //weight: 1
        $x_1_3 = "ELessermovethfirsthimRpBia" ascii //weight: 1
        $x_1_4 = "8ownmanhone,formseedx" ascii //weight: 1
        $x_1_5 = "ofsayingfNmovedseas" ascii //weight: 1
        $x_1_6 = "midstthattherew" ascii //weight: 1
        $x_1_7 = "ztheregrasscreatedm" ascii //weight: 1
        $x_1_8 = "qYIxUBeginningmhimearth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SP_2147835598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SP!MTB"
        threat_id = "2147835598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 08 8b 0d 04 d5 58 00 8a 8c 01 d6 38 00 00 8b 15 7c 7e 58 00 88 0c 02 c9 c2 04 00}  //weight: 3, accuracy: High
        $x_2_2 = "sugitozegitofa-pece.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_C_2147835637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.C!MTB"
        threat_id = "2147835637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8 75 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_C_2147835637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.C!MTB"
        threat_id = "2147835637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uevery4dividedgreatherb" ascii //weight: 1
        $x_1_2 = "ymHimtvPgatheringgreat" ascii //weight: 1
        $x_1_3 = "nyieldingAusydivide" ascii //weight: 1
        $x_1_4 = "6StarsseaGsubduej" ascii //weight: 1
        $x_1_5 = "Xrule4KgivenlightVoidyieldingW" ascii //weight: 1
        $x_1_6 = "kmakegiveny7f" ascii //weight: 1
        $x_1_7 = "sooverkinfowl" ascii //weight: 1
        $x_1_8 = "wereidominion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTM_2147836298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTM!MTB"
        threat_id = "2147836298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "e0XMovingsixththe5d" ascii //weight: 1
        $x_1_2 = "X2firmamentGflyus9" ascii //weight: 1
        $x_1_3 = "nspiritkCattlevHgathering" ascii //weight: 1
        $x_1_4 = "treelandfishmCattleWere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AH_2147836400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AH!MTB"
        threat_id = "2147836400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "7kLgreatTfruitface.lifefrom" ascii //weight: 2
        $x_2_2 = "Ir&WJs%F3" ascii //weight: 2
        $x_2_3 = "3_KIg7mWNdtiyihEv*@/C.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RK_2147836567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RK!MTB"
        threat_id = "2147836567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 83 c2 04 83 f0 07 89 25 ?? ?? ?? ?? 48 83 e8 09 e8 2e 00 00 00 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RK_2147836567_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RK!MTB"
        threat_id = "2147836567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 8b 44 24 ?? 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 ?? 29 c1 89 c8 83 e8 ?? 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RK_2147836567_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RK!MTB"
        threat_id = "2147836567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 88 45 ?? 89 4d ?? 89 55 ?? 89 75 ?? 8b 4d ?? 8b 55 ?? 0f b6 0c ?? 0f b6 55 ?? 29 d1 88 c8 88 45 fb 8a 45 fb 8b 4d f4 8b 55 e8 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RC_2147836896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RC!MTB"
        threat_id = "2147836896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 02 6b c2 12 8b 4c 24 ?? 29 c1 89 c8 83 e8 04 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RC_2147836896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RC!MTB"
        threat_id = "2147836896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 02 6b c2 12 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RC_2147836896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RC!MTB"
        threat_id = "2147836896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 18 ba 09 00 00 00 83 e8 06 42 83 c0 03 01 2d ?? ?? ?? ?? 83 ea 01 4a 8d 05 ?? ?? ?? ?? 31 38 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RC_2147836896_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RC!MTB"
        threat_id = "2147836896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c2 40 89 1d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 28 83 c0 02 31 3d ?? ?? ?? ?? ba 06 00 00 00 89 d0 48 89 f0 50 8f 05 ?? ?? ?? ?? e8 ?? ?? ff ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RC_2147836896_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RC!MTB"
        threat_id = "2147836896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 b8 07 00 00 00 29 c2 8d 05 ?? ?? ?? ?? 89 38 83 f0 04 42 89 c2 89 e8 50 8f 05 ?? ?? ?? ?? 31 c2 48 31 35 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_D_2147837083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.D!MTB"
        threat_id = "2147837083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 8b 4d e4 8b 55 e0 01 ca 89 15 ?? ?? ?? ?? 8b 4d ec 8a 1c 01 8b 55 e8 88 1c 02 05 01 00 00 00 8b 75 f0 39 f0 89 45 d8 74 19}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_D_2147837083_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.D!MTB"
        threat_id = "2147837083"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hQT]!H2G" ascii //weight: 1
        $x_1_2 = "RjPkEQM" ascii //weight: 1
        $x_1_3 = "7kLgreatTfruitface.lifefrom" ascii //weight: 1
        $x_1_4 = "%MrR<LUWn2Guf" wide //weight: 1
        $x_1_5 = "aFP5$3+r#U9R7" ascii //weight: 1
        $x_1_6 = "\\TMTn8\\7lrsXSG\\Qd.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RH_2147837206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RH!MTB"
        threat_id = "2147837206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 8b 44 24 ?? 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 ?? 29 c1 89 c8 83 e8 0a 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RH_2147837206_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RH!MTB"
        threat_id = "2147837206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 d0 83 f2 08 01 35 ?? ?? ?? ?? 01 d0 b8 09 00 00 00 48 ba 06 00 00 00 89 f8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 28 b9 02 00 00 00 e2 bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RH_2147837206_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RH!MTB"
        threat_id = "2147837206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 07 00 00 00 83 c0 0a 31 1d ?? ?? ?? ?? 42 31 d0 8d 05 ?? ?? ?? ?? 01 28 8d 05 ?? ?? ?? ?? 01 30 8d 05 ?? ?? ?? ?? ff d0 89 d0 8d 05 ?? ?? ?? ?? 01 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RI_2147837496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RI!MTB"
        threat_id = "2147837496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 6c 0c 00 00 88 45 ff 8a 45 ff 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RI_2147837496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RI!MTB"
        threat_id = "2147837496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 89 88 88 88 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 ?? 29 c1 89 c8 83 e8 04 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RI_2147837496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RI!MTB"
        threat_id = "2147837496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 cd cc cc cc 89 44 24 ?? f7 e1 c1 ea 04 6b c2 14 8b 4c 24 ?? 29 c1 89 c8 83 e8 0b 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RI_2147837496_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RI!MTB"
        threat_id = "2147837496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 8b 44 24 ?? 29 d0 d1 e8 01 d0 c1 e8 04 6b c0 13 8b 4c 24 ?? 29 c1 89 c8 83 e8 07 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RI_2147837496_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RI!MTB"
        threat_id = "2147837496"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 84 24 a8 00 00 00 b9 39 8e e3 38 89 84 24 a4 00 00 00 f7 e1 c1 ea 02 6b c2 12 8b 8c 24 a4 00 00 00 29 c1 89 c8 83 e8 0b 89 8c 24 a0 00 00 00 89 84 24 9c 00 00 00 74 7f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RJ_2147837691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RJ!MTB"
        threat_id = "2147837691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 6d 78 29 cc 89 44 24 ?? 89 c8 f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 02 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBA_2147837795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBA!MTB"
        threat_id = "2147837795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 3b 45 fc 74 1f 8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_F_2147837852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.F!MTB"
        threat_id = "2147837852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 3c 06 01 d7 89 45 d4 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_F_2147837852_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.F!MTB"
        threat_id = "2147837852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "2UlightsfourthuTqseedW" wide //weight: 1
        $x_1_2 = "givestarsgodundersecondw4vdQ" wide //weight: 1
        $x_1_3 = "eseedappearwhaleswas" ascii //weight: 1
        $x_1_4 = "landATalso1fruitbeast" wide //weight: 1
        $x_1_5 = "uNmovethGherbgatheredMFsea" ascii //weight: 1
        $x_1_6 = "cattlehe.maSoforyou.realsobroughtZ" wide //weight: 1
        $x_1_7 = "day,creepethdivide.iBMan.winged.Klikeness,Z" wide //weight: 1
        $x_1_8 = "Mtgreen5moved.rDalllife" wide //weight: 1
        $x_1_9 = "seasons.8sixthPUSs0" ascii //weight: 1
        $x_1_10 = "you.llEiForth.veryG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AI_2147838137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AI!MTB"
        threat_id = "2147838137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 84 24 94 00 00 00 b9 6d 78 29 cc 89 44 24 24 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 24 29 c1 89 c8 83 e8 05 89 4c 24 20 89 44 24 1c 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 44 24 24 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 24 29 c1 89 c8 83 e8 05 89 4c 24 20 89 44 24 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 f1 8b 75 ec 8b 5d d0 8a 34 1e 32 34 0f 8b 4d e8 88 34 19 8b 4d c0 8b 75 f0 39 f1 8b 4d b8 8b 75 b0 8b 7d c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 ?? 29 c1 89 c8 83 e8 0e 89 4c 24 ?? 89 44 24 ?? 74 43 eb 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 8d 8d fc fe ff ff 81 c1 03 00 00 00 8a 95 ff fe ff ff 80 fa 4d 89 85 d8 fe ff ff 89 8d ?? fe ff ff 88 95 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e0 c7 40 14 57 03 00 00 c7 40 10 57 03 00 00 c7 40 0c 57 03 00 00 c7 40 08 57 03 00 00 c7 40 04 57 03 00 00 c7 00 57 03 00 00 a1 ?? ?? ?? ?? ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 6d 78 29 cc 89 44 24 ?? f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 ?? 29 c1 89 c8 83 e8 0d 89 4c 24 ?? 89 44 24 ?? 74 43}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RA_2147838281_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RA!MTB"
        threat_id = "2147838281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 0c 8d 8d fc fe ff ff 81 c1 03 00 00 00 8a 95 ff fe ff ff 80 fa 4d 0f 94 c6 89 85 ?? fe ff ff 89 8d ?? fe ff ff 88 95 ?? fe ff ff 88 b5 ?? fe ff ff 8a 85 ?? fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AJ_2147838710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AJ!MTB"
        threat_id = "2147838710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 64 b9 6d 78 29 cc 89 44 24 1c f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 1c 29 c1 83 e9 05 89 4c 24 18 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPQA_2147838946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPQA!MTB"
        threat_id = "2147838946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vsstarsmorning.Darkness" wide //weight: 1
        $x_1_2 = "erd5Pplace1Lessera" wide //weight: 1
        $x_1_3 = "themFilleBeginningwmaya" wide //weight: 1
        $x_1_4 = "lightSuntoixQeveningdarkness4Firmament" wide //weight: 1
        $x_1_5 = "4isfirst" wide //weight: 1
        $x_1_6 = "hadheavenkindmkind" wide //weight: 1
        $x_1_7 = "maleall.lesserlandAndcreatedXsb" wide //weight: 1
        $x_1_8 = "txFS*VECYCewJClW-v01/V90UdoS+.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AK_2147839014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AK!MTB"
        threat_id = "2147839014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 6d 78 29 cc 89 44 24 30 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 30 29 c1 89 c8 83 e8 0e 89 4c 24 2c 89 44 24 28 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AL_2147839169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AL!MTB"
        threat_id = "2147839169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 f8 b9 ab aa aa aa 89 45 ec f7 e1 c1 ea 03 6b c2 0c 8b 4d ec 29 c1 89 c8 83 e8 05 89 4d e8 89 45 e4 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AM_2147839170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AM!MTB"
        threat_id = "2147839170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 6d 78 29 cc 8b 4c 24 50 89 44 24 4c 89 c8 8b 54 24 4c f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 06 89 4c 24 48 89 44 24 44 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AN_2147839232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AN!MTB"
        threat_id = "2147839232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc b9 6d 78 29 cc 89 45 f0 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d f0 29 c1 89 c8 83 e8 0e 89 4d ec 89 45 e8 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AO_2147839257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AO!MTB"
        threat_id = "2147839257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 84 24 8c 00 00 00 b9 6d 78 29 cc 89 44 24 40 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 40 29 c1 89 c8 83 e8 06 89 4c 24 3c 89 44 24 38 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AP_2147839350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AP!MTB"
        threat_id = "2147839350"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 6d 78 29 cc 89 44 24 38 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 38 29 c1 89 c8 83 e8 07 89 4c 24 34 89 44 24 30 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 8b ec 51 e8 47 54 00 00 89 25 38 3e 43 00 89 2d 3c 3e 43 00 e8 99 53 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 06 83 f2 07 31 d0 e8 1c 00 00 00 4a 83 e8 03 8d 05 ?? ?? ?? ?? 31 28 01 d0 01 d0 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 d1 e9 ba 93 24 49 92 89 [0-6] 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b [0-6] 29 c1 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 28 48 31 c2 83 c0 04 40 89 35 ?? ?? ?? ?? 29 c2 48 89 d0 01 3d ?? ?? ?? ?? b9 02 00 00 00 e2 c2 89 45 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d0 29 c2 8d 05 ?? ?? ?? ?? 31 30 31 2d ?? ?? ?? ?? 40 40 01 d0 8d 05 ?? ?? ?? ?? 89 38 40 8d 05 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 89 88 88 88 89 84 24 ?? ?? 00 00 f7 e1 c1 ea 03 6b c2 0f 8b 8c 24 ?? ?? 00 00 29 c1 89 c8 83 e8 06 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RD_2147839393_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RD!MTB"
        threat_id = "2147839393"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 b9 90 00 00 00 8d 54 24 20 be 60 00 00 00 8d bc 24 68 02 00 00 89 3c 24 c7 44 24 04 00 00 00 00 c7 44 24 08 60 00 00 00 89 44 24 1c 89 4c 24 18 89 54 24 14 89 74 24 10 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AQ_2147839440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AQ!MTB"
        threat_id = "2147839440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AQ_2147839440_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AQ!MTB"
        threat_id = "2147839440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 6d 78 29 cc 89 44 24 64 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 64 29 c1 89 c8 83 e8 0d 89 4c 24 60 89 44 24 5c 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GDL_2147839602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GDL!MTB"
        threat_id = "2147839602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f8 89 c1 d1 e9 ba 93 24 49 92 89 45 ec 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b 4d ec 29 c1 89 c8 83 e8 0a 89 4d e8 89 45 e4 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MC_2147839830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MC!MTB"
        threat_id = "2147839830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 eb ?? 89 2d 70 e0 56 00 58 a3 6c e0 56 00 ba 04 00 00 00 01 15 70 e0 56 00 66 6a 0a 50 e8 ?? ?? ?? ?? 89 d9 89 0d 68 e0 56 00 89 f1 89 0d 60 e0 56 00 89 3d 64 e0 56 00 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AR_2147840419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AR!MTB"
        threat_id = "2147840419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 39 8e e3 38 89 45 e4 f7 e1 c1 ea 02 6b c2 12 8b 4d e4 29 c1 89 c8 83 e8 02 89 4d e0 89 45 dc 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 38 83 f2 07 83 f2 04 8d 05 ?? ?? ?? ?? 01 30 01 c2 83 c2 03 48 89 d8 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 c3 83 f2 02 83 c2 09 83 f0 08 01 1d ?? ?? ?? ?? 40 89 3d ?? ?? ?? ?? b9 02 00 00 00 e2 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 55 89 e5 50 8b 45 08 31 c9 81 c1 18 00 00 00 89 45 fc 8b 45 fc 05 d0 00 00 00 05 e0 00 00 00 01 c8 89 45 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 89 88 88 88 89 45 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4d ?? 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 89 88 88 88 89 44 24 ?? f7 e1 c1 ea 03 6b c2 0f 8b 4c 24 ?? 29 c1 83 c9 04 83 e9 07 89 4c 24 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 8b 55 ?? f7 e2 c1 ea 02 6b c2 12 29 c1 89 c8 83 e8 02 89 4d ?? 89 45 ?? 0f 84 ?? ?? ff ff eb 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 f1 f0 f0 f0 89 44 24 ?? f7 e1 c1 ea 04 6b c2 11 8b 4c 24 ?? 29 c1 89 c8 83 e8 ?? 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 fb 01 fe 81 e6 ff 00 00 00 8b 3d ?? ?? ?? ?? 81 c7 9e f4 ff ff 89 3d ?? ?? ?? ?? 8b 7d ec 8a 1c 0f 8b 7d e4 32 1c 37 8b 75 e8 88 1c 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 09 83 f0 08 8d 05 ?? ?? ?? ?? 89 28 8d 05 ?? ?? ?? ?? 31 18 83 f2 07 40 40 01 3d ?? ?? ?? ?? 31 c2 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 b8 0f 94 c1 88 8d ?? fe ff ff b8 01 00 00 00 8a 8d ?? fe ff ff f6 c1 01 89 85 ?? fe ff ff 75 ?? eb 05 00 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c2 ba 0a 00 00 00 31 25 ?? ?? ?? ?? 29 c2 4a 01 d0 b9 02 00 00 00 e2 21 01 d0 89 f8 50 8f 05 ?? ?? ?? ?? ba 04 00 00 00 b8 05 00 00 00 31 1d ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RF_2147840501_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RF!MTB"
        threat_id = "2147840501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 29 d0 89 1d ?? ?? ?? ?? 4a 8d 05 ?? ?? ?? ?? 89 30 e9 ?? ?? ff ff c3 42 29 d0 29 d0 31 2d ?? ?? ?? ?? 31 c2 89 d0 83 e8 07 8d 05 ?? ?? ?? ?? 31 38 e8 ?? ff ff ff c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AS_2147840502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AS!MTB"
        threat_id = "2147840502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d fc ba 6d 78 29 cc 89 45 c8 89 c8 f7 e2 c1 ea 08 69 c2 41 01 00 00 29 c1 89 c8 83 e8 13 89 4d c4 89 45 c0 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MD_2147840714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MD!MTB"
        threat_id = "2147840714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 fc b9 6d 78 29 cc 89 45 d8 f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d d8 29 c1 89 c8 83 e8 08 89 4d d4 89 45 d0 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AT_2147841286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AT!MTB"
        threat_id = "2147841286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 5c b9 [0-4] 89 44 24 58 f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 58 29 c1 89 c8 83 e8 09 89 4c 24 54 89 44 24 50 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ME_2147841722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ME!MTB"
        threat_id = "2147841722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 e0 b9 ab aa aa aa 89 45 ec f7 e1 c1 ea 03 6b c2 0c 8b 4d ec 29 c1 89 c8 83 e8 04 89 4d d8 89 45 d4 74 86 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AU_2147841774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AU!MTB"
        threat_id = "2147841774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 48 b9 ab aa aa aa 89 44 24 44 f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 44 29 c1 89 c8 83 e8 04 89 4c 24 40 89 44 24 3c 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MF_2147842125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MF!MTB"
        threat_id = "2147842125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 e0 b9 ab aa aa aa 89 45 dc f7 e1 c1 ea 03 6b c2 0c 8b 4d dc 29 c1 89 c8 83 e8 09 89 4d d8 89 45 d4 74 2e eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GFK_2147842191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GFK!MTB"
        threat_id = "2147842191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 89 c2 40 8d 05 ?? ?? ?? ?? 01 38 29 c2 83 f2 ?? 31 35 ?? ?? ?? ?? 83 f0 ?? 8d 05 ?? ?? ?? ?? 89 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MG_2147842258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MG!MTB"
        threat_id = "2147842258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 ec b9 ab aa aa aa 89 45 d8 f7 e1 c1 ea 03 6b c2 0c 8b 4d d8 29 c1 89 4d d4 74 81}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AW_2147842504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AW!MTB"
        threat_id = "2147842504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 ec b9 ab aa aa aa 89 45 e4 f7 e1 c1 ea 03 6b c2 0c 8b 4d e4 29 c1 89 c8 83 e8 09 89 4d e0 89 45 dc 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AV_2147843096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AV!MTB"
        threat_id = "2147843096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 05 98 15 54 00 31 18 01 d0 31 c2 89 f0 50 8f 05 90 15 54 00 31 3d 94 15 54 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {86 4b 14 00 70 4b 14 00 54 4b 14 00 42 4b 14 00 2e 4b 14 00 1a 4b 14 00 04 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GFU_2147843098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GFU!MTB"
        threat_id = "2147843098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 18 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? ff e0 31 c2 01 3d ?? ?? ?? ?? b8 09 00 00 00 4a 83 c2 0a 31 2d ?? ?? ?? ?? eb}  //weight: 10, accuracy: Low
        $x_1_2 = "sonemidstfor3wfrom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GHA_2147843688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GHA!MTB"
        threat_id = "2147843688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 f0 33 d2 6a 20 59 f7 f1 8b 45 ec 0f b6 04 10 8b 4d f4 03 4d f0 0f b6 09 2b c8 8b 45 f4 03 45 f0 88 08 eb}  //weight: 10, accuracy: High
        $x_1_2 = "C:\\Windows\\Opengl_3.0.1.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GHC_2147843804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GHC!MTB"
        threat_id = "2147843804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c2 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 8b c2 c1 e8 ?? 03 c3 03 ca 89 44 24 ?? 33 c8 8b 44 24 ?? 33 c1 c7 05 ?? ?? ?? ?? 19 36 6b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 2b f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPH_2147846052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPH!MTB"
        threat_id = "2147846052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 57 6a 40 68 00 30 00 00 68 1c dc 04 00 6a 00 8b f9 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75}  //weight: 1, accuracy: Low
        $x_1_2 = "125.124.86.31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GID_2147846583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GID!MTB"
        threat_id = "2147846583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f2 05 01 25 ?? ?? ?? ?? 83 ea 07 e8 ?? ?? ?? ?? 29 d0 29 d0 89 2d ?? ?? ?? ?? 83 e8 0a 8d 05 ?? ?? ?? ?? 31 38 8d 05 ?? ?? ?? ?? 89 30 48 40 83 c2 03 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff d0 b9 02 00 00 00 e2 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_EQ_2147846596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.EQ!MTB"
        threat_id = "2147846596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "139.224.13.184/jzq/brian.jpg" ascii //weight: 2
        $x_2_2 = "Users\\Public\\Documents\\brian.jpg" ascii //weight: 2
        $x_2_3 = "4-27.oss-cn-hangzhou.aliyuncs.com" ascii //weight: 2
        $x_2_4 = "Users\\Public\\Documents\\md.jpg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AX_2147846783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AX!MTB"
        threat_id = "2147846783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d7 01 f7 81 c7 [0-4] 69 f0 88 00 00 00 01 f2 81 c2 [0-4] 05 01 00 00 00 8b 12 0f b7 37 31 d6 01 ce 3d c0 00 00 00 89 f1 89 4d cc 89 75 c4 89 45 c8 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_E_2147846850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.E!MTB"
        threat_id = "2147846850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 e4 8b 75 c4 8a 0c 32 32 0c 1f 8b 5d e0 88 0c 33 c7 05 ?? ?? ?? ?? 37 22 00 00 81 c6 01 00 00 00 8b 55 f0 39 d6 89 75 c8 0f 84 f3 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_E_2147846850_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.E!MTB"
        threat_id = "2147846850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UgB{zCXHy" ascii //weight: 1
        $x_1_2 = "F01OwGe>@" ascii //weight: 1
        $x_1_3 = "7kLgreatTfruitface.lifefrom" ascii //weight: 1
        $x_1_4 = "%MrR<LUWn2Guf" wide //weight: 1
        $x_1_5 = "aFP5$3+r#U9R7" ascii //weight: 1
        $x_1_6 = "\\TMTn8\\7lrsXSG\\Qd.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAP_2147847067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAP!MTB"
        threat_id = "2147847067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d ec 8b 75 c8 8a 1c 37 8b 75 e4 32 1c 0e 8b 4d e8 8b 75 c8 88 1c 31 c7 05 [0-4] f6 06 00 00 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d c4 89 75 d8 89 4d d4 89 55 d0 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RE_2147847089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RE!MTB"
        threat_id = "2147847089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 07 31 35 ?? ?? ?? ?? 4a 89 d0 42 8d 05 ?? ?? ?? ?? 89 38 8d 05 ?? ?? ?? ?? 01 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RE_2147847089_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RE!MTB"
        threat_id = "2147847089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 d1 e9 ba 93 24 49 92 89 [0-6] 89 c8 f7 e2 c1 ea 02 6b c2 0e 8b [0-6] 29 c1 89 c8 83 e8 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RE_2147847089_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RE!MTB"
        threat_id = "2147847089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 03 8d 05 ?? ?? ?? ?? 31 18 40 40 83 f0 03 8d 05 ?? ?? ?? ?? 01 30 ba 05 00 00 00 83 f0 04 31 d0 8d 05 ?? ?? ?? ?? 89 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RE_2147847089_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RE!MTB"
        threat_id = "2147847089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0c 1e 8b 7d e4 8b 5d d0 32 0c 1f 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 32 28 00 00 8b 55 e0 88 0c 1a c7 05 ?? ?? ?? ?? f4 04 00 00 8b 4d cc 8b 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GHJ_2147847950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GHJ!MTB"
        threat_id = "2147847950"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 e0 61 c6 45 e1 6d c6 45 e2 44 c6 45 e3 61 c6 45 e4 74 c6 45 e5 61 c6 45 e6 5c c6 45 e7 77 c6 45 e8 69 c6 45 e9 6e c6 45 ea 6e c6 45 eb 74 c6 45 ec 5c c6 45 ed 6d c6 45 ee 75 c6 45 ef 73 c6 45 f0 69 c6 45 f1 63 c6 45 f2 2e c6 45 f3 65 c6 45 f4 78 c6 45 f5 65}  //weight: 10, accuracy: High
        $x_1_2 = "cmd /c start C:\\ProgramData\\114514" ascii //weight: 1
        $x_1_3 = "cmd /c taskkill /f /t /im mmc.exe" ascii //weight: 1
        $x_1_4 = "C:\\ProgramData\\114514" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GJN_2147848445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GJN!MTB"
        threat_id = "2147848445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e0 50 8f 05 ?? ?? ?? ?? eb ?? 42 42 83 c0 07 8d 05 ?? ?? ?? ?? 31 28 e8 ?? ?? ?? ?? c3 48 48 29 c2 31 35 ?? ?? ?? ?? 83 e8 01 40 01 1d ?? ?? ?? ?? 31 c2 31 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GJS_2147848749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GJS!MTB"
        threat_id = "2147848749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 6c 88 44 24 ?? 88 44 24 ?? 88 44 24 ?? 8d 44 24 ?? 50 c6 44 24 ?? 56 c6 44 24 ?? 69 c6 44 24 ?? 72 c6 44 24 ?? 74 c6 44 24 ?? 75 c6 44 24 ?? 61 c6 44 24 ?? 41 c6 44 24 ?? 6f c6 44 24 ?? 63 c6 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAQ_2147849528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAQ!MTB"
        threat_id = "2147849528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 c2 29 c2 89 35 [0-4] 8d 05 [0-4] ff e0 29 c2 48 31 1d [0-4] 8d 05 [0-4] 01 38 ba 05 00 00 00 b8 08 00 00 00 89 d0 40 8d 05 [0-4] 01 28 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAR_2147849529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAR!MTB"
        threat_id = "2147849529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 1c 37 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 c7 05 [0-4] f6 06 00 00 81 c6 01 00 00 00 8b 4d f0 39 ce 8b 4d cc 89 75 dc 89 4d ec 89 55 d8 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CRTF_2147849611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CRTF!MTB"
        threat_id = "2147849611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 42 31 2d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 00 af}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAS_2147850022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAS!MTB"
        threat_id = "2147850022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8a 4c 24 08 30 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 c0 50 8d 0c 37 51 e8 ?? ff ff ff 83 c4 08 83 ee 01 79}  //weight: 1, accuracy: Low
        $x_1_3 = "xabikugikijabesogutuyozu konipihowuso cegutosixuxacojofodagoluhitokiho nizezigesoje" ascii //weight: 1
        $x_1_4 = "hamocugorozotahujamijurukukiyi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GKH_2147850656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GKH!MTB"
        threat_id = "2147850656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4f 70 65 6e 88 5d ec c7 45 ?? 49 6e 74 65 c7 45 ?? 72 6e 65 74 c7 45 ?? 43 6f 6e 6e c7 45 ?? 65 63 74 00 c7 45 ?? 46 74 70 4f c7 45 ?? 70 65 6e 46 c7 45 ?? 69 6c 65 00 c7 45 ?? 49 6e 74 65 c7 45 ?? 72 6e 65 74 c7 45 ?? 52 65 61 64 c7 45 ?? 46 69 6c 65 88 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBGV_2147851217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBGV!MTB"
        threat_id = "2147851217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d ec 8a 1c 0f 8b 7d e4 32 1c 37 8b 75 e8 88 1c 0e 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c1 01 00 00 00 8b 75 f0 39 f1 8b 75 d0 89 4d e0 89 75 dc 89 55 d8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAT_2147851288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAT!MTB"
        threat_id = "2147851288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 bc 8b 08 8b 55 c4 8b 32 8b 7d cc 8b 1f 8b 02 8b 55 b8 8b 12 8b 7d c8 8b 3f 0f b6 04 03 0f b6 0c 11 31 c8 88 04 37 e9}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4d c4 8b 11 2d [0-4] 01 c2 89 55 ac 8b 45 c4 8b 4d ac 89 08 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CAU_2147851308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CAU!MTB"
        threat_id = "2147851308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 7d e8 8a 1c 0f 8b 7d e0 32 1c 37 8b 75 e4 88 1c 0e c7 05 [0-4] 33 00 00 00 81 c1 01 00 00 00 8b 75 f0 39 f1 8b 75 d0 89 4d ec 89 75 dc 89 55 d8 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNR_2147851742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNR!MTB"
        threat_id = "2147851742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 29 c2 29 c2 8d 05 ?? ?? ?? ?? 31 38 31 c2 31 d0 89 35 ?? ?? ?? ?? 83 c2 03 83 f2 08 01 2d ?? ?? ?? ?? 40 29 d0 31 d0 8d 05 ?? ?? ?? ?? 89 18}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBHJ_2147851812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBHJ!MTB"
        threat_id = "2147851812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 02 8a 8c 32 4b 13 01 00 8b 15 e0 ?? 7d 02 88 0c 32 3d a8 00 00 00 75 [0-18] 50 ff d7 a1 a8 ?? 7d 02 46 3b f0 72}  //weight: 1, accuracy: Low
        $x_1_2 = "ejet sazimofizuvavavalovisecokifilos" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNS_2147852121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNS!MTB"
        threat_id = "2147852121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {42 40 8d 05 ?? ?? ?? ?? 89 18 83 c2 ?? 31 c2 4a 31 2d ?? ?? ?? ?? 29 d0 31 d0 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 83 e8 ?? 31 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNS_2147852121_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNS!MTB"
        threat_id = "2147852121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c6 d3 e8 8d 14 37 8b cd 89 54 24 ?? 89 44 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNW_2147852736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNW!MTB"
        threat_id = "2147852736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 01 25 ?? ?? ?? ?? 48 e8 ?? ?? ?? ?? 4a 42 8d 05 ?? ?? ?? ?? 31 30 29 d0 31 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 d0 31 2d ?? ?? ?? ?? 83 c2 0a b8 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNZ_2147852828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNZ!MTB"
        threat_id = "2147852828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 83 f0 09 42 40 01 2d ?? ?? ?? ?? 31 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff d0 83 f0 03 4a 89 1d ?? ?? ?? ?? b8 ?? ?? ?? ?? 83 f2 05 83 f0 03 01 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CBYB_2147853118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CBYB!MTB"
        threat_id = "2147853118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4a 42 83 ea 08 01 35 ?? ?? ?? ?? 83 ea 07 83 f0 07 b8 03 00 00 00 8d 05 ?? ?? ?? ?? 31 18 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDE_2147888241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDE!MTB"
        threat_id = "2147888241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 0e 8b 75 e0 32 1c 3e 8b 7d e4 88 1c 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_DAX_2147888475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.DAX!MTB"
        threat_id = "2147888475"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d d4 8a 0c 0b 8b 5d e0 32 0c 33 8b 75 e4 8b 5d d4 88 0c 1e c7 05 [0-4] 33 00 00 00 8b 4d f0 39 cf 8b 4d d0 89 55 ec 89 4d dc 89 7d d8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CBYE_2147888591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CBYE!MTB"
        threat_id = "2147888591"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e2 2c 40 31 35 ?? ?? ?? ?? 83 c2 04 83 e8 03 31 d0 4a 89 e8 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPB_2147889015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPB!MTB"
        threat_id = "2147889015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1c 0e 8b 75 ?? 32 1c 3e 8b 7d ?? 88 1c 0f c7 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMH_2147889129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMH!MTB"
        threat_id = "2147889129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 c6 85 91 ?? ?? ?? 6e c6 85 92 ?? ?? ?? 74 c6 85 93 ?? ?? ?? 65 c6 85 94 ?? ?? ?? 72 c6 85 95 ?? ?? ?? 6e c6 85 96 ?? ?? ?? 65 c6 85 97 ?? ?? ?? 74 c6 85 98 ?? ?? ?? 52 c6 85 99 ?? ?? ?? 65 c6 85 9a ?? ?? ?? 61 c6 85 9b ?? ?? ?? 64 c6 85 9c ?? ?? ?? 46 c6 85 9d ?? ?? ?? 69 c6 85 9e ?? ?? ?? 6c c6 85 9f ?? ?? ?? 65 c6 85 a0 ?? ?? ?? 00 6a 00 6a 00 6a 00 6a 00 8d 8d ?? ?? ?? ?? 51 ff 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCAE_2147889146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCAE!MTB"
        threat_id = "2147889146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kuuslivingm" ascii //weight: 1
        $x_1_2 = "Saj3VyhaduponYV" ascii //weight: 1
        $x_1_3 = "BCUntoIThatN" ascii //weight: 1
        $x_1_4 = "can.tThemSw" ascii //weight: 1
        $x_1_5 = "broughtgood76for5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNA_2147889302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNA!MTB"
        threat_id = "2147889302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 18 31 d0 31 c2 83 f2 ?? 31 c2 31 2d ?? ?? ?? ?? 31 d0 89 35 ?? ?? ?? ?? 31 c2 42 83 c0 ?? 89 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNA_2147889302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNA!MTB"
        threat_id = "2147889302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b b5 ec fe ff ff 8b 8d c0 fe ff ff 8a 1c 0e 32 9c 3d f4 fe ff ff 8b bd e8 fe ff ff 88 1c 0f 81 c1 01 00 00 00 8b b5 f0 fe ff ff 39 f1 8b b5 bc}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_H_2147889361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.H!MTB"
        threat_id = "2147889361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 28 8d 05 ?? ?? ?? ?? 31 30 8d 05 ?? ?? ?? ?? 01 18 8d 05 ?? ?? ?? ?? 31 38 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_H_2147889361_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.H!MTB"
        threat_id = "2147889361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d e8 0f b6 1c 07 01 f3 89 45 d8 31 f6 89 55 d4 89 f2 8b 75 f0 f7 f6 8b 75 ec 0f b6 14 16 01 d3 89 d8 99 8b 5d d4 f7 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_I_2147889525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.I!MTB"
        threat_id = "2147889525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 30 01 3d ?? ?? ?? ?? 40 29 c2 31 1d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_I_2147889525_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.I!MTB"
        threat_id = "2147889525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 e8 0f b6 3c 06 01 d7 31 d2 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 f7 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMC_2147890056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMC!MTB"
        threat_id = "2147890056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e0 50 8f 05 ?? ?? ?? ?? 83 e8 08 e8 ?? ?? ?? ?? 42 89 e8 50 8f 05 ?? ?? ?? ?? 01 d0 8d 05 ?? ?? ?? ?? 01 18 e8 ?? ?? ?? ?? c3 48 48 89 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMC_2147890056_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMC!MTB"
        threat_id = "2147890056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "62.171.176.24" ascii //weight: 1
        $x_1_2 = "payload.dll" ascii //weight: 1
        $x_1_3 = "0@.idata" ascii //weight: 1
        $x_10_4 = {70 61 79 6c 6f 61 64 2e 64 6c 6c 00 6d 61 69 6e 00 70 75 6e 74 00 72 65 63 76 5f 61 6c 6c 00 73 65 72 76 65 72 00 73 65 72 76 65 72 70 00 77 69 6e 73 6f 63 6b 5f 69 6e 69 74 00 77 73 63 6f 6e 6e 65 63 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_J_2147890064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.J!MTB"
        threat_id = "2147890064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 14 1e 47 8a 0c 07 8b c6 32 d1 88 14 1e 99 f7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_J_2147890064_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.J!MTB"
        threat_id = "2147890064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dgreenforthdmovedyielding.Our" ascii //weight: 1
        $x_1_2 = "Hgiven.untolesserabove" ascii //weight: 1
        $x_1_3 = "They.redaytwoitselfDryIRg" ascii //weight: 1
        $x_1_4 = "PX5godVourm9greenfruit" ascii //weight: 1
        $x_1_5 = "SeLF.ExE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCAS_2147890132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCAS!MTB"
        threat_id = "2147890132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f4 0f b7 80 ?? ?? ?? ?? 89 45 dc 8b 45 dc 33 45 e0 89 45 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASC_2147890424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASC!MTB"
        threat_id = "2147890424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 38 4a 01 1d [0-4] 40 31 c2 89 e8 50}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e1 c1 ea 08 69 c2 [0-4] 8b 4d ?? 29 c1 89 c8 83 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDF_2147891283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDF!MTB"
        threat_id = "2147891283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 38 83 f2 02 83 f2 04 89 e8 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMAB_2147891395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMAB!MTB"
        threat_id = "2147891395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "O:\\l4hNfYA\\9Vl\\6f\\W\\8dGNaOm.pdb" ascii //weight: 1
        $x_1_2 = "TponfKheem" ascii //weight: 1
        $x_1_3 = "EhherbMidstYScreplenish" ascii //weight: 1
        $x_1_4 = "alsohefirmamentA9Therefishkind" ascii //weight: 1
        $x_1_5 = "GJmeatgodrCYSsetAbundantly" ascii //weight: 1
        $x_1_6 = "c5fowlGbe.uMmdoesn.twU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDG_2147891482_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDG!MTB"
        threat_id = "2147891482"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 45 f0 89 4d ec 89 55 e8 b8 3b 05 00 00 31 c9 89 45 e4 89 4d e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDH_2147891493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDH!MTB"
        threat_id = "2147891493"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 e0 8b 4d e4 31 d2 81 c1 c7 20 00 00 89 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_VD_2147891671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.VD!MTB"
        threat_id = "2147891671"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 3b 45 fc 74 1f 8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPA_2147891925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPA!MTB"
        threat_id = "2147891925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 d7 01 f7 81 c7 ?? 00 00 00 8b 37 69 f8 ?? 00 00 00 01 fa 81 c2 ?? 00 00 00 0f b7 12 31 f2 01 ca 05 01 00 00 00 3d a9 01 00 00 89 d1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPAB_2147891926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPAB!MTB"
        threat_id = "2147891926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 7d e0 32 1c 37 8b 75 e4 88}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBJB_2147892084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBJB!MTB"
        threat_id = "2147892084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 67 70 74 65 66 39 36 2e 64 6c 6c 00 54 70 6f 6e 66 4b 68 65 65 6d 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65}  //weight: 1, accuracy: High
        $x_1_2 = {66 32 69 7a 6a 4c 45 4e 2e 44 4c 4c 00 73 65 4c 46 2e 45 78 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCBY_2147892155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCBY!MTB"
        threat_id = "2147892155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 de 81 c6 ?? ?? ?? ?? 0f b7 36 31 fe 01 ce 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCBZ_2147892165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCBZ!MTB"
        threat_id = "2147892165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 d3 01 fb 8b 3b 69 d8 ?? ?? ?? ?? 01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b b5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_K_2147892178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.K!MTB"
        threat_id = "2147892178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 32 32 0c 1f 8b 5d ?? 88 0c 33}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_K_2147892178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.K!MTB"
        threat_id = "2147892178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d e8 0f b6 1c 0f 01 f3 89 45 d8 89 c8 31 f6 89 55 d4 89 f2 8b 75 f0 f7 f6 8b 75 ec 0f b6 14 16 01 d3 89 d8 99 8b 5d d4 f7 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCCA_2147892245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCCA!MTB"
        threat_id = "2147892245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "x1dXvA4rlTz_QCLk/D!nCbqd2GfX/jD.pdb" ascii //weight: 1
        $x_1_2 = "IehhzrfLieerati" ascii //weight: 1
        $x_1_3 = "aneohe31.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AZ_2147892269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AZ!MTB"
        threat_id = "2147892269"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c6 81 c6 ?? ?? ?? ?? 8b 06 0f b7 33 31 c6 01 ce 81 ff ?? ?? ?? ?? 89 f0 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASD_2147892363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASD!MTB"
        threat_id = "2147892363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 6b c2 ?? 8b 4e ?? 29 c1 89 c8 83 e8 02 89 4e ?? 89 46 08 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {31 d0 31 c2 4a 48 8d 05 ?? ?? ?? ?? 01 30 b9 02 00 00 00 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPE_2147892397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPE!MTB"
        threat_id = "2147892397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 0c 1a 8b 55 ?? 32 0c 32 8b 75 ?? 88 0c 1e 8b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_L_2147892525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.L!MTB"
        threat_id = "2147892525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c2 42 8d 05 ?? ?? ?? ?? 01 38 83 ea 04 89 d0 48}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_L_2147892525_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.L!MTB"
        threat_id = "2147892525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d e8 0f b6 1c 07 01 f3 89 45 d4 31 f6 89 55 d0 89 f2 8b 75 f0 f7 f6 8b 75 ec 0f b6 14 16 01 d3 89 d8 99 8b 5d d0 f7 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPG_2147892597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPG!MTB"
        threat_id = "2147892597"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {d0 8a 0c 0a 32 0c 1f 8b 5d e8 8b 55 d0 88 0c 13 c7 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMQ_2147892652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMQ!MTB"
        threat_id = "2147892652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thingdividedghadmultiplyYbringxMale" ascii //weight: 1
        $x_1_2 = "CreepethYwherein" ascii //weight: 1
        $x_1_3 = "EalEsneataysxxt" ascii //weight: 1
        $x_1_4 = "ONFI7wTsetrfly" ascii //weight: 1
        $x_1_5 = "hmyyouwingedLhecreeping" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMAD_2147892663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMAD!MTB"
        threat_id = "2147892663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A:\\LqOph2T\\Dhf3Vfp7S\\5i.pdb" ascii //weight: 1
        $x_1_2 = "subdueCgod9Creepethwstarsfowl" ascii //weight: 1
        $x_1_3 = "yBbDgodshe.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDI_2147892727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDI!MTB"
        threat_id = "2147892727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1c 31 32 1c 17 8b 55 e8 88 1c 32}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDJ_2147892782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDJ!MTB"
        threat_id = "2147892782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 29 d0 4a 8d 05 ?? ?? ?? ?? 89 28 42 01 35}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBJV_2147892804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBJV!MTB"
        threat_id = "2147892804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 00 75 00 68 00 61 00 70 00 65 00 63 00 6f 00 5c 00 43 00 65 00 6c 00 61 00 67 00 20 00 63 00 65 00 64 00 69 00 79 00 75 00 74 00 75 00 79 00 69 00 77 00 61 00 63 00 20 00 78}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 57 00 61 00 6a 00 69 00 74 00 6f 00 6c 00 6f 00 74 00 6f 00 79 00 6f 00 64 00 65 00 6a 00 20 00 76 00 65 00 63 00 69 00 62 00 69 00 62 00 61 00 7a 00 61 00 20 00 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_M_2147892839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.M!MTB"
        threat_id = "2147892839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 75 e8 0f b6 3c 0e 01 c7 89 c8 31 db 89 55 d8 89 da 8b 5d f0 f7 f3 8b 75 ec 0f b6 14 16 01 d7 89 f8 99 8b 7d d8 f7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_M_2147892839_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.M!MTB"
        threat_id = "2147892839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 fa 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 01 ca 05}  //weight: 2, accuracy: Low
        $x_2_2 = {01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8a 1c 31 32 1c 17 8b 55 ?? 88 1c 32}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_GMR_2147892917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMR!MTB"
        threat_id = "2147892917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "everywhichLveryXalsoa" ascii //weight: 1
        $x_1_2 = "zourZcwhichQu" ascii //weight: 1
        $x_1_3 = "fgive.fruituyurzd" ascii //weight: 1
        $x_1_4 = "nqhenrnewd68.dll" ascii //weight: 1
        $x_1_5 = "EalEsneataysxxt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMS_2147893132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMS!MTB"
        threat_id = "2147893132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vEAi\\j1KsWp.pdb" ascii //weight: 1
        $x_1_2 = "she.dgrass.man" ascii //weight: 1
        $x_1_3 = "duaJthey.reaqItogether" ascii //weight: 1
        $x_1_4 = "5Ohe.abovexia" ascii //weight: 1
        $x_1_5 = "EaipifEeetoio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBJZ_2147893192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBJZ!MTB"
        threat_id = "2147893192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8}  //weight: 1, accuracy: High
        $x_1_2 = {61 6e 62 6c 73 62 69 61 6c 6c 35 32 2e 64 6c 6c 00 49 65 65 63 70 6e 45 77 65 65 74 6e 61 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70}  //weight: 1, accuracy: High
        $x_1_3 = "Fit4!x9ChV|HnDB-igLr8ERz57=#Gs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPDT_2147893197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPDT!MTB"
        threat_id = "2147893197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "56VYeMdj+bud1ynP#ZXAsg=f" ascii //weight: 2
        $x_2_2 = "BodsuwtubestdHnit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMU_2147893240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMU!MTB"
        threat_id = "2147893240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 20 83 f2 07 42 01 d0 eb 30 83 f0 04 42 01 2d ?? ?? ?? ?? 48 83 c0 08 01 3d ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 31 18 83 e8 04 01 d0 8d 05 ?? ?? ?? ?? 31 30 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMV_2147893245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMV!MTB"
        threat_id = "2147893245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 20 01 d0 83 ea 06 e8 ?? ?? ?? ?? c3 8d 05 ?? ?? ?? ?? 50 c3 8d 05 ?? ?? ?? ?? 31 30 48 8d 05 ?? ?? ?? ?? 89 38 83 f0 09 89 1d ?? ?? ?? ?? 48 83 ea 02 40 8d 05 ?? ?? ?? ?? 01 28 b9}  //weight: 10, accuracy: Low
        $x_1_2 = "EalEsneataysxxt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASE_2147893266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASE!MTB"
        threat_id = "2147893266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 e8 8b 75 d0 8a 14 32 32 14 0b 8b 4d e4 88 14 31}  //weight: 1, accuracy: High
        $x_1_2 = "wAwatersmoving.forfirst6" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAD_2147893274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAD!MTB"
        threat_id = "2147893274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d d4 8a 0c 0a 32 0c 1f 8b 5d e8 8b 55 d4 88}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_NZ_2147893287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.NZ!MTB"
        threat_id = "2147893287"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HYgathered6winged.malemadefNy" ascii //weight: 1
        $x_1_2 = "meatilivingdayIbe" ascii //weight: 1
        $x_1_3 = "lWhalesmakeFqabundantly.amultiplyG" ascii //weight: 1
        $x_1_4 = "Jlightfifth7she.d" ascii //weight: 1
        $x_1_5 = "gatheredone7Ekind" ascii //weight: 1
        $x_1_6 = "can.t,7fly" ascii //weight: 1
        $x_1_7 = "dryallsignsMliving" ascii //weight: 1
        $x_1_8 = "she.dbroughti" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBKB_2147893364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBKB!MTB"
        threat_id = "2147893364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 79 6c 61 68 74 65 38 37 2e 64 6c 6c 00 42 6f 64 73 75 77 74 75 62 65 73 74 64 48 6e 69 74 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70}  //weight: 1, accuracy: High
        $x_1_2 = "z:\\vEAi\\j1KsWp.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBJG_2147893420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBJG!MTB"
        threat_id = "2147893420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 65 6f 68 65 33 31 2e 64 6c 6c 00 49 65 68 68 7a 72 66 4c 69 65 65 72 61 74 69 00 6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPJ_2147893502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPJ!MTB"
        threat_id = "2147893502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 1c 31 8b 4d ?? 32 1c 11 8b 55 ?? 88 1c 32 c7 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GND_2147893561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GND!MTB"
        threat_id = "2147893561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 8d 05 ?? ?? ?? ?? 31 20 83 c2 ?? 01 c2 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 29 d0 42 83 f2 ?? 8d 05 ?? ?? ?? ?? 89 18 4a 8d 05 ?? ?? ?? ?? 01 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GND_2147893561_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GND!MTB"
        threat_id = "2147893561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3DDLJF8.DLL" ascii //weight: 1
        $x_1_2 = "uqverythatbeginninghearth.sixth" ascii //weight: 1
        $x_1_3 = "JwfruitfulQmeT" ascii //weight: 1
        $x_1_4 = "KOjSseasfillfbwatersmoving" ascii //weight: 1
        $x_1_5 = "Under9seedo4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNE_2147893748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNE!MTB"
        threat_id = "2147893748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 6c 98 55 89 75 ?? b8 ?? ?? ?? ?? 01 45 ?? 8b 45 ?? 8a 04 08 88 04 39 41 3b 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNE_2147893748_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNE!MTB"
        threat_id = "2147893748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 c2 89 1d ?? ?? ?? ?? 4a 83 c2 ?? 83 ea ?? 40 8d 05 ?? ?? ?? ?? 31 38 8d 05 ?? ?? ?? ?? 50 c3 48 40}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNE_2147893748_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNE!MTB"
        threat_id = "2147893748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 20 31 c2 4a 4a 83 f0 ?? e8 ?? ?? ?? ?? c3 01 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 31 d0 89 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 29 d0 89 f8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 18 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBKL_2147893953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBKL!MTB"
        threat_id = "2147893953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 61 70 69 6d 6f 68 69 62 6f 7a 61 79 6f 63 65 78 6f 6a 69 6b 65 79 65 66 61 20 6b 61 63 75 6a 61 77 65 6d 6f 6a 69 6d 65 6e 61 64 61 6e 65 64 6f 6d 00 00 67 6f 63 75 79 65 6e 61 7a 65 74 6f 6a 61 62 6f 70 65 68 65 77 69 66 00 6c 65 77 61 79 69 76 65 73 75 72 65 6a 75 6d 65 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBKL_2147893953_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBKL!MTB"
        threat_id = "2147893953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mifipesanahewoxezusuwopaxexoc" ascii //weight: 1
        $x_1_2 = "xabositixaboxojebekeyeyexakinikojasupizofafehatofikekadihisekacujumokusoxusosamo" ascii //weight: 1
        $x_1_3 = "yawagobeduhafurutagulel" ascii //weight: 1
        $x_1_4 = "hufofehizu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNP_2147894360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNP!MTB"
        threat_id = "2147894360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 31 d0 89 c2 8d 05 ?? ?? ?? ?? 31 20 83 c0 ?? 01 c2 b9 ?? ?? ?? ?? e2 ?? e8 ?? ?? ?? ?? 83 f2 ?? b8 ?? ?? ?? ?? 42 40 31 35 ?? ?? ?? ?? 89 d0 42 31 1d ?? ?? ?? ?? 40 89 2d ?? ?? ?? ?? 29 d0 40 8d 05 ?? ?? ?? ?? 01 38}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNQ_2147894578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNQ!MTB"
        threat_id = "2147894578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e0 50 8f 05 ?? ?? ?? ?? 01 c2 b9 ?? ?? ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 18 31 c2 83 c2 ?? 29 c2 89 2d ?? ?? ?? ?? 42 8d 05 ?? ?? ?? ?? 89 30 e8 ?? ?? ?? ?? 40 4a ba ?? ?? ?? ?? 31 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNI_2147894585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNI!MTB"
        threat_id = "2147894585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 53 81 ec ?? ?? ?? ?? 89 e0 c7 00 ?? ?? ?? ?? a1}  //weight: 10, accuracy: Low
        $x_10_2 = {29 c2 83 c2 ?? 89 f8 50 8f 05 ?? ?? ?? ?? 4a 89 2d ?? ?? ?? ?? 83 c2 ?? 89 f0 50 8f 05 ?? ?? ?? ?? 8d 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDN_2147895077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDN!MTB"
        threat_id = "2147895077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ff d1 83 ec 10 31 c9 89 ca 89 45 bc 89 55 c0 89 4d c4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDN_2147895077_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDN!MTB"
        threat_id = "2147895077"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {80 39 53 0f 94 c3 8b 95 e4 fe ff ff 80 3a 54 0f 94 c7 20 fb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNT_2147895085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNT!MTB"
        threat_id = "2147895085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 20 31 c2 4a 4a 83 f0 ?? e8 ?? ?? ?? ?? c3 01 c2 89 f0 50 8f 05 ?? ?? ?? ?? 31 d0 31 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNT_2147895085_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNT!MTB"
        threat_id = "2147895085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 30 c8 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? a8 06 00 00 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNT_2147895085_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNT!MTB"
        threat_id = "2147895085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 ?? 8a 4d ?? 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPK_2147895101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPK!MTB"
        threat_id = "2147895101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {32 0c 1a 8b 55 ?? 88 0c 1a c7 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMBA_2147895289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMBA!MTB"
        threat_id = "2147895289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e8 8b 4d ec 8a 14 01 8b 45 e8 8b 4d f0 88 14 01 8b 45 e8 05 01 00 00 00 89 45 e8 eb}  //weight: 1, accuracy: High
        $x_1_2 = "LnlteehOsterbp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASF_2147895359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASF!MTB"
        threat_id = "2147895359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 14 16 8b 35 [0-4] 8b 7d e4 0f b6 34 37 31 f2 88 d3 8b 55 dc 8b 75 e8 88 1c 16 eb}  //weight: 1, accuracy: Low
        $x_1_2 = "LnlteehOsterbp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPDU_2147895483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPDU!MTB"
        threat_id = "2147895483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "s7tC9Ly.dLl" ascii //weight: 2
        $x_2_2 = "LnlteehOsterbp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPL_2147895539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPL!MTB"
        threat_id = "2147895539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lifehMoving.seasonsXvWereK" ascii //weight: 1
        $x_1_2 = "Twinged1greater.wseavoidr" ascii //weight: 1
        $x_1_3 = "fruittktogetherwithoutZbeginning" ascii //weight: 1
        $x_1_4 = "Qlivinggivengreatseaseedgivez" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASG_2147895841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASG!MTB"
        threat_id = "2147895841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 1f 8b 55 ec 8b 5d d0 32 0c 1a 8b 55 e8 88 0c 1a}  //weight: 1, accuracy: High
        $x_1_2 = {01 df 89 f8 89 55 c8 99 f7 fe 89 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDL_2147895941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDL!MTB"
        threat_id = "2147895941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0j39L6zWu4.dlL" ascii //weight: 1
        $x_1_2 = "4together.19" ascii //weight: 1
        $x_1_3 = "1bethird3cherbsaidnsofirst" ascii //weight: 1
        $x_1_4 = "0whereinshalltogetherwere.Rtf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPM_2147895967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPM!MTB"
        threat_id = "2147895967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 c2 83 c0 07 40 83 f2 01 01 35 ?? ?? ?? ?? 31 d0 01 2d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCDU_2147896048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCDU!MTB"
        threat_id = "2147896048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 8b 1b 0f b7 12 31 c2 89 34 24 89 5c 24 ?? 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPAC_2147896244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPAC!MTB"
        threat_id = "2147896244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {32 1c 3e 8b 7d e8 88 1c 0f 8b 35}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMBD_2147896483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMBD!MTB"
        threat_id = "2147896483"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 f2 81 c2 ?? ?? ?? ?? 81 c1 01 00 00 00 8b ?? ?? ?? ?? ff 01 c6 8b 1b 8b 12 0f b7 3f 31 df 89 34 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 0c 1f 8b 55 e4 8b 5d d0 32 0c 1a 8b 55 e0 88 0c 1a 81 c3 01 00 00 00 8b 4d f0 39 cb 89 5d c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPF_2147896644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPF!MTB"
        threat_id = "2147896644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 65 00 6d 00 74 00 62 00 63 00 69 00 72}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 6e 00 37 00 79 00 63 00 72 00 65 00 61 00 74 00 65 00 64}  //weight: 1, accuracy: High
        $x_1_3 = {65 00 76 00 65 00 6e 00 69 00 6e 00 67 00 63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 46 00 48 00 34 00 57 00 61 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMA_2147896723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMA!MTB"
        threat_id = "2147896723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c2 89 e0 50 8f 05 ?? ?? ?? ?? 89 d0 42 e8 ?? ?? ?? ?? c3 8d 05 ?? ?? ?? ?? 01 30 31 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBEY_2147896901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBEY!MTB"
        threat_id = "2147896901"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 12 8b 00 0f b7 3b 31 d7 89 34 24 89 44 24 04 89 7c 24 08}  //weight: 1, accuracy: High
        $x_1_2 = "EhoftahalllqheTefnre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAE_2147897013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAE!MTB"
        threat_id = "2147897013"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 3f 8b 12 0f b7 1b 31 fb 89 34 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMBB_2147897027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMBB!MTB"
        threat_id = "2147897027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 0c 32 8b 55 ?? 88 0c 32 8b 4d ?? 39 cf 89 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMBC_2147897047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMBC!MTB"
        threat_id = "2147897047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 0c 1f 8b 55 ec 8b 5d d4 32 0c 1a 8b 55 e8 88 0c 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_N_2147897098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.N!MTB"
        threat_id = "2147897098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 7d e8 0f b6 3c 0f 01 df 8b 5d ec 0f b6 14 13 01 d7 89 3d 98 78 0d 10 89 f8 99 8b 7d d4 f7 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_N_2147897098_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.N!MTB"
        threat_id = "2147897098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 d0 32 0c 32 8b 55 ?? 88 0c 32}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 12 0f b7 37 31 d6 01 ce}  //weight: 2, accuracy: High
        $x_2_3 = {8b 12 8b 3f 0f b7 1b 31 d3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_RDM_2147897382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDM!MTB"
        threat_id = "2147897382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4d f0 8a 14 01 8b 75 ec 88 14 06 05 01 00 00 00 8b 7d f4 39 f8 89 45 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_O_2147897508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.O!MTB"
        threat_id = "2147897508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 ec 89 34 24 8b 7d f0 89 7c 24 04 89 44 24 08 0f b6 04 15 ?? ?? ?? ?? 89 44 24 0c 89 4d e4 e8 ?? ?? ?? ?? 8b 45 e4 8b 4d f4 39 c8 89 45 e8 75 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPHD_2147897515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPHD!MTB"
        threat_id = "2147897515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "igkcBoG1yJ4QWxzOarU|ss2ouXHmL+" ascii //weight: 2
        $x_2_2 = "NributtetaatoTdhti" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_P_2147897775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.P!MTB"
        threat_id = "2147897775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 ec 89 34 24 8b 7d f0 89 7c 24 04 89 44 24 08 0f b6 04 0d ?? ?? ?? ?? 89 44 24 0c 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 8b 4d f4 39 c8 89 45 e8 75 bb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_P_2147897775_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.P!MTB"
        threat_id = "2147897775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 cc 32 0c 32 8b 55 ?? 88 0c 32}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 3f 8b 00 0f b7 12 31 fa}  //weight: 2, accuracy: High
        $x_2_3 = {c6 85 d4 fe ff ff 56 c6 85 d5 fe ff ff 69 c6 85 d6 fe ff ff 72 c6 85 d7 fe ff ff 74 c6 85 d8 fe ff ff 75 c6 85 d9 fe ff ff 61 c6 85 da fe ff ff 6c c6 85 db fe ff ff 41 c6 85 dc fe ff ff 6c c6 85 dd fe ff ff 6c c6 85 de fe ff ff 6f c6 85 df fe ff ff 63}  //weight: 2, accuracy: High
        $x_2_4 = {c6 45 d4 56 c6 45 d5 69 c6 45 d6 72 c6 45 d7 74 c6 45 d8 75 c6 45 d9 61 c6 45 da 6c c6 45 db 41 c6 45 dc 6c c6 45 dd 6c c6 45 de 6f c6 45 df 63}  //weight: 2, accuracy: High
        $x_2_5 = {c6 45 94 6b c6 45 95 65 c6 45 96 72 c6 45 97 6e c6 45 98 65 c6 45 99 6c c6 45 9a 33 c6 45 9b 32 c6 45 9c 2e c6 45 9d 64 c6 45 9e 6c c6 45 9f 6c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_RDO_2147897797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDO!MTB"
        threat_id = "2147897797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 0f b6 c0 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_Q_2147897902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.Q!MTB"
        threat_id = "2147897902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 d0 48 29 d0 01 25 ?? ?? ?? ?? 4a 31 c2 89 c2 4a b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASH_2147898442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASH!MTB"
        threat_id = "2147898442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 0a 48 48 8d 05 [0-4] 31 18 83 f2 02 8d 05 [0-4] 31 30 40 8d 05}  //weight: 1, accuracy: Low
        $x_1_2 = {01 d0 8d 05 [0-4] 01 20 83 ea 0a 83 ea 0a ba 01 00 00 00 31 d0 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASI_2147898443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASI!MTB"
        threat_id = "2147898443"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e1 c1 ea 03 6b c2 0c 8b 8c 24 d0 00 00 00 29 c1 89 c8 83 e8 02 89 4c 24 28 89 44 24 24 0f 84}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPGQ_2147898577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPGQ!MTB"
        threat_id = "2147898577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lisigezopak nuyeholuvanuyo" wide //weight: 1
        $x_1_2 = "cujoce yibuboditukapicimivijaxexepu netoyogiparupineconula" wide //weight: 1
        $x_1_3 = "Letepilus xuci ligav+Ricegis mucija hehujixa gahepe nugadufabamu" wide //weight: 1
        $x_1_4 = "KKonulafop magikoxotefojep noyopidugon zod litelidudi gihirit bocupajohafara" wide //weight: 1
        $x_1_5 = "xemifofilajozonidogujusit kodovowahovaxe guyolereyupeyuyulabo jupojebuhidapubimuvehek" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASJ_2147898603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASJ!MTB"
        threat_id = "2147898603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 6b c2 ?? 8b 4d ?? 29 c1 89 c8 83 e8 08 89 4d ?? 89 45 ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {f7 e1 c1 ea 02 6b c2 ?? 8b 4d ec 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_ASK_2147898604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASK!MTB"
        threat_id = "2147898604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d ?? 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45 ?? 0f 84}  //weight: 1, accuracy: Low
        $x_1_2 = {29 d0 31 3d [0-4] 83 f0 09 29 d0 83 c0 02 89 d0 01 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASL_2147898605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASL!MTB"
        threat_id = "2147898605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d ?? 29 c1 89 c8 83 e8 01 89 4d ?? 89 45 ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f2 07 40 83 f2 02 29 d0 89 e0 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GBA_2147898650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GBA!MTB"
        threat_id = "2147898650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e0 50 8f 05 ?? ?? ?? ?? 4a b9 ?? ?? ?? ?? e2 1c 48 89 2d ?? ?? ?? ?? 89 d0 31 d0 01 d0 4a 8d 05 ?? ?? ?? ?? 31 18 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASM_2147898697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASM!MTB"
        threat_id = "2147898697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c2 03 83 ea 09 01 35 ?? ?? 00 10 8d 05 ?? ?? 00 10 31 38 4a 01 1d ?? ?? 00 10 40 31 c2 89 e8 50 8f 05}  //weight: 2, accuracy: Low
        $x_2_2 = {f7 e1 c1 ea 03 6b c2 0c 8b 4c 24 ?? 29 c1 89 c8 83 e8 06 89 4c 24 ?? 89 44 24 ?? 74}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_ASN_2147898698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASN!MTB"
        threat_id = "2147898698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 6b c2 11 8b 4e ?? 29 c1 89 c8 83 e8 07 89 4e ?? 89 46 ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GAD_2147898931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GAD!MTB"
        threat_id = "2147898931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d1 83 ec ?? 8b 4c 24 ?? 81 c1 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 89 44 24 ?? 89 4c 24}  //weight: 10, accuracy: Low
        $x_10_2 = {31 20 83 f0 05 48 e8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GAE_2147898932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GAE!MTB"
        threat_id = "2147898932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 01 c2 89 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 50 c3 29 d0 ba ?? ?? ?? ?? 29 c2 8d 05 ?? ?? ?? ?? 31 28 83 e8 ?? 83 c0 ?? 31 1d ?? ?? ?? ?? b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GAE_2147898932_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GAE!MTB"
        threat_id = "2147898932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c2 40 89 d8 50 8f 05 ?? ?? ?? ?? 31 c2 b8 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 89 38 40 48 8d 05 ?? ?? ?? ?? 01 30 ba ?? ?? ?? ?? 83 f0 ?? 89 d0 89 2d ?? ?? ?? ?? b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASO_2147899123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASO!MTB"
        threat_id = "2147899123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4c 24 ?? 29 c1 89 c8 83 e8 ?? 89 4c 24 ?? 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDP_2147899140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDP!MTB"
        threat_id = "2147899140"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ttBfemale" ascii //weight: 1
        $x_1_2 = "dsixthunder" ascii //weight: 1
        $x_1_3 = "doesn.t.set,third" ascii //weight: 1
        $x_1_4 = "idstallqVmnNy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GAF_2147899206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GAF!MTB"
        threat_id = "2147899206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 18 89 d0 31 c2 31 2d ?? ?? ?? ?? 42 29 d0 29 d0 89 3d ?? ?? ?? ?? e9 ?? ?? ?? ?? 01 c2 01 d0 83 f2 ?? 31 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_S_2147899883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.S!MTB"
        threat_id = "2147899883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 01 d0 48 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 28 31 c2 42 40}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASP_2147899947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASP!MTB"
        threat_id = "2147899947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e1 c1 ea 08 69 c2 41 01 00 00 8b 4d ?? 29 c1 89 c8 83 e8 ?? 89 4d ?? 89 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAF_2147899971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAF!MTB"
        threat_id = "2147899971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d fc 33 ce 8d 45 e4 89 4d fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASQ_2147899989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASQ!MTB"
        threat_id = "2147899989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f7 e1 c1 ea 02 6b c2 ?? 8b 4c 24 [0-4] 29 c1 89 c8 83 e8 02 89 4c 24 ?? 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNF_2147900192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNF!MTB"
        threat_id = "2147900192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b ce 83 e1 1f 88 82 ?? ?? ?? ?? 83 c6 03 0f b6 81 ?? ?? ?? ?? 30 82 ?? ?? ?? ?? 0f b6 82 ?? ?? ?? ?? 2a 81 ?? ?? ?? ?? 88 82 ?? ?? ?? ?? 83 c2 03 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNF_2147900192_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNF!MTB"
        threat_id = "2147900192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d2 89 15 ?? ?? ?? ?? 01 3d ?? ?? ?? ?? 89 c2 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 30 e9 ?? ?? ?? ?? c3 40 8d 05 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 31 28 4a c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RDQ_2147900231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RDQ!MTB"
        threat_id = "2147900231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 c2 09 01 d0 40 83 c2 09 8d 05 ?? ?? ?? ?? 89 18 b8 06 00 00 00 83 f2 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAG_2147900309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAG!MTB"
        threat_id = "2147900309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4onebroughtJdarknesshadwas.Cs" ascii //weight: 1
        $x_1_2 = "pgod.8Bringyears" ascii //weight: 1
        $x_1_3 = "hingbeastlseasonsZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASS_2147900648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASS!MTB"
        threat_id = "2147900648"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea 04 6b c2 ?? 8b 4c 24 ?? 29 c1 89 c8 83 e8 03 89 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = "d5BlessedYisn.tfspirit4she.dj" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASR_2147900736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASR!MTB"
        threat_id = "2147900736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "154.204.179.4/a154.39.239.56.txt" ascii //weight: 1
        $x_1_2 = "Users\\Administrator\\Desktop\\BBBBBBB\\Release\\BBBBBBB.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AST_2147900739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AST!MTB"
        threat_id = "2147900739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {67 72 65 61 74 65 72 77 68 69 63 68 50 37 76 65 72 79 67 72 61 73 73 35 64 65 65 70 00 61 49 4a 55 4d 00 65 76 65 72 79 62 72 6f 75 67 68 74 2e 56 61 69 46 6b 70 46 00 50 6e 69 67 68 74 46 4d 6f 76 69 6e 67 5a 00 64 62 6a 73 65 61 2e 68 65 53 6f 64 72 79 68 65 47 74 6f 67 65 74 68 65 72 00 68 61 76 65 66 44 6f 6e 2e 74}  //weight: 5, accuracy: High
        $x_1_2 = "SwdividedDivideiAVmanyou.lly" ascii //weight: 1
        $x_1_3 = "v1kindyou.reXCv0U" ascii //weight: 1
        $x_1_4 = "she.disn.tyoudrykindS9n" ascii //weight: 1
        $x_1_5 = "xshallyieldingto.uNdryacan.t" ascii //weight: 1
        $x_1_6 = "herbwNwhichqDMorninghavekind.fill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zenpak_KAH_2147900751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAH!MTB"
        threat_id = "2147900751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b c1 0f b6 55 ?? 33 c2 8b 4d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASU_2147900813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASU!MTB"
        threat_id = "2147900813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Himfrom1theremovedIearthZbeholdx" wide //weight: 1
        $x_1_2 = "8egodflyMbeastRu" wide //weight: 1
        $x_1_3 = "whalesbruleseasonssignscattleopenlight.created" wide //weight: 1
        $x_1_4 = "Clights.Void4" wide //weight: 1
        $x_1_5 = "is4Lmorning,0Z" wide //weight: 1
        $x_1_6 = "beholdreplenishtgood.Twoface" wide //weight: 1
        $x_1_7 = "XstarsCZwhosetree" wide //weight: 1
        $x_1_8 = "Htogethermorningcreateddarknesshave" wide //weight: 1
        $x_1_9 = "MtreeLivingdivide" wide //weight: 1
        $x_1_10 = "underdoesn.tcqsecond" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Zenpak_T_2147900851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.T!MTB"
        threat_id = "2147900851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 30 ba 02 00 00 00 8d 05 ?? ?? ?? ?? 01 18 89 c2 83 c2 09 83 ea 05 8d 05 ?? ?? ?? ?? 31 38 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PQ_2147901137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PQ!MTB"
        threat_id = "2147901137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 30 c8 8b 15 f8 fa 33 10 81 c2 36 ed ff ff 89 15 f4 fa 33 10 0f b6 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASV_2147901158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASV!MTB"
        threat_id = "2147901158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ncreepingairJTherefirmamentabovemade1" wide //weight: 1
        $x_1_2 = "landitselfQdayethemYmakeFacefowl" wide //weight: 1
        $x_1_3 = "S2aftergreen.uIsn.t" ascii //weight: 1
        $x_1_4 = "man.PGtherejhathSeasffirmament.rule" ascii //weight: 1
        $x_1_5 = "dgreatmadeYieldingvIDaygrass50" ascii //weight: 1
        $x_1_6 = "RIsetmorningQCreepethwjemeat" wide //weight: 1
        $x_1_7 = "eveningblessedtoGandbe.sixth" wide //weight: 1
        $x_1_8 = "fishsayinggatheredFillsaw.y" ascii //weight: 1
        $x_1_9 = "yearscan.tlesser3OgyieldingKGj" ascii //weight: 1
        $x_1_10 = "she.dseahFthey.reSeas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Zenpak_U_2147901243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.U!MTB"
        threat_id = "2147901243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 e8 50 8f 05 ?? ?? ?? ?? 48 42 83 f2 ?? 8d 05 ?? ?? ?? ?? 89 18 8d 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAI_2147901601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAI!MTB"
        threat_id = "2147901601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 75 00 66 0f b3 e9 80 f5 9a 8a 06 0f 95 c1 00 d8 0f 9c c5 46}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAJ_2147901605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAJ!MTB"
        threat_id = "2147901605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JewwdeosjehtFsecnr" ascii //weight: 1
        $x_1_2 = "nhrhl97.dll" ascii //weight: 1
        $x_1_3 = "HLoadNonloadedIconOverlayIdentifiers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAK_2147901610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAK!MTB"
        threat_id = "2147901610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oreeuxanai" ascii //weight: 1
        $x_1_2 = "BkenLoadiaaee" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_V_2147901906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.V!MTB"
        threat_id = "2147901906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 01 d0 4a 4a 01 1d ?? ?? ?? ?? 31 d0 ba ?? ?? ?? ?? 83 ea ?? 8d 05 ?? ?? ?? ?? 31 28 b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASW_2147902209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASW!MTB"
        threat_id = "2147902209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e1 c1 ea 03 6b c2 ?? 8b 8c ?? ?? ?? 00 00 29 c1 89 c8 83 e8 ?? 89 ?? 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZN_2147902283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZN!MTB"
        threat_id = "2147902283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 31 d0 89 f0 50 8f 05 ?? ?? ?? ?? 48 01 c2 01 3d ?? ?? ?? ?? 29 c2 83 f0 01 42 89 d0 31 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZN_2147902283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZN!MTB"
        threat_id = "2147902283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 31 d0 40 8d 05 ?? ?? ?? ?? 01 20 83 f2 01 e8 ?? ?? ?? ?? ba ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 18 8d 05 ?? ?? ?? ?? ff e0 8d 05 ?? ?? ?? ?? 89 30 89 d0 8d 05 ?? ?? ?? ?? 01 28 40 8d 05 ?? ?? ?? ?? 31 38 b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZM_2147902360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZM!MTB"
        threat_id = "2147902360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 f0 50 8f 05 ?? ?? ?? ?? 83 f2 ?? 42 89 d0 31 1d ?? ?? ?? ?? 89 f8 50 8f 05 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZM_2147902360_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZM!MTB"
        threat_id = "2147902360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 05 29 c2 ?? ?? 4a ba ?? ?? ?? ?? 4a 89 f8 50 8f 05 ?? ?? ?? ?? e8 ?? ?? ?? ?? c3 4a 01 1d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 8d 05 ?? ?? ?? ?? 89 28}  //weight: 10, accuracy: Low
        $x_10_2 = {29 c2 89 e0 50 8f 05 ?? ?? ?? ?? 83 f0 01 e8 ?? ?? ?? ?? 01 2d ?? ?? ?? ?? 89 c2 8d 05 ?? ?? ?? ?? 01 18 e8 ?? ?? ?? ?? c3 01 c2 8d 05 ?? ?? ?? ?? 01 38 8d 05 ?? ?? ?? ?? 89 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_KAL_2147902502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAL!MTB"
        threat_id = "2147902502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASX_2147902994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASX!MTB"
        threat_id = "2147902994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "good6grass.zQmultiplyweremoved.Ky" wide //weight: 2
        $x_2_2 = "aFruitfulyearskmandaysthird" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASY_2147903148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASY!MTB"
        threat_id = "2147903148"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? 5f 06 00 00 c7 05 ?? ?? ?? ?? 97 df ff ff 30 c8 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCHT_2147903237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCHT!MTB"
        threat_id = "2147903237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 02 8d 05 ?? ?? ?? ?? 01 20 29 d0 83 e8 01 e8 ?? ?? ?? ?? 42 89 d0 8d 05 ?? ?? ?? ?? 01 38 8d 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXZ_2147903613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXZ!MTB"
        threat_id = "2147903613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? 5b 1c 00 00 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXZ_2147903613_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXZ!MTB"
        threat_id = "2147903613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 20 83 ea ?? 31 d0 48 48 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 f0 ?? 29 d0 89 2d ?? ?? ?? ?? 31 35 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 31 38}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXZ_2147903613_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXZ!MTB"
        threat_id = "2147903613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f af d1 0f b7 4d d0 29 d1 89 4d c8 8b 45 e8 8b 4d c0 89 08 8b 4d 0c 0f b7 45 cc 31 c1 66 89 4d ac 8b 55 e8 8b 4d b8 89 4a 04 8b 45 c8 b9 0b 00 00 00 31 d2 f7 f1 88 55 c4 8b 55 e0 83 c2 08 89 55 e0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASZ_2147903726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASZ!MTB"
        threat_id = "2147903726"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? f0 1a 00 00 c7 05 ?? ?? ?? ?? e7 11 00 00 30 c8 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_W_2147903866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.W!MTB"
        threat_id = "2147903866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d0 8d 05 ?? ?? ?? ?? 01 38 01 c2 83 ea ?? 8d 05 ?? ?? ?? ?? 01 28 83 c2 ?? 48 83 c0 05 31 35}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAB_2147904497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAB!MTB"
        threat_id = "2147904497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
        $x_1_2 = "xmhFowlbringallkindmorningand" wide //weight: 1
        $x_1_3 = "midstgreenfruitfulyearshimot" wide //weight: 1
        $x_1_4 = "malemayseaairUfemaledarknessxV" wide //weight: 1
        $x_1_5 = "Hwon.tzjisn.tover.herbgreater3fly" wide //weight: 1
        $x_1_6 = "qcreaturedoesn.tX4c" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zenpak_CCHW_2147905172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCHW!MTB"
        threat_id = "2147905172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 40 89 d0 48 31 1d ?? ?? ?? ?? 89 c2 42 83 ea 02 89 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_QQ_2147905283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.QQ!MTB"
        threat_id = "2147905283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_X_2147905288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.X!MTB"
        threat_id = "2147905288"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 38 31 d0 29 c2 b8}  //weight: 2, accuracy: High
        $x_2_2 = {89 f0 50 8f 05 ?? ?? ?? ?? 01 d0 31 d0 89 d8 50 8f 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AB_2147905651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AB!MTB"
        threat_id = "2147905651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4d dc 8b 4d dc 33 4d e0 89 4d e0 8b 4d e0 03 4d e8 89 4d e8 8b 45 e4 05 ?? ?? ?? ?? 89 45 e4 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AA_2147905693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AA!MTB"
        threat_id = "2147905693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 4d fa 0f b6 55 fa 0f b6 75 fb 31 f2 88 ?? 0f b6 ?? 83 c4 ?? 5e 5d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BZ_2147905701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BZ!MTB"
        threat_id = "2147905701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 f8 50 8f 05 ?? ?? ?? ?? 83 c2 03 83 f0 05 8d 05 ?? ?? ?? ?? 01 30 e8 c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BY_2147905702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BY!MTB"
        threat_id = "2147905702"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 c2 31 35 ?? ?? ?? ?? 83 c0 07 42 83 c0 04 83 c2 01 8d 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAM_2147905981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAM!MTB"
        threat_id = "2147905981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HathhihrsethZhohn" ascii //weight: 1
        $x_1_2 = "lhtwthdwst" ascii //weight: 1
        $x_1_3 = "g|V.0t6-+C*Pd2+Wk!e+-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAC_2147906056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAC!MTB"
        threat_id = "2147906056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? 00 00 30 c8 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPDB_2147906465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPDB!MTB"
        threat_id = "2147906465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 0c 83 65 fc 00 89 55 f4 89 4d f8 8b 45 f4 01 45 fc 8b 45 fc 31 45 f8 8b 45 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BX_2147906964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BX!MTB"
        threat_id = "2147906964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 c2 48 48 01 1d ?? ?? ?? ?? 42 8d 05 ?? ?? ?? ?? 01 38 8d 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BX_2147906964_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BX!MTB"
        threat_id = "2147906964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 cd 02 2d}  //weight: 4, accuracy: High
        $x_1_2 = {0f b6 c4 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPX_2147907043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPX!MTB"
        threat_id = "2147907043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 fa 0f b6 75 fb 31 f2 88 d0 0f b6 c0 83 c4 04 5e 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBZW_2147907076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBZW!MTB"
        threat_id = "2147907076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 b8 8b 45 b8 33 45 c8 89 45 c8 8b 45 c8 03 45 c4 89 45 c4 8b 45 b4 05 01 00 00 00 89 45 a4 8b 45 a4 89 45 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BW_2147907107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BW!MTB"
        threat_id = "2147907107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? 10 88 c5 02 2d}  //weight: 4, accuracy: Low
        $x_1_2 = {0f b6 c4 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BW_2147907107_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BW!MTB"
        threat_id = "2147907107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 e5 8a 45 ?? 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 30 c8 0f b6 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAD_2147907478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAD!MTB"
        threat_id = "2147907478"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 0b 8b 55 e8 8b 75 d0 32 0c 32 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? d7 13 00 00 c7 05 ?? ?? ?? ?? c9 1a 00 00 8b 55 e4 88 0c 32 8b 4d f0 39 cf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAE_2147907479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAE!MTB"
        threat_id = "2147907479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8b 45 dc 33 45 e0 89 45 e0 8b 45 e0 03 45 e8 89 45 e8 8b 45 e4 05 01}  //weight: 3, accuracy: High
        $x_3_2 = {8b 4d f4 33 4d ec 89 4d ec 8b 4d ec 03 4d b0 89 4d b0 8b 45 c0 05 01}  //weight: 3, accuracy: High
        $x_1_3 = "movethgatheredtESsaidyou.reso" wide //weight: 1
        $x_1_4 = "faceto.vopengiveQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zenpak_GZX_2147907535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZX!MTB"
        threat_id = "2147907535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ff d0 83 c2 03 89 e8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30 29 c2 ba 04 00 00 00 01 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 18 b9 02 00 00 00 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZX_2147907535_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZX!MTB"
        threat_id = "2147907535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e0 50 8f 05 ?? ?? ?? ?? 48 b9 02 00 00 00 ?? ?? 31 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 04 00 00 00 89 c2 31 35 ?? ?? ?? ?? 31 2d ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 ?? 55 89 e5 b8 01 00 00 00 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZX_2147907535_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZX!MTB"
        threat_id = "2147907535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 00 ca d6 41 00 f4 d6 41 00 4f d7 41 00 c6 d7 41 00 fc d7 41 00 46 d8}  //weight: 5, accuracy: High
        $x_5_2 = {b5 07 41 00 79 07 41 00 b5 ?? ?? ?? ?? 07 41 00 b5 ?? ?? ?? ?? 07 41 00 79 07 41 00 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 83 ec 08 56 8b f0 c1 e8 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RL_2147907732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RL!MTB"
        threat_id = "2147907732"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? 00 00 c7 05 ?? ?? ?? ?? ?? ?? 00 00 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAF_2147907931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAF!MTB"
        threat_id = "2147907931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0f b6 55 fb 0f b6 75 fa 31 f2 88 d0 0f b6 c0 83 c4 04 5e 5d c3}  //weight: 4, accuracy: High
        $x_1_2 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 45 fa 88 4d fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_NA_2147908384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.NA!MTB"
        threat_id = "2147908384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 cd 8b 55 e8 88 2c 1a 81 c3 ?? ?? ?? ?? 8b 55 f0 39 d3 89 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPA_2147908525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPA!MTB"
        threat_id = "2147908525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 55 fa 0f b6 75 fb 31 f2 88 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AF_2147908625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AF!MTB"
        threat_id = "2147908625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 ff 89 55 f8 88 45 f7 8a 45 f7 0f b6 c8 8b 55 f8 31 ca 88 d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAG_2147908633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAG!MTB"
        threat_id = "2147908633"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c8 8b 55 f8 31 ca 88 d4}  //weight: 2, accuracy: High
        $x_2_2 = {55 89 e5 83 ec 0c 8a 45 0c 8a 4d 08 88 45 ff 88 4d fe}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIE_2147908961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIE!MTB"
        threat_id = "2147908961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 50 8a 45 ?? 8a 4d ?? 88 45 ?? 88 4d ?? 0f b6 55 ?? 0f b6 75 ?? 31 f2 88 d0 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAN_2147909172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAN!MTB"
        threat_id = "2147909172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_RM_2147909251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.RM!MTB"
        threat_id = "2147909251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 0f b6 c1 8b 4d ?? 8a 84 05 ?? ?? ?? ?? 30 04 0a 42 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIF_2147909266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIF!MTB"
        threat_id = "2147909266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 30 c8 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAO_2147909473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAO!MTB"
        threat_id = "2147909473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 55 fa 0f b6 75 fb 31 f2 88 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AQE_2147909593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AQE!MTB"
        threat_id = "2147909593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 fe 88 45 fd 8a 45 fd 0f b6 c8 0f b6 55 ff 31 d1 88 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAH_2147909742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAH!MTB"
        threat_id = "2147909742"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d fe 0f b6 55 ff 31 d1 88 cc}  //weight: 2, accuracy: High
        $x_2_2 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 45 ff 88 4d fd 8a 45 fd 88 45 fe}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BV_2147909830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BV!MTB"
        threat_id = "2147909830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 81 c2 8d cf ff ff 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 4a 1b 00 00 0f b6 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAP_2147909872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAP!MTB"
        threat_id = "2147909872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 2c 32 8b 15 ?? ?? ?? ?? 30 cd 88 2d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 55 ?? 88 2c 32 8b 55 ?? 39 d7 89 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CZ_2147910019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CZ!MTB"
        threat_id = "2147910019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 f2 88 d0 a2}  //weight: 2, accuracy: High
        $x_2_2 = {01 20 4a b8}  //weight: 2, accuracy: High
        $x_2_3 = {31 d0 8d 05 ?? ?? ?? ?? 31 28 89 d0 89 d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAQ_2147910550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAQ!MTB"
        threat_id = "2147910550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AZY_2147910600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AZY!MTB"
        threat_id = "2147910600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 85 f4 f7 ff ff 83 ad f4 f7 ff ff 64 8a 95 f4 f7 ff ff 8b 85 f8 f7 ff ff 30 14 30 83 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPZR_2147910744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPZR!MTB"
        threat_id = "2147910744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "OydhectrPaaehaarisoe" ascii //weight: 2
        $x_1_2 = "lidaolania96.dll" ascii //weight: 1
        $x_1_3 = "OydhectrPaaehaarisoe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXY_2147911429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXY!MTB"
        threat_id = "2147911429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 6a 08 99 5e f7 fe 8a 82 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 81 f9 0c ac 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXU_2147912027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXU!MTB"
        threat_id = "2147912027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 89 d0 89 d8 50 8f 05 ?? ?? ?? ?? 29 c2 8d 05 ?? ?? ?? ?? 01 38 31 c2 29 d0 83 e8 ?? 8d 05 ?? ?? ?? ?? 01 28 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXU_2147912027_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXU!MTB"
        threat_id = "2147912027"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c2 8d 05 ?? ?? ?? ?? 31 28 89 c2 4a 01 1d ?? ?? ?? ?? 83 ea ?? 31 c2 01 3d ?? ?? ?? ?? 4a 83 c2 ?? b8 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 89 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMMJ_2147912427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMMJ!MTB"
        threat_id = "2147912427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 ?? 8a 4d ?? 8b 15 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GLN_2147912930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GLN!MTB"
        threat_id = "2147912930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 d0 42 b9 ?? ?? ?? ?? e2 ?? 29 c2 8d 05 ?? ?? ?? ?? 31 28 89 c2 01 c2 8d 05 ?? ?? ?? ?? 89 18 8d 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPAD_2147912964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPAD!MTB"
        threat_id = "2147912964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 83 ec 08 8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 55 fa 0f b6 75 fb 31 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GQZ_2147914920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GQZ!MTB"
        threat_id = "2147914920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 8a 45 ?? 8a 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 10, accuracy: Low
        $x_10_2 = {55 89 e5 8a 45 ?? 8a 4d ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_GZZ_2147915102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZZ!MTB"
        threat_id = "2147915102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZZ_2147915102_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZZ!MTB"
        threat_id = "2147915102"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 10 89 45 e8 68 04 00 00 80 6a 00 68 b7 02 42 00 68 01 00 00 00 bb dc 09 00 00 e8 ?? ?? ?? ?? 83 c4 10 89 45 e4 8d 45 fc 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPCK_2147915322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPCK!MTB"
        threat_id = "2147915322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 30 c8 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SCVP_2147915933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SCVP!MTB"
        threat_id = "2147915933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AwcdthodsHlu" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAR_2147916074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAR!MTB"
        threat_id = "2147916074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPUK_2147916225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPUK!MTB"
        threat_id = "2147916225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 d6 81 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPN_2147916326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPN!MTB"
        threat_id = "2147916326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ewtr4_e7bh8_9r7ty89_4y51t5h1" ascii //weight: 2
        $x_1_2 = "rep2583lace" ascii //weight: 1
        $x_1_3 = "rep2004ace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPZC_2147916345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPZC!MTB"
        threat_id = "2147916345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SZZC_2147916439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SZZC!MTB"
        threat_id = "2147916439"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAI_2147916469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAI!MTB"
        threat_id = "2147916469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SXZC_2147916528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SXZC!MTB"
        threat_id = "2147916528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 15 41 28 22 10 0f b6 35 42 28 22 10 31 f2 88 d0 a2 40 28 22 10 8b 15 24 28 22 10 81 ea e0 0e 00 00 89 15 24 28 22 10 c7 05 24 28 22 10 4e 0a 00 00 a0 40 28 22 10 88 45 f9 8a 45 f9 0f b6 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAS_2147916537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAS!MTB"
        threat_id = "2147916537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d6 88 d0 a2 ?? ?? ?? ?? 8a 45 ?? a2 ?? ?? ?? ?? 8a 45 ?? a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 88 d0 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SCZC_2147916556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SCZC!MTB"
        threat_id = "2147916556"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? f3 08 00 00 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNK_2147916624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNK!MTB"
        threat_id = "2147916624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af d6 88 d0 a2 ?? ?? ?? ?? 8a 45 ?? a2 ?? ?? ?? ?? 8a 45 ?? a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 89 55 ?? 8b 45 ?? 88 c1 88 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_MBXK_2147916654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.MBXK!MTB"
        threat_id = "2147916654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d [0-21] 30 c8 a2 [0-53] 0f b6 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {37 00 39 00 4f 00 54 00 4a 00 31 00 4d 00 30 00 57 00 2e 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SSZC_2147916727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SSZC!MTB"
        threat_id = "2147916727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 31 f2 88 d0 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SHZC_2147916811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SHZC!MTB"
        threat_id = "2147916811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAJ_2147916865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAJ!MTB"
        threat_id = "2147916865"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 d0 88 c1 88 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d ?? ?? 00 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c4 08 5e 5d c3}  //weight: 4, accuracy: Low
        $x_1_2 = {01 f2 88 d0 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAK_2147916959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAK!MTB"
        threat_id = "2147916959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 88 ?? ?? ?? ?? 10 ?? ?? ?? ?? 10 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SCCK_2147917130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SCCK!MTB"
        threat_id = "2147917130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAL_2147917189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAL!MTB"
        threat_id = "2147917189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 8a 45 ?? 8a 4d ?? 88 0d [0-4] 88 c2 30 ca a2 [0-4] 88 15 [0-4] 8b 35 [0-4] 81 c6 [0-4] 89 35 [0-4] c7 05 [0-8] 0f b6 c2 5e 5d c3}  //weight: 5, accuracy: Low
        $x_5_2 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-4] 88 45 ff 88 4d fe 8a 45 ff a2 [0-4] 8a 4d fe 30 c8 a2 [0-4] c7 05 [0-8] c7 05 [0-8] 0f b6 c0 83 c4 04 5d c3}  //weight: 5, accuracy: Low
        $x_5_3 = {31 f2 88 d4 88 25 [0-4] c7 05 [0-8] c7 05 [0-8] c7 05 [0-8] 0f b6 05 8c 40 1f 10 83 c4 04 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_GNX_2147917241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNX!MTB"
        threat_id = "2147917241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 50 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 88 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PH_2147917335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PH!MTB"
        threat_id = "2147917335"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 50 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 45 ?? 8a 45 ?? 0f b6 c0 83 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAT_2147917385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAT!MTB"
        threat_id = "2147917385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 83 ec ?? 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAM_2147917449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAM!MTB"
        threat_id = "2147917449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 88 c2 30 ca 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? c7 05 [0-8] c7 05 [0-8] 0f b6 c2 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SBMB_2147917503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SBMB!MTB"
        threat_id = "2147917503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 45 ff 8a 45 ff 0f b6 c0 83 c4 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAN_2147917657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAN!MTB"
        threat_id = "2147917657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 c0 83 c4 04}  //weight: 2, accuracy: High
        $x_1_3 = {8a 4d fe 30 c8 a2}  //weight: 1, accuracy: High
        $x_3_4 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? 10 88 45 fb 88 4d fa 8a 45 fb 8a 4d fa 30 c8 8a 55 fb 88 15 ?? ?? ?? 10 a2}  //weight: 3, accuracy: Low
        $x_3_5 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? 10 88 c2 30 ca a2}  //weight: 3, accuracy: Low
        $x_2_6 = {0f b6 c0 83 c4 04 5e 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zenpak_SXMB_2147917713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SXMB!MTB"
        threat_id = "2147917713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 45 ff 8a 45 ff 0f b6 c0 83 c4 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SZMB_2147917714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SZMB!MTB"
        threat_id = "2147917714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 45 ff a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 4d ff 0f b6 c1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SSMB_2147917844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SSMB!MTB"
        threat_id = "2147917844"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAU_2147917845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAU!MTB"
        threat_id = "2147917845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 50 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 88 45 ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 4d ?? 0f b6 c1 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXM_2147917935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXM!MTB"
        threat_id = "2147917935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 c2 30 ca 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 55}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAO_2147918381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAO!MTB"
        threat_id = "2147918381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 50 8a 45 0c 8a 4d 08 88 0d [0-4] a2 [0-4] 30 c8 a2 [0-4] 88 45 ff c7 05 [0-8] a1 [0-4] 05 [0-4] a3 [0-4] 8a 4d ff 0f b6 c1 83 c4 04 5d c3}  //weight: 5, accuracy: Low
        $x_5_2 = {55 89 e5 83 ec 08 8a 45 0c 8a 4d 08 88 0d [0-4] a2 [0-4] 30 c8 a2 [0-4] 8b 15 [0-4] 81 c2 [0-4] 88 45 ff 89 55 f8 8b 45 f8 a3 [0-4] c7 05 [0-8] 8a 4d ff 0f b6 c1 83 c4 08 5d c3}  //weight: 5, accuracy: Low
        $x_5_3 = {55 89 e5 56 8a 45 0c 8a 4d 08 8b 15 [0-4] 88 0d [0-4] 89 d6 81 c6 [0-4] 89 35 [0-4] a2 [0-4] 30 c8 a2 [0-4] 81 c2 [0-4] 89 15 [0-4] 0f b6 c0 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zenpak_GXD_2147918429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXD!MTB"
        threat_id = "2147918429"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {30 c8 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SKXC_2147918530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SKXC!MTB"
        threat_id = "2147918530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMN_2147918603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMN!MTB"
        threat_id = "2147918603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 f2 88 d0 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 83 c4 ?? 5e 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAW_2147918750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAW!MTB"
        threat_id = "2147918750"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 56 8a 45 [0-50] 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAX_2147918872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAX!MTB"
        threat_id = "2147918872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 56 8a 45 [0-50] 30 c8 81 c2 [0-15] 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAP_2147918987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAP!MTB"
        threat_id = "2147918987"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? 10 88 15 ?? ?? ?? 10 88 0d ?? ?? ?? 10 a2 ?? ?? ?? 10 30 c8 8b 35 ?? ?? ?? 10 81 c6 [0-4] 89 35 ?? ?? ?? 10 c7 05 [0-8] 0f b6 c0 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SNUK_2147919257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SNUK!MTB"
        threat_id = "2147919257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMAG_2147919407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMAG!MTB"
        threat_id = "2147919407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 0f b6 c0 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAY_2147919632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAY!MTB"
        threat_id = "2147919632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 56 8a 45 ?? ?? ?? ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMAI_2147920086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMAI!MTB"
        threat_id = "2147920086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 0c 8a 4d ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 8b 35 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c0 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAQ_2147920184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAQ!MTB"
        threat_id = "2147920184"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 4d f6 0f b6 55 f7 31 d1 88 cb 88 5d f5 8b 0d ?? ?? ?? 10 81 e9 ?? ?? ?? 00 89 0d ?? ?? ?? 10 c7 05 [0-8] 0f b6 45 f5 83 c4 08 5e 5b 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNM_2147920296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNM!MTB"
        threat_id = "2147920296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c2 31 d0 89 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff e0 01 35 ?? ?? ?? ?? 48 42 89 2d ?? ?? ?? ?? b8 ?? ?? ?? ?? 89 d8 50 8f 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNM_2147920296_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNM!MTB"
        threat_id = "2147920296"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 f2 88 d0 88 45 ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 45 ?? 83 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAZ_2147920361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAZ!MTB"
        threat_id = "2147920361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 ?? 8a 4d ?? 88 c2 30 ca 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXN_2147920503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXN!MTB"
        threat_id = "2147920503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 c4 30 cc 00 c2 88 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMAK_2147920546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMAK!MTB"
        threat_id = "2147920546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 [0-53] 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c0 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SSUK_2147920645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SSUK!MTB"
        threat_id = "2147920645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4d 08 88 c2 30 ca 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GNN_2147920919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GNN!MTB"
        threat_id = "2147920919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 31 c2 89 e0 50 8f 05 ?? ?? ?? ?? 42 48 eb ?? 4a 83 c2 ?? 83 f0 ?? 83 c0 ?? 89 d8 50 8f 05 ?? ?? ?? ?? 83 f0 ?? b8 ?? ?? ?? ?? 31 35 ?? ?? ?? ?? 89 e8 50}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZT_2147921002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZT!MTB"
        threat_id = "2147921002"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 30 8d 05 ?? ?? ?? ?? ff d0 89 c2 8d 05 ?? ?? ?? ?? 89 18 42 01 3d ?? ?? ?? ?? 42 31 d0 89 e8 50 8f 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GBZ_2147921669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GBZ!MTB"
        threat_id = "2147921669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c2 8d 05 ?? ?? ?? ?? 89 38 83 c2 ?? 29 d0 48 8d 05 ?? ?? ?? ?? 31 30 b8 ?? ?? ?? ?? 31 c2 83 ea ?? 8d 05 ?? ?? ?? ?? 01 18 b9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXT_2147921674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXT!MTB"
        threat_id = "2147921674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ea 05 42 4a 40 ?? ?? 31 c2 8d 05 ?? ?? ?? ?? 01 30 e8 ?? ?? ?? ?? 4a 89 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PVH_2147921866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PVH!MTB"
        threat_id = "2147921866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GCN_2147922424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GCN!MTB"
        threat_id = "2147922424"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 83 c2 ?? 83 e8 ?? e8 ?? ?? ?? ?? c3 31 d0 b8 ?? ?? ?? ?? 31 35 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 18 8d 05 ?? ?? ?? ?? 31 38 8d 05 ?? ?? ?? ?? ff d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GCW_2147922613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GCW!MTB"
        threat_id = "2147922613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 30 83 c2 ?? 83 f2 ?? 8d 05 ?? ?? ?? ?? 89 28 31 c2 b8 ?? ?? ?? ?? 89 d8 50 8f 05 ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? 01 38 8d 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMF_2147922614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMF!MTB"
        threat_id = "2147922614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 88 45 [0-144] a2 ?? ?? ?? ?? c7 05 [0-144] 0f b6 05 ?? ?? ?? ?? 83 c4 04 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GQT_2147922911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GQT!MTB"
        threat_id = "2147922911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c2 31 c2 89 d0 83 c2 ?? 8d 05 ?? ?? ?? ?? 31 20 01 c2 4a 48 29 d0 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMK_2147923006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMK!MTB"
        threat_id = "2147923006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIM_2147923091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIM!MTB"
        threat_id = "2147923091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d0 31 25 ?? ?? ?? 00 89 d0 e8 15 00 00 00 b8 06 00 00 00 8d 05 10 10 ?? 00 01 30 8d 05 f5 11 ?? 00 50 c3 8d 05 1c ?? ?? 00 89 28 83 c0 09 83 f0 05 89 1d 18 10 ?? 00 89 c2 31 3d 14 10 ?? 00 eb cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AML_2147923107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AML!MTB"
        threat_id = "2147923107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 57 56 8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 0d 00 a2 ?? ?? ?? ?? 89 f7 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c2 5e 5f 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PPPY_2147923247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PPPY!MTB"
        threat_id = "2147923247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 f7 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPPW_2147923469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPPW!MTB"
        threat_id = "2147923469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GDN_2147923549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GDN!MTB"
        threat_id = "2147923549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 8d 05 ?? ?? ?? ?? 89 20 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? c3 48 31 d0 48 31 1d ?? ?? ?? ?? 01 35}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SDPW_2147923559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SDPW!MTB"
        threat_id = "2147923559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SDPW_2147923559_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SDPW!MTB"
        threat_id = "2147923559"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 05 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_STGP_2147923821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.STGP!MTB"
        threat_id = "2147923821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 81 c2 24 e0 ff ff 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GXH_2147923924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GXH!MTB"
        threat_id = "2147923924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4a 31 c2 31 1d ?? ?? ?? ?? ba ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c2 29 d0 8d 05 ?? ?? ?? ?? 01 30 31 2d ?? ?? ?? ?? 31 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AZN_2147924072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AZN!MTB"
        threat_id = "2147924072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 45 0c 8a 4d 08 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 55 fb 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PNFH_2147924330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PNFH!MTB"
        threat_id = "2147924330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIO_2147924583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIO!MTB"
        threat_id = "2147924583"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 d0 48 89 c2 42 8d 05 ?? ?? ?? ?? 01 38 e8 ?? ?? ?? ?? c3 40 8d 05 ?? ?? ?? ?? 89 28 4a ba 09 00 00 00 40 89 d8 50 8f 05 ?? ?? ?? ?? 48 40 89 f0 50 8f 05 ?? ?? ?? ?? b9 02 00 00 00 e2 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PNMH_2147924711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PNMH!MTB"
        threat_id = "2147924711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? b3 23 00 00 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SXNW_2147924723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SXNW!MTB"
        threat_id = "2147924723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c2 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ABCA_2147924913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ABCA!MTB"
        threat_id = "2147924913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GMT_2147925135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GMT!MTB"
        threat_id = "2147925135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d0 83 f0 ?? 29 d0 e8 ?? ?? ?? ?? 4a 8d 05 ?? ?? ?? ?? 89 28 83 c0 ?? 31 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? ff d0 40 8d 05 ?? ?? ?? ?? 31 30 40 01 d0 31 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PNVH_2147925273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PNVH!MTB"
        threat_id = "2147925273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 c9 10 00 00 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 69 0a 00 00 0f b6 c4 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAAB_2147925624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAAB!MTB"
        threat_id = "2147925624"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PMDH_2147925642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PMDH!MTB"
        threat_id = "2147925642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PMJH_2147925827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PMJH!MTB"
        threat_id = "2147925827"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SMNW_2147925832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SMNW!MTB"
        threat_id = "2147925832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5e}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PMMH_2147925925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PMMH!MTB"
        threat_id = "2147925925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 71 0d 00 00 0f b6 c4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SPZK_2147926241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SPZK!MTB"
        threat_id = "2147926241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIQ_2147926272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIQ!MTB"
        threat_id = "2147926272"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 48 01 c2 83 f0 07 8d 05 ?? ?? ?? ?? 89 20 eb 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PMVH_2147926301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PMVH!MTB"
        threat_id = "2147926301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 89 f7 ?? ?? ?? ?? ff ff 89 3d 18 e4 2a 10 81 c6 ea be ff ff 89 35 ?? ?? ?? ?? 0f b6 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PMYH_2147926415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PMYH!MTB"
        threat_id = "2147926415"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0c 8a 4d 08 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 89 f7 81 c7 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 0f b6 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_HZ_2147926595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.HZ!MTB"
        threat_id = "2147926595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 3b 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 3b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAT_2147927159_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAT!MTB"
        threat_id = "2147927159"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c2 02 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c2 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAAC_2147927161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAAC!MTB"
        threat_id = "2147927161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 ?? 8a 4d ?? 30 c8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c0 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCP_2147927602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCP!MTB"
        threat_id = "2147927602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 [0-50] 01 f2 88 d0 a2 ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fb a2 [0-30] 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAAD_2147927611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAAD!MTB"
        threat_id = "2147927611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ASAU_2147927822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ASAU!MTB"
        threat_id = "2147927822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 55 fb 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0}  //weight: 2, accuracy: Low
        $x_2_2 = {50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa}  //weight: 2, accuracy: High
        $x_1_3 = {01 f2 88 d0 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SUZK_2147928248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SUZK!MTB"
        threat_id = "2147928248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 45 0c 8a 4d 08 31 d2 88 d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMGA_2147928446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMGA!MTB"
        threat_id = "2147928446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCU_2147928540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCU!MTB"
        threat_id = "2147928540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCU_2147928540_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCU!MTB"
        threat_id = "2147928540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCW_2147929091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCW!MTB"
        threat_id = "2147929091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_KAAF_2147929299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.KAAF!MTB"
        threat_id = "2147929299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 ?? 8a 4d ?? 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCZ_2147929856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCZ!MTB"
        threat_id = "2147929856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ALIA_2147930103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ALIA!MTB"
        threat_id = "2147930103"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMIA_2147930104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMIA!MTB"
        threat_id = "2147930104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GPPB_2147930219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GPPB!MTB"
        threat_id = "2147930219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {55 89 e5 8a 45 ?? 8a 4d ?? 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 8b 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMCY_2147930983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMCY!MTB"
        threat_id = "2147930983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 8b 5c 24 20 55 8b 6c 24 20 57 55 ff 15 ?? ?? ?? ?? 53 8b f8 66 c7 44 24 14 02 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 10 8b 08 8d 44 24 ?? 50 8b 11 8b 4e 08 51 89 54 24 ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AMDA_2147931241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AMDA!MTB"
        threat_id = "2147931241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GB_2147931394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GB!MTB"
        threat_id = "2147931394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 a8 fd ff ff 33 d2 b9 0a 00 00 00 f7 f1 b8 01 00 00 00 6b c8 00 8d 84 0d 70 ef ff ff 0f be 0c 10 8b 95 e0 f7 ff ff 03 95 a8 fd ff ff 0f b6 02 33 c1 8b 8d e0 f7 ff ff 03 8d a8 fd ff ff 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_PLIIH_2147931542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.PLIIH!MTB"
        threat_id = "2147931542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AFKA_2147932469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AFKA!MTB"
        threat_id = "2147932469"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GSQ_2147932920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GSQ!MTB"
        threat_id = "2147932920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 28 40 8d 05 ?? ?? ?? ?? 89 38 01 c2 42 83 e8 ?? 31 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTK_2147935168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTK!MTB"
        threat_id = "2147935168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 54 4d ?? 8b 85 ?? ?? ?? ?? 0f b7 4c 45 ?? 33 d1 8b 85 ?? ?? ?? ?? 66 89 54 45 ?? ?? ?? b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AZE_2147935352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AZE!MTB"
        threat_id = "2147935352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 cd 02 2d ?? 49 5f 10 88 2d ?? 49 5f 10 88 0d ?? 49 5f 10 a2 ?? 49 5f 10 c7 05 ?? 49 5f 10 09 1b 00 00 c7 05 ?? 49 5f 10 5f 0d 00 00 0f b6 c4 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_CCIR_2147936009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.CCIR!MTB"
        threat_id = "2147936009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 06 00 00 00 83 f2 09 83 f2 06 8d 05 ?? ?? ?? ?? c7 00 00 00 00 00 01 20 b9 02 00 00 00 e2 1c ba 06 00 00 00 83 c2 03 31 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AGOA_2147936202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AGOA!MTB"
        threat_id = "2147936202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AJOA_2147936218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AJOA!MTB"
        threat_id = "2147936218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 88 cd 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AXOA_2147936789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AXOA!MTB"
        threat_id = "2147936789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_AYOA_2147936813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.AYOA!MTB"
        threat_id = "2147936813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 89 e5 56 50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ZHY_2147937229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ZHY!MTB"
        threat_id = "2147937229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 8a 45 0c 8a 4d 08 31 d2 88 d4 88 45 fb 88 4d fa 0f b6 55 fa 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8a 45 fa a2 ?? ?? ?? ?? 8a 45 fb a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 83 c4 04 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTY_2147937687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTY!MTB"
        threat_id = "2147937687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 d0 31 d2 89 15 ?? ?? ?? ?? 01 35 ?? ?? ?? ?? 42 29 c2 01 c2 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BAA_2147937900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BAA!MTB"
        threat_id = "2147937900"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 28 c1 ef 05 03 c1 03 7c 24 1c 33 f8 8d 04 1a 33 f8 81 fe ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_BAB_2147938079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.BAB!MTB"
        threat_id = "2147938079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 c8 03 45 f0 89 45 f0 8b 45 ec 83 c0 01 89 45 ec eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ZYY_2147938679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ZYY!MTB"
        threat_id = "2147938679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 53 81 ec ?? ?? ?? ?? b8 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 80 39 6a 89 85 ?? ?? ?? ?? 0f 84 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 05 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 80 38 2e 74 ?? eb ?? 80 bd ?? ?? ?? ?? 2e 75 16 31 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTZ_2147938911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTZ!MTB"
        threat_id = "2147938911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 56 50 8a 45 ?? 8a 4d ?? 31 d2 88 d4 88 45 ?? 88 4d ?? 8b 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 55 ?? 0f b6 35 ?? ?? ?? ?? 01 f2 88 d0 a2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTB_2147938913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTB!MTB"
        threat_id = "2147938913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 30 83 e8 ?? 8d 05 ?? ?? ?? ?? 89 38 ?? ?? ?? ?? ?? 40 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18 89 d0 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GTB_2147938913_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GTB!MTB"
        threat_id = "2147938913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ca 01 25 ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 ?? ff d0 89 d8 01 05 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 89 e8 01 05 ?? ?? ?? ?? 89 f8 01 05}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SEZC_2147938956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SEZC!MTB"
        threat_id = "2147938956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {22 00 00 c7 05 ?? ?? ?? ?? ?? ?? ?? 00 0f b6 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ZVY_2147939053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ZVY!MTB"
        threat_id = "2147939053"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 31 d2 88 d4 88 cd 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 d6 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ZEY_2147939713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ZEY!MTB"
        threat_id = "2147939713"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 cd 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 18 ee 60 00 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GYZ_2147940202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GYZ!MTB"
        threat_id = "2147940202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 c2 01 d0 8d 05 ?? ?? ?? ?? 89 18 83 e8 ?? 4a 8d 05 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 31 30 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 3d ?? ?? ?? ?? 8d 05 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 31 28}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_SEC_2147940631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.SEC!MTB"
        threat_id = "2147940631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {88 cc 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5e}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ZTY_2147940764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ZTY!MTB"
        threat_id = "2147940764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 89 e5 56 8a 45 0c 8a 4d 08 b2 01 8b 35 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c2 5e 5d c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_ABC_2147942015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.ABC!MTB"
        threat_id = "2147942015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 10 31 30 42 89 2d ?? ?? ?? ?? 31 c2 83 f2 02 29 c2 ba 08 00 00 00 8d 05 ?? ?? ?? ?? 89 18 b9 02 00 00 00 e2}  //weight: 4, accuracy: Low
        $x_1_2 = {55 89 e5 8a 45 0c 8a 4d 08 b2 01 88 cc 02 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GZK_2147942829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GZK!MTB"
        threat_id = "2147942829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 f2 0a 42 8d 05 ?? ?? ?? ?? 89 38 8d 05 ?? ?? ?? ?? ff d0 83 f2 ?? 83 ea ?? 8d 05 ?? ?? ?? ?? 31 d2 89 10 31 18 4a 48 8d 05 ?? ?? ?? ?? c7 00 ?? ?? ?? ?? 31 28 b9 02 00 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenpak_GVB_2147951189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenpak.GVB!MTB"
        threat_id = "2147951189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenpak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4b 8d 0c 0b 41 30 41 02 48 8b c7 48 f7 e1 48 c1 ea 02 48 8d 04 92 4c 2b c0 41 0f b6 44 28 05 41 30 41 03 49 83 c1 06 4b 8d 04 0a 48 3d 00 18 00 00 0f 82 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

