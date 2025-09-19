rule Trojan_Win32_Chapak_C_2147740999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.C"
        threat_id = "2147740999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 18 81 fe e6 26 00 00 7d 08 6a 00 ff 15 [0-3] 00 e8 [0-4] 30 04 37 83 ee 01 79 e3}  //weight: 1, accuracy: Low
        $x_1_2 = {81 fe 51 a1 00 00 75 05 e8 [0-3] ff 46 81 fe 5b 54 5a 00 7c ea 64 a1 2c 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 c2 03 c8 0f b6 c1 5e 8a 80 [0-3] 00 c3}  //weight: 1, accuracy: Low
        $x_1_4 = "yiyapeli" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_DSK_2147743508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.DSK!MTB"
        threat_id = "2147743508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 2a 02 88 44 24 11 8a 44 2a 03 8a c8 88 44 24 10 80 e1 f0 c0 e1 02 0a 0c 2a 81 3d ?? ?? ?? ?? e9 05 00 00 88 4c 24 12 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_GM_2147755831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.GM!MTB"
        threat_id = "2147755831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 8d 87 [0-16] 33 8d ?? ?? ?? ?? 88 8d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d 08 03 8d ?? ?? ?? ?? 8a 95 ?? ?? ?? ?? 88 11 [0-32] 8b 45 ?? 03 85 ?? ?? ?? ?? 8a 8d ?? ?? ?? ?? 88 08 83 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_DSA_2147759647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.DSA!MTB"
        threat_id = "2147759647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 87 d5 7c 3a 81 45 f8 8c eb 73 22 8b 4d f8 83 25 ?? ?? ?? ?? 00 8b c7 d3 e0 8b cf c1 e9 05 03 8d 14 fe ff ff 03 85 0c fe ff ff 33 c1 8b 8d 38 fe ff ff 03 cf 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_DEA_2147762372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.DEA!MTB"
        threat_id = "2147762372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reh777k6jh54gz4" ascii //weight: 1
        $x_1_2 = "qfwopkeamkofvvcs" ascii //weight: 1
        $x_1_3 = "ncvvgbefjwnrer" ascii //weight: 1
        $x_1_4 = "mnaoijfwepkwi4frg" ascii //weight: 1
        $x_1_5 = "eishfawinoefjf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Chapak_DEB_2147762417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.DEB!MTB"
        threat_id = "2147762417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\xehudavu yucusafo ledomugimehemiway_xekorop si.pdb" ascii //weight: 1
        $x_1_2 = "in\\xugujode.pdb" ascii //weight: 1
        $x_1_3 = "noyalahipu" ascii //weight: 1
        $x_1_4 = "layFCiwijajuroz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Chapak_MR_2147774340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.MR!MTB"
        threat_id = "2147774340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 e6 ?? 81 3d [0-8] [0-2] c1 e8 ?? 89 [0-3] 8b [0-3] 01 [0-5] 8d [0-2] 33 ?? 81 [0-9] c7 [0-9] 31 [0-3] 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_AHB_2147788265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.AHB!MTB"
        threat_id = "2147788265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 85 84 f8 ff ff a3 ?? ?? ?? ?? 8b 8d 84 f8 ff ff 69 c9 24 31 00 00 8b 15 04 e0 06 01 2b d1 89 95 84 f8 ff ff}  //weight: 10, accuracy: Low
        $x_3_2 = "half.pdb" ascii //weight: 3
        $x_3_3 = "Battheir" ascii //weight: 3
        $x_3_4 = "Cornerfamily" ascii //weight: 3
        $x_3_5 = "Wifefollow" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_DY_2147820171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.DY!MTB"
        threat_id = "2147820171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 07 3b 2d 0b 00 8b 0d [0-4] 88 04 0f 83 3d [0-4] 44 75 22}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ac 24 c0 01 00 00 03 c3 34 51 81 84 24 38 02 00 00 b8 20 fe 10 81 84 24 c0 01 00 00 ed a0 99 07 81 84 24 9c 00 00 00 80 a7 6e 68 81 84 24 c8 01 00 00 4b 8f 59 6d 81 84 24 6c 01 00 00 8c d4 9e 15 81 44 24 78 31 ae 7e 60}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff 92 b4 e7 00 7f 0d 47 81 ff 86 4b ec 5a 0f 8c}  //weight: 1, accuracy: High
        $x_1_4 = "GetTickCount" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_ARAE_2147846441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.ARAE!MTB"
        threat_id = "2147846441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b8 cd cc cc cc f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 8a 82 30 b4 40 00 30 04 31 41 3b cf 72 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_GPA_2147894385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.GPA!MTB"
        threat_id = "2147894385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {31 75 fc 2b 7d fc 81 c3 ?? ?? ?? ?? ff 4d ec 89 7d f0 0f 85 fe fe ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_GNT_2147895321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.GNT!MTB"
        threat_id = "2147895321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 1c 77 48 81 ad ?? ?? ?? ?? 44 13 5f 67 35 ?? ?? ?? ?? 81 85 ?? ?? ?? ?? 44 13 5f 67 c1 eb ?? bb ?? ?? ?? ?? 81 ad ?? ?? ?? ?? a4 b5 43 1d 81 85 ?? ?? ?? ?? a4 b5 43 1d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_RB_2147900566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.RB!MTB"
        threat_id = "2147900566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc f0 43 03 00 83 45 fc 0d a1 ?? ?? ?? ?? 0f af 45 fc 05 c3 9e 26 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_RX_2147903571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.RX!MTB"
        threat_id = "2147903571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stretch\\117\\past\\dream.pdb" ascii //weight: 1
        $x_1_2 = "dream.dll" ascii //weight: 1
        $x_1_3 = "Camparrive" ascii //weight: 1
        $x_1_4 = "Historylight" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_SPDB_2147907618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.SPDB!MTB"
        threat_id = "2147907618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 33 db 8b 45 f4 33 d1 03 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_GNN_2147918704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.GNN!MTB"
        threat_id = "2147918704"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {33 c2 33 c1 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAEA_2147929615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAEA!MTB"
        threat_id = "2147929615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f4 8b 45 f8 8b 55 f0 03 c1 8a 14 02 41 88 10 89 4d f4 3b 0d dc 94 42 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAJW_2147936807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAJW!MTB"
        threat_id = "2147936807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 00 33 85 68 ff ff ff 8b 8d 54 ff ff ff 89 01 81 7d f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAFR_2147938596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAFR!MTB"
        threat_id = "2147938596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 01 e1 bf 01 00 8b 15 ?? ?? ?? ?? 88 04 11 41 3b 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAFR_2147938596_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAFR!MTB"
        threat_id = "2147938596"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 06 e1 bf 01 00 8b 0d ?? ?? ?? ?? 88 04 0e 46 3b 35}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAUM_2147938598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAUM!MTB"
        threat_id = "2147938598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 94 01 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EAAL_2147943997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EAAL!MTB"
        threat_id = "2147943997"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 8c 31 f5 d0 00 00 8b 15 ?? ?? ?? ?? 88 0c 32 46 3b f0 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 8d 0c 07 e8 ?? ?? ?? ?? 30 01 47 3b fb 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_BAA_2147949085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.BAA!MTB"
        threat_id = "2147949085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b c6 c1 e0 04 03 45 e8 8d 0c 33 33 d0 33 d1 6a 00 2b fa 81 c3}  //weight: 2, accuracy: High
        $x_2_2 = {8b 45 08 89 38 89 70 04 83 c0 08 ff 4d f8 89 45 08 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Chapak_EFXB_2147952595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chapak.EFXB!MTB"
        threat_id = "2147952595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 4d fc c1 e0 04 03 45 f8 33 c8 8d 04 3b 33 c8 8d 9b}  //weight: 2, accuracy: High
        $x_2_2 = {8a 0c 0a 88 0c 02 42 8b 85 44 f7 ff ff 8b 8d 3c f7 ff ff 3b d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

