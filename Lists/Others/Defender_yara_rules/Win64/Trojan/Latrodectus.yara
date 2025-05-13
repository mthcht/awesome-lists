rule Trojan_Win64_Latrodectus_PA_2147904850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PA!MTB"
        threat_id = "2147904850"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 99 8b 8c 24 ?? ?? ?? ?? f7 f9 48 98 48 8d 44 04 ?? 48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 08 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PB_2147904851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PB!MTB"
        threat_id = "2147904851"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 01 00 00 00 48 6b d2 2a 0f be 94 14 ?? ?? ?? ?? 0f af ca 48 63 c9 48 2b c1 0f b6 44 04 ?? 8b 8c 24 ?? ?? ?? ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PC_2147904945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PC!MTB"
        threat_id = "2147904945"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 04 02 8d 44 08 ?? 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a 0f b6 44 24 ?? 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DA_2147905658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DA!MTB"
        threat_id = "2147905658"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 4b 7c 8b 43 64 35 23 31 01 00 c1 ea 10 29 43 18 48 8b 05 ?? ?? ?? ?? 88 14 01 41 8b d0 ff 43 7c 48 8b 05 ?? ?? ?? ?? c1 ea 08 48 63 48 7c 48 8b 80 a0 00 00 00 88 14 01}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 c8 48 f7 e2 48 c1 ea 02 48 89 d0 48 c1 e0 02 48 01 d0 48 01 c0 48 01 d0 48 01 c0 48 29 c1 48 89 ca 0f b6 84 15 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? 01 48 8b 85 ?? ?? ?? ?? 48 39 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Latrodectus_DB_2147908540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DB!MTB"
        threat_id = "2147908540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 03 cc 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 ?? c0 48 ?? c8 48 ?? cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DY_2147908767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DY!MTB"
        threat_id = "2147908767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 c9 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 45 03 cc 48 f7 e1 48 c1 ea 04 48 6b c2 13 48 2b c8 48 2b cb 8a 44 0c 20 43 32 04 ?? 41 88 02 4d 03 d4 45 3b cd 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PD_2147910582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PD!MTB"
        threat_id = "2147910582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 49 8b c4 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 19 48 2b c8 49 2b cd 0f b6 44 0c ?? 43 32 44 0a ?? 41 88 41 ?? 41 8d 47 ?? 48 63 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PE_2147910693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PE!MTB"
        threat_id = "2147910693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 c8 49 8b c4 48 f7 e1 48 c1 ea 04 48 6b c2 11 48 2b c8 49 2b cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 41 8d 42 ?? 48 63 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PF_2147910694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PF!MTB"
        threat_id = "2147910694"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 29 c2 8b 85 ?? ?? ?? ?? 48 98 48 01 c2 8b 85 ?? ?? ?? ?? 48 98 48 29 c2 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 48 98 48 01 d0 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 48 8b 85 ?? ?? ?? ?? 48 83 c0 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PG_2147914223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PG!MTB"
        threat_id = "2147914223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 ca 49 8b c7 41 ff c2 4d 8d 49 ?? 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 49 2b cb 0f b6 44 0c ?? 42 32 44 0b ?? 41 88 41 ?? 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_PG_2147914223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PG!MTB"
        threat_id = "2147914223"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4d 2b d1 4e 8d 04 0b 48 8b cb 48 b8 cd cc cc cc cc cc cc cc 48 f7 e3 48 c1 ea ?? 48 ff c3 48 8d ?? 92 48 c1 e0 ?? 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00 48 81 fb [0-4] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_MA_2147914271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.MA!MTB"
        threat_id = "2147914271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 2b c8 48 2b cb 0f b6 44 0c ?? 43 32 44 0b ?? 41 88 41 ?? 41 81 fa ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_OBS_2147917294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.OBS!MTB"
        threat_id = "2147917294"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 63 ca 48 b8 ab aa aa aa aa aa aa aa 41 ff c2 48 f7 e1 48 c1 ea 04 48 8d 04 52 48 c1 e0 03 48 2b c8 49 03 cb 8a 44 0c 20 42 32 04 0b 41 88 01 49 ff c1 45 3b d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_LAZ_2147917698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.LAZ!MTB"
        threat_id = "2147917698"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 03 d6 48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 1c 48 2b c8 48 03 cb 8a 44 0c 20 43 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_QEZ_2147917700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.QEZ!MTB"
        threat_id = "2147917700"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 48 74 33 48 0c 41 8b 42 40 83 f1 01 0f af c1 41 8b d0 c1 ea 08 41 89 42 40 48 8b 05 43 e5 00 00 48 63 88 ?? ?? ?? ?? 49 8b 82 e8 00 00 00 88 14 01 48 8b 05 2b e5 00 00 ff 80 ?? ?? ?? ?? 49 63 8a ?? ?? ?? ?? 49 8b 82 e8 00 00 00 44 88 04 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_MEA_2147918454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.MEA!MTB"
        threat_id = "2147918454"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {45 03 c3 41 c1 e0 02 41 0f b6 c1 41 fe c1 41 03 c0 8a 0c 18 30 0a 48 ff c2 41 80 f9 04 72 e8}  //weight: 3, accuracy: High
        $x_3_2 = {41 32 c2 4d 8d 76 04 32 c3 40 32 c7 40 32 c6 41 88 46 fd 48 83 ed 01}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DC_2147919194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DC!MTB"
        threat_id = "2147919194"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 03 48 8d 7c 24 40 49 8d 0c 86 41 8b 03 42 8b 2c 09 49 03 c1 eb ?? 3a 0f 75 ?? 48 ff c0 48 ff c7 8a 08 84 c9 75 ?? 8a 08 41 8b d0 41 8b c0 3a 0f 0f 97 c2 38 0f 0f 97 c0 3b d0 74 ?? 41 ff c2 48 83 c3 02 49 83 c3 04 44 3b d6 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DD_2147919789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DD!MTB"
        threat_id = "2147919789"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b7 03 48 8b d5 49 8d 0c 86 42 8b 34 09 41 8b 0a 49 03 c9 e8 ?? ?? ?? ?? 85 c0 74 ?? ff c3 49 83 c3 02 49 83 c2 04 3b df 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {49 63 ca 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 44 03 d6 48 f7 e1 [0-50] 48 c1 ?? 04 48 6b ?? ?? 48 2b c8 49 ?? cb 8a 44 0c 20 42 32 04 0b 41 88 01 4c 03 ce 45 3b d4 72}  //weight: 1, accuracy: Low
        $x_1_3 = {48 63 cb 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 41 03 df 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 48 2b ce 8a 44 0c 20 43 32 04 1a 41 88 03 4d 03 df 81 fb 00 ec 01 00 72}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 63 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 49 f7 e0 48 c1 ea 02 48 6b c2 16 4c 2b c0 41 8b c1 44 03 ce 99 4d 2b c3 f7 fb 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 63 c8 42 8a 44 04 20 32 04 11 41 88 02 4c 03 d6 45 3b cc 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Latrodectus_PH_2147921595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.PH!MTB"
        threat_id = "2147921595"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 63 ca 48 b8 cd cc cc cc cc cc cc cc 44 03 d6 48 f7 e1 48 c1 ea 04 48 8d ?? 92 48 c1 e0 ?? 48 2b c8 8a 44 0c ?? 43 32 04 0b 41 88 01 4c 03 ce 45 3b d7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DE_2147922315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DE!MTB"
        threat_id = "2147922315"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 03 cc 48 f7 e1 48 c1 ea 04 48 8d 04 d2 48 03 c0 48 2b c8 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 44 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_KLA_2147922913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.KLA!MTB"
        threat_id = "2147922913"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 89 c0 4c 89 c1 4c 89 c7 49 f7 e1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 29 d0 48 29 c7 0f b6 44 3c ?? 43 32 04 10 48 8b 54 24 ?? 42 88 04 02 49 83 c0 01 4c 39 44 24 40 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_ZSS_2147924637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.ZSS!MTB"
        threat_id = "2147924637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4c 89 c7 49 f7 e1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 29 d0 48 29 c7 0f b6 44 3c ?? 43 32 04 10 48 8b 54 24 ?? 42 88 04 02 49 83 c0 01 4c 39 44 24 40 77}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DF_2147926100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DF!MTB"
        threat_id = "2147926100"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 f7 e3 48 c1 ea 04 48 ff c3 48 8d 04 d2 48 03 c0 48 2b c8 8a 44 0d ?? 43 32 04 02 41 88 00 48 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DG_2147927471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DG!MTB"
        threat_id = "2147927471"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 a5 d3 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GNS_2147927742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GNS!MTB"
        threat_id = "2147927742"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 2b c8 49 0f af cb 0f b6 44 0c ?? 42 32 44 0e ?? 41 88 41 ?? 41 8d 42 ?? 41 83 c2 ?? 4c 63 c0 49 8b c7 49 f7 e0 48 c1 ea ?? 48 6b c2 ?? 4c 2b c0 4d 0f af c3 42 0f b6 44 04 28 43 32 44 0e fc 41 88 41 ff 49 ff cc 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DH_2147928561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DH!MTB"
        threat_id = "2147928561"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 5c 44 30 1c 0f 48 ff c1 48 89 c8 48 81 f9 d3 47 0a 00 0f 86}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GNP_2147929881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GNP!MTB"
        threat_id = "2147929881"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 89 e9 48 ff c9 48 29 f9 48 31 f7 48 83 c0 ?? 0f 57 c3 41 d1 e8 49 d1 ef 41 d1 e8 49 83 e1 ?? 41 83 e0 ?? 48 63 d0 48 63 c1 0f 28 ce 0f 28 f1 0f 28 d6 66 48 0f 7e d0 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 5e 5a 59 5b 58 41 88 0c 08 48 ff c1 48 83 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_ASJ_2147930148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.ASJ!MTB"
        threat_id = "2147930148"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 19 41 88 03 49 ff c3 41 81 fa}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_VKZ_2147932184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.VKZ!MTB"
        threat_id = "2147932184"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 31 d2 c4 c1 55 ef e9 49 f7 f1 66 0f 67 d7 45 8a 14 10 ?? 66 0f 6f fd 66 0f eb d3 66 0f fe f2 66 0f fe fa 66 0f 6f d8 44 30 14 0f 66 0f f6 c8 51 48 31 f9 59 48 ff c1 66 0f 73 ff ?? 48 89 c8 48 81 f9 d3 3b 01 00 76}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_RRR_2147932749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.RRR!MTB"
        threat_id = "2147932749"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 f7 f1 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 45 8a 14 10 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb 44 30 14 0f c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 ff c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GNQ_2147932767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GNQ!MTB"
        threat_id = "2147932767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 30 14 0f c4 41 7d 6f d0 48 ff c1 c4 41 1d fe e3 48 89 c8 c4 43 1d 0f e4 ?? 48 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GNE_2147932773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GNE!MTB"
        threat_id = "2147932773"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 30 14 0f c5 fd fd db c5 d5 fd f5 48 ff c1 c5 c5 71 d7 ?? c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 89 c8 c5 ed 67 d2 c5 e5 67 db 48 81 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_ASL_2147932895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.ASL!MTB"
        threat_id = "2147932895"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 8a 14 10 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb 44 30 14 0f c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 48 ff c1 c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd 48 89 c8 90 48 81 f9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GND_2147933629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GND!MTB"
        threat_id = "2147933629"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4d 31 ca 49 c1 e1 ?? 41 88 0c 08 c5 e5 d4 d9 48 ff c1 49 c1 e9 ?? 48 83 f9 ?? ?? ?? ?? 49 83 c9 ?? 48 31 c9 ?? 48 ff c2 48 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DI_2147936917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DI!MTB"
        threat_id = "2147936917"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 4c 24 ?? 33 d2 48 8b c1 b9 1a 00 00 00 48 f7 f1 48 8b c2 0f b6 84 04 [0-4] 8b 4c 24 ?? 33 c8 8b c1 48 63 4c 24 ?? 48 8b 54 24 ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DJ_2147937000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DJ!MTB"
        threat_id = "2147937000"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 63 cb 49 8b c1 ff c3 4d 8d 40 01 48 f7 e1 48 c1 ea 03 48 6b c2 1a 48 2b c8 48 8b 45 0f 0f b6 4c 0d 27 43 32 4c 10 ff 41 88 4c 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_DK_2147939452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.DK!MTB"
        threat_id = "2147939452"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 8b c6 99 41 ff c2 41 f7 fd 41 ff c6 34 35 0f b6 c8 41 0f b6 80 11 0d 00 00 0f af c1 0f b7 ce 41 88 80 11 0d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_ADTZ_2147940200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.ADTZ!MTB"
        threat_id = "2147940200"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8b d7 48 8b cf 48 2b d7 8a 04 0a 45 03 c4 88 01 49 63 c0 49 03 cc 49 3b c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_BY_2147940299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.BY!MTB"
        threat_id = "2147940299"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {45 8a 1c 10 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 c5 c5 68 f9 c5 cd fd eb c5 dd fd d3 44 30 1c 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_LLB_2147940328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.LLB!MTB"
        threat_id = "2147940328"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 44 30 14 0f c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4}  //weight: 5, accuracy: High
        $x_4_2 = {c5 e5 6a dc c5 f5 ef c9 48 ff c1 66 0f 70 fc 00 c5 fc 28 c1 c5 fc 28 d3}  //weight: 4, accuracy: High
        $x_3_3 = {0f 28 dc 48 89 c8 0f 28 df 44 0f 14 c0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_BH_2147940403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.BH!MTB"
        threat_id = "2147940403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {c5 dd 69 e9 c5 dd 61 e1 0f 58 c8 0f 28 c3 90 90 90 49 21 c4 49 83 eb 0a 90 41 88 0c 08 90 90 90 48 ff c1 41 08 ce 48 83 f9 72}  //weight: 4, accuracy: High
        $x_1_2 = {c5 d5 fd f5 4c 8d 44 24 20 c5 fd 67 c0 c5 f5 67 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_YAC_2147940966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.YAC!MTB"
        threat_id = "2147940966"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 5f 41 5b 44 30 2c 0f 66 0f d9 da 66 0f d9 d0 66 0f eb d3 66 0f 6f d8 66 0f f5 d1 66 0f fe f2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Latrodectus_GTS_2147941272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Latrodectus.GTS!MTB"
        threat_id = "2147941272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Latrodectus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {c5 fd 62 c3 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 45 8a 34 11 c5 e5 67 db}  //weight: 5, accuracy: High
        $x_4_2 = {c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 02 c5 fd 69 f4 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db 02 c5 e5 69 d7 44 30 34 0f c5 e5 67 db c5 dd fd e6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

