rule Trojan_Win32_Mokes_DSK_2147753107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.DSK!MTB"
        threat_id = "2147753107"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b cb c1 e9 05 03 4c 24 ?? c7 05 ?? ?? ?? ?? b4 1a 3a df 89 54 24 ?? 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c7 c1 e8 05 03 44 24 ?? 03 d7 33 ca 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df 89 35 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 4c 24 ?? 75}  //weight: 2, accuracy: Low
        $x_2_3 = {8b f3 03 d3 c1 ee 05 03 74 24 ?? c7 05 ?? ?? ?? ?? b4 1a 3a df 89 4c 24 ?? 89 54 24 ?? 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Mokes_PVD_2147753504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.PVD!MTB"
        threat_id = "2147753504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 ff 00 00 00 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 c3 03 d0 81 e2 ff 00 00 00 8a 8a ?? ?? ?? ?? 30 0c 37}  //weight: 2, accuracy: Low
        $x_2_2 = {25 ff 00 00 00 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 88 99 58 31 84 00 0f b6 80 ?? ?? ?? ?? 0f b6 cb 03 c1 25 ff 00 00 00 0f b6 ?? ?? ?? ?? ?? 30 14 3e}  //weight: 2, accuracy: Low
        $x_2_3 = {25 ff 00 00 00 8a 98 ?? ?? ?? ?? 88 ?? ?? ?? ?? ?? 88 99 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f b6 cb 03 ca 81 e1 ff 00 00 00 a3 ?? ?? ?? ?? 8a 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Mokes_PVA_2147756528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.PVA!MTB"
        threat_id = "2147756528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 05 00 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 11 41 3b 4d 08 7c 05 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RDV_2147774373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RDV!MTB"
        threat_id = "2147774373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 3b de 7e ?? 8b 45 ?? 8d 0c 07 e8 ?? ?? ?? ?? 30 01 83 fb 19 75 ?? 56 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RT_2147776623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RT!MTB"
        threat_id = "2147776623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c4 89 84 24 ?? ?? ?? ?? 56 33 f6 85 db 7e ?? e8 ?? ?? ?? ?? 30 04 37 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RT_2147776623_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RT!MTB"
        threat_id = "2147776623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 8b 4d ?? 33 4d ?? 89 4d ?? 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RT_2147776623_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RT!MTB"
        threat_id = "2147776623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? c6 0e 00 00 75 ?? 55 55 ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 cf 33 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RF_2147776784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RF!MTB"
        threat_id = "2147776784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ec 81 ec 04 08 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ?? 56 33 f6 85 db 7e ?? e8 ?? ?? ?? ?? 30 04 37 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RM_2147778100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RM!MTB"
        threat_id = "2147778100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 81 ff 85 02 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 ea 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? 33 c6 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Mokes_RMA_2147778108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RMA!MTB"
        threat_id = "2147778108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 85 ff 7e ?? 81 ff 85 02 00 00 75 ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 ?? 8d 0c 06 e8 ?? ?? ?? ?? 30 01 46 3b f7 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RMA_2147778108_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RMA!MTB"
        threat_id = "2147778108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b 6c 24 ?? 81 3d ?? ?? ?? ?? c7 0f 00 00 75 ?? 6a ?? 6a ?? 6a ?? 6a ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 69 c0 fd 43 03 00 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 37 83 fb 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RTH_2147778361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RTH!MTB"
        threat_id = "2147778361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 ?? ?? ?? ?? 84 10 d6 cb c7 05 ?? ?? ?? ?? ff ff ff ff 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 33 d6 33 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_MAK_2147788185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.MAK!MTB"
        threat_id = "2147788185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d8 8b c3 c1 e8 [0-1] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_MA_2147798603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.MA!MTB"
        threat_id = "2147798603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 74 00 2e 00 67 00 6f 00 67 00 61 00 6d 00 65 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-16] 2f 00 73 00 71 00 6c 00 69 00 74 00 65 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 74 2e 67 6f 67 61 6d 65 63 2e 63 6f 6d 2f [0-16] 2f 73 71 6c 69 74 65 2e 64 61 74}  //weight: 1, accuracy: Low
        $x_1_3 = "WriteFile" ascii //weight: 1
        $x_1_4 = {8b 44 24 04 a3 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b f0 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 24 a3 ?? ?? ?? ?? 5e c3}  //weight: 1, accuracy: Low
        $x_1_6 = {c6 40 04 00 83 08 ff c6 40 05 0a 89 78 08 c6 40 24 00 c6 40 25 0a c6 40 26 0a 83 c0 28 8b 0d ?? ?? ?? ?? 81 c1 00 05 00 00 3b c1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Mokes_B_2147828178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.B!MTB"
        threat_id = "2147828178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 44 24 1c 76 00 2e 00 [0-9] c7 44 24 ?? 7a 00 67 00 [0-9] c7 44 24 ?? 65 00 76 00 c7 44 24 ?? 2f 00 25 00 c7 44 24 ?? 64 00 2e 00 c7 44 24 ?? 6d 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RG_2147832056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RG!MTB"
        threat_id = "2147832056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_SK_2147847463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.SK!MTB"
        threat_id = "2147847463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "m_tempbrush" ascii //weight: 1
        $x_1_2 = "m_drawNumPen" ascii //weight: 1
        $x_1_3 = "AfxWnd90sd" ascii //weight: 1
        $x_1_4 = "AfxOldWndProc423" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_RA_2147850994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.RA!MTB"
        threat_id = "2147850994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e2 14 42 fc cf 79 86 c8 e8 00 00 00 00 75 04 74 02 bc 55 8b 1c 24 83 c4 04 eb 0a 40 81 eb 49 32 00 00 eb 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_AB_2147892575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.AB!MTB"
        threat_id = "2147892575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 e8 cd 0a ff ff 8d 46 44 50 e8 ca d7 fe ff 33 c0 83 c4 10 88 46 6c 89 46 70 66 89 46 74 88 46 76 8b 44 24 08 89 46 78 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_EW_2147899691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.EW!MTB"
        threat_id = "2147899691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kulajowutevigax" ascii //weight: 1
        $x_1_2 = "povenisorujuducogarulozuye" ascii //weight: 1
        $x_1_3 = "vekowitakorumac" ascii //weight: 1
        $x_1_4 = "niposubulibetuveyifozebetawujem" ascii //weight: 1
        $x_1_5 = "pofavuwuporiketaluduyisekena koxikerewacuzihasexutatafu" ascii //weight: 1
        $x_1_6 = "Rozuti yogujuficizarod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_SPD_2147901166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.SPD!MTB"
        threat_id = "2147901166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 4c 24 0c 30 04 31 83 ff 0f 75}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_AMCC_2147901497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.AMCC!MTB"
        threat_id = "2147901497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 ec 31 45 fc 33 55 fc 89 55 d8 8b 45 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_SPSB_2147923219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.SPSB!MTB"
        threat_id = "2147923219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d b5 f8 fb ff ff c7 85 f8 fb ff ff 00 00 00 00 e8 ?? ?? ?? ?? 8a 95 f8 fb ff ff 8b 85 f4 fb ff ff 30 14 38 83 fb 0f 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_EAUD_2147931204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.EAUD!MTB"
        threat_id = "2147931204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c7 33 c6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b d8 8b 44 24 1c 29 44 24 10 83 6c 24 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Mokes_EARS_2147934430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mokes.EARS!MTB"
        threat_id = "2147934430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mokes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 cf 33 ce c7 05 ?? ?? ?? ?? ff ff ff ff 2b d9 8b 44 24 28 29 44 24 10 83 6c 24 14 01}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

