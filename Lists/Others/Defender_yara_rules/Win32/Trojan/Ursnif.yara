rule Trojan_Win32_Ursnif_S_2147730204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.S!MTB"
        threat_id = "2147730204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e4 b9 ?? ?? ?? ?? 89 45 e0 31 d2 f7 f1 8a 1c 15 ?? ?? ?? ?? 8b 4d ec 8b 55 e0 8a 3c 11 28 df 8b 75 e8 88 3c 16 83 c2 01 8b 7d f0 39 fa 89 55 e4 74 c4 eb ca}  //weight: 1, accuracy: Low
        $x_1_2 = {31 c9 8d 55 d6 89 45 a0 89 55 9c 89 4d 98 8b 45 98 8a 0c 05 ?? ?? ?? ?? 8a 14 05 ?? ?? ?? ?? 28 ca 88 54 05 d6 83 c0 01 83 f8 14 89 45 98 75 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_S_2147730204_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.S!MTB"
        threat_id = "2147730204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 17 13 d8 89 35 ?? ?? 43 00 8b 44 24 1c 0f b7 c8 8b c1 89 1d ?? ?? 43 00 2b 05 ?? ?? 43 00 05 1a b9 00 00 89 54 24 18 a3 ?? ?? 43 00 8d 81 1b ff ff ff 03 c5 3d 2a 0e 00 00 7c 1a 6b c1 4d 2b c5 99 8b da 8b f0 8b 54 24 18 89 35 ?? ?? 43 00 89 1d ?? ?? 43 00 6b 6c 24 10 4d 81 c2 d8 e9 eb 01 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 44 24 28 1b d7 03 d8 89 1d ?? ?? 43 00 13 ea 89 2d ?? ?? 43 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AD_2147730467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AD!MTB"
        threat_id = "2147730467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 c2 20 c1 c1 07 0f be c2 33 c8 f7 d1 41 46 47 8a 16 84 d2}  //weight: 10, accuracy: High
        $x_10_2 = {80 84 1d 1e ff ff ff f6 43 83 fb 0a 72 f2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AD_2147730467_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AD!MTB"
        threat_id = "2147730467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "qljnoiinZTSr" ascii //weight: 1
        $x_1_2 = "976;43234223?==3NKK3hcb@xrpMnhgOnh" ascii //weight: 1
        $x_1_3 = {39 38 37 56 3a 39 39 56 3c 3b 3b 56 41 3f 3f 56 45 44 43 56 47 47 46 56 48 48 47 51 45 44 44 09}  //weight: 1, accuracy: High
        $x_1_4 = "544k0//OPLKRngf" ascii //weight: 1
        $x_1_5 = {28 27 27 45 2f 2d 2d 28 4e 49 47 2e 4e 49 47 2e 4e 49 47 2e 4e 49 48 2e 4e 49 48 2e 4e 49 48 2e 4e 49 48 2e 3c 39 39 2c 27 27 27 29 2f 2f 2f 4b 3a 39 39 54 23 23 23 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AD_2147730467_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AD!MTB"
        threat_id = "2147730467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8b 0e 8d 7c 07 bc 8b c2 0f b7 15 ?? ?? ?? 00 2b c3 05 ?? ?? ?? ?? 8b e8 69 ed ?? ?? ?? 00 81 c1 ?? ?? ?? ?? 89 0e 03 d5 83 c6 04 ff 4c 24 10 75 b4}  //weight: 1, accuracy: Low
        $x_1_2 = {03 ca 81 f9 ?? ?? ?? ?? 75 0d 2b d3 83 ea ?? 69 d2 ?? ?? ?? ?? 03 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AD_2147730467_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AD!MTB"
        threat_id = "2147730467"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\sat\\Section\\stood\\country\\strong\\segment\\Fell\\mostchild.pdb" ascii //weight: 1
        $x_1_2 = "if exists (select * from dbo.sysobjects where id = object_id(N'[dbo].[Prc_QueryLoadTestRequestSummary]') and OBJECTPROPERTY(id, N'IsProcedure') = 1)" ascii //weight: 1
        $x_1_3 = "ugoeodT]tns5aLnRa N umLun ]lt cerogP  n mTToR P lEstdOA]Ko]EtTF)sa Cr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_T_2147730470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.T!MTB"
        threat_id = "2147730470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff d3 83 3d ?? ?? ?? ?? ?? 75 ?? 8a 85 ?? ?? ?? ?? 8b 4d 04 34 ?? 88 41 ?? 6a 00 ff d3}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff d3 6a 00 c6 85 ?? ?? ?? ?? 6b ff d3 6a 00 c6 85 ?? ?? ?? ?? 65 ff d3 6a 00 c6 85 ?? ?? ?? ?? 72 ff d3 6a 00 c6 85 ?? ?? ?? ?? 6e ff d3 6a 00 c6 85 ?? ?? ?? ?? 65 ff d3 6a 00 c6 85 ?? ?? ?? ?? 6c ff d3 6a 00 c6 85 ?? ?? ?? ?? 33 ff d3 6a 00 c6 85 ?? ?? ?? ?? 32 ff d3 6a 00 c6 85 ?? ?? ?? ?? 2e ff d3 6a 00 c6 85 ?? ?? ?? ?? 64 ff d3 6a 00 c6 85 ?? ?? ?? ?? 6c ff d3 6a 00 c6 85 ?? ?? ?? ?? 6c ff d3 6a 00 c6 85 ?? ?? ?? ?? 00 ff d3 68 ?? ?? ?? ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_C_2147730617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.C!MTB"
        threat_id = "2147730617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 [0-48] 01 1d ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 8b 45 ?? 89 45 ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 89 55 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_U_2147730776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.U!MTB"
        threat_id = "2147730776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 0e 8a 85 ?? ?? ?? ?? 8b 4d 04 34 ?? 88 41}  //weight: 1, accuracy: Low
        $x_1_2 = {75 0f 8a 8d ?? ?? ?? ?? 8b 55 04 80 f1 ?? 88 4a}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 85 c4 a6 00 00 33 c6 85 c5 a6 00 00 30 c6 85 c6 a6 00 00 37 c6 85 c7 a6 00 00 37 c6 85 c8 a6 00 00 32 c6 85 c9 a6 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AM_2147730951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AM!MTB"
        threat_id = "2147730951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c3 89 44 24 ?? 6b c0 ?? 0f b7 f1 3b f0 74 ?? 6b 44 24 20 ?? 8b d6 2b d0 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {69 c0 82 53 00 00 89 11 89 15 ?? ?? ?? ?? 0f b7 c8 66 a3 ?? ?? ?? ?? 8d 86 ?? ?? ?? ?? 89 4c 24 ?? 8b f5 8d 14 41 8b cf 03 d0 8b 44 24 ?? 2b ca 89 54 24 ?? 99}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AN_2147731010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AN!MTB"
        threat_id = "2147731010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c6 89 44 24 20 0f b7 c1 8b cd 99 2b c8 8b 44 24 20 1b fa 83 c1 67 99 83 d7 00}  //weight: 1, accuracy: High
        $x_1_2 = {1b fa 0f a4 c8 03 c1 e1 03}  //weight: 1, accuracy: High
        $x_1_3 = {8d 85 46 40 00 00 81 c2 ?? ?? ?? ?? 66 03 f0 89 54 24 20 8b 44 24 1c 66 89 35 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_E_2147731091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.E"
        threat_id = "2147731091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\hhu\\TeamViewer_13.bjbj\\BuildTarget\\Release2017\\tv_w32dll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_V_2147731160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.V!MTB"
        threat_id = "2147731160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 30 1c 06 46 3b f7 7c 39 00 8b 0d ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 0f b7 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_V_2147731160_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.V!MTB"
        threat_id = "2147731160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 02 89 75 d8 8b 75 ec c1 2d 84 f0 49 00 07 8b 75 d8 2d 7e a9 c5 3e 89 4d dc 8d 4d d0 f7 19 8b 4d dc 2b 02}  //weight: 1, accuracy: High
        $x_1_2 = {33 55 f4 ff 45 08 8a 4d 08 33 d0 d3 ca 8b 4d ec 89 4d f4 89 16 83 c6 04 4f 75 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_V_2147731160_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.V!MTB"
        threat_id = "2147731160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c7 8d 04 45 ?? ?? ?? ?? 2b c6 0f b7 d8 8b 6c 24 ?? 8b 44 24 ?? 03 e9 8b 74 24 ?? 8b cf 13 c2 89 2d ?? ?? ?? ?? a3 ?? ?? ?? ?? 69 c3 ?? ?? ?? ?? 8b 16 81 c2 ?? ?? ?? ?? 89 16 89 15 ?? ?? ?? ?? 2b c8 0f b7 d9 8b d3 8d 72 1c 69 c6 ?? ?? ?? ?? 3d ?? ?? ?? ?? 76 0e}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c7 0f b7 e8 8b c5 2b c7 05 ?? ?? ?? ?? 0f b7 c8 89 4c 24 ?? 83 7c 24 ?? ?? 0f 83 9e 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_W_2147731178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.W!MTB"
        threat_id = "2147731178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Injected" ascii //weight: 1
        $x_1_2 = "CMD.EXE" ascii //weight: 1
        $x_1_3 = "Remote Thread ID: %u" ascii //weight: 1
        $x_1_4 = "Failed to gather information on system processes" ascii //weight: 1
        $x_1_5 = "Checking process %ls" ascii //weight: 1
        $x_1_6 = "firefox.exe" ascii //weight: 1
        $x_1_7 = "Touched A Neighbour %d with %d. Resuming a thread with ID: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ce 90 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 90 c1 ca 08 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6c 00 33 f6 30 00 66 c7 05 ?? ?? ?? ?? 6b 65 c7 05 ?? ?? ?? ?? 32 2e 64 6c c6 05 ?? ?? ?? ?? 72 c7 05 ?? ?? ?? ?? 6e 65 6c 33 66 c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 c1 ca 08 e2 e7 e9 ?? ?? 00 00 4f 00 e8 00 00 00 00 5b 8d 43 ?? bf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c2 83 c0 ?? 8b 5c 24 ?? a3 ?? ?? ?? ?? 0f b7 ef 81 c6 ?? ?? ?? ?? 8b c2 2b c5 89 33 83 c3 ?? 83 c0 ?? 83 6c 24 ?? ?? 89 5c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 89 7d 00 0f b7 2d ?? ?? ?? ?? 03 c0 2b c5 83 e8 ?? ff 4c 24 ?? 0f 85 ?? ?? ff ff 40 00 8b 6c 24 ?? 83 44 24 ?? ?? 8d 04 ?? 81 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c1 2b c6 8d 58 ?? 2b d9 81 eb ?? ?? ?? ?? 0f b7 cb 81 c7 ?? ?? ?? ?? 8b d9 03 5c 24 ?? 89 7d 00 8b 6c 24 10 83 c5 04 ff 4c 24 14 8d 9c 43 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 6c 24 10 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b de 2b df 8b 7c 24 ?? 01 1d ?? ?? ?? ?? 8b 1f 0f b7 d2 8d 44 0a ?? 8d 3c ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 81 c3 ?? ?? ?? ?? 89 18 8d 84 51 ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 04 00 00 00 6b c2 50 00 8b 4d ?? 83 c1 ?? 89 4d ?? 81 7d ?? ?? ?? ?? ?? 0f 83}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 04 00 00 00 70 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f9 8d 81 ?? ?? ?? ?? 8d 77 ?? 03 c6 89 74 24 ?? 66 89 35 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 74 24 ?? 81 c2 ?? ?? ?? ?? 0f b7 c5 89 15 ?? ?? ?? ?? 89 16 83 c6 04 8d 04 58 89 74 24 18 83 c0 ?? ff 4c 24 ?? a3 ?? ?? ?? ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 8d 7e ?? 81 c1 ?? ?? ?? ?? 03 fa 89 0d ?? ?? ?? ?? 89 08 a1 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 83 44 24 0c 04 0f b7 c8 8d 04 95 00 00 00 00 89 4c 24 10 f7 d9 2b c8 a1 ?? ?? ?? ?? 03 f9 ff 4c 24 18 8b 4c 24 10 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f9 81 ff ?? ?? ?? ?? 8d 74 10 ?? 89 35 ?? ?? ?? ?? 75 ?? 2b cd 2b ca 8d 4c 48 ?? 39 15 ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af e8 8b 74 24 ?? 8b fa 2b f9 81 c7 ?? ?? ?? ?? 8b cf 8b 3e 2b e9 81 fa ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {89 3e 8b f1 2b f0 83 c6 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 03 f0 8b 44 24 ?? 0f b7 d6 81 c7 ?? ?? ?? ?? 89 38 39 15 ?? ?? ?? ?? 8d 42 ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 2b f2 69 d2 ?? ?? ?? ?? 2b 35 ?? ?? ?? ?? 03 c6 8b 35 ?? ?? ?? ?? 01 15 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 83 44 24 ?? ?? 8b d0 6b d2 ?? 2b 15 ?? ?? ?? ?? ff 4c 24 ?? 0f b7 f2 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f1 8d 9c 3b ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 [0-32] a1 ?? ?? ?? ?? 8b b4 10 ?? ?? ?? ?? 2b dd 8b c5 83 c3 ?? 2b c1 66 89 1d ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c7 81 c6 ?? ?? ?? ?? 89 b4 11 ?? ?? ?? ?? 48 0f b7 db 8b c8 2b cb 83 c2 ?? 83 c1 ?? 81 fa ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 db 66 8b 7c 24 ?? 66 03 f8 8b 44 24 ?? 66 89 7c 24 ?? 66 89 3d ?? ?? ?? ?? 8b fa 2b fb 8b 00 83 ef ?? 89 44 24 ?? 89 3d ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 1c 05 ?? ?? ?? ?? 89 44 24 ?? a3 ?? ?? ?? ?? 89 02 8b d6 2b d3 81 c2 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 8d 14 53 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b 05 ?? ?? ?? ?? 0f b7 da 8d 44 07 ?? 8b 7d ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b c3 83 e8 ?? 81 f9 ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c2 69 d2 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 8d 84 08 ?? ?? ?? ?? 8b f0 69 f6 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 89 7d ?? 03 f2 83 c5 ?? ff 4c 24 ?? 0f b7 d6 89 6c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b df 2b d8 83 c3 ?? 8b cb 2b c8 66 89 1d ?? ?? ?? ?? 8d 7c 0f ?? 8b 44 24 ?? 81 c2 ?? ?? ?? ?? b9 ?? ?? ?? ?? 89 10 89 15 ?? ?? ?? ?? 66 39 0d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 10 69 c9 ?? ?? ?? ?? 8b 12 8b c6 2b c1 0f b7 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 8d 5c 29 ?? 8b cf 2b c8 83 c1 ?? 89 0d ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c9 8d 5f 04 03 de 89 1d ?? ?? ?? ?? 8d 04 11 83 f8 ?? 75 07 [0-16] 2b dd 2b f7 83 c3 ?? 83 c6 ?? 0f b7 ce 81 c5 ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? 8b c1 8b 5c 24 10 03 e8 8b 13 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 f1 81 c1 ?? ?? ?? ?? 2b f7 89 13 83 c6 ?? 83 c3 ?? 03 c6 89 5c 24 10 03 c8 ff 4c 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 18 0f b7 4c 24 ?? 0f b7 c2 8b f0 89 4c 24 ?? 2b 35 ?? ?? ?? ?? 8b 6d ?? 83 c6 ?? 66 89 0d ?? ?? ?? ?? 89 44 24 ?? 81 fb ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 f1 8b 0d ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 2b d0 8b 44 24 18 83 44 24 18 04 0f b7 d2 89 54 24 14 89 28 a1 ?? ?? ?? ?? 0f b7 ea 03 f5 83 6c 24 ?? ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 10 8b 2b 8b fa 2b 3d ?? ?? ?? ?? 8d 04 46 8d 84 08 ?? ?? ?? ?? 83 c7 ?? 8d 5c 08 ?? 66 89 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 04 42 8d 84 08 ?? ?? ?? ?? 8b d8 2b d9 88 15 ?? ?? ?? ?? 03 d3 8b d8 2b de 03 cb 8b 5c 24 10 81 c5 ?? ?? ?? ?? 89 2b 0f b6 1d [0-21] 88 15 ?? ?? ?? ?? 8d 14 42 03 d0 03 d1 8d 94 12 ?? ?? ?? ?? 83 44 24 10 04 ff 4c 24 14 0f b7 c7 8d 44 08 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 14 8d 04 0a 03 df 83 f8 ?? 75 0f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 00 8d 59 ?? 0f af cb 81 c2 ?? ?? ?? ?? 89 55 00 83 c5 04 89 1d ?? ?? ?? ?? 2b 4c 24 18 83 6c 24 10 01 75 bd}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 0c 03 83 f9 ?? 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b 6c 24 ?? 0f b7 cf 2b f1 81 c6 ?? ?? ?? ?? 8b 5d 00 81 fa ?? ?? ?? ?? 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 44 24 10 04 81 c3 ?? ?? ?? ?? 0f af d0 89 5d 00 bd ?? ?? ff ff 0f b7 cf 69 d2 ?? ?? ?? ?? 2b ea 8b c5 2b c1 2b c2 83 6c 24 ?? ?? 8b 15 ?? ?? ?? ?? 75 92}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_2147731259_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!MTB"
        threat_id = "2147731259"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 18 8b 54 24 30 03 d1 89 54 24 24 8b 30 69 c5 ?? ?? ?? ?? 89 74 24 ?? 8d b7 ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? 03 c1 8d 34 70 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 24 18 8d 47 ?? 8b 54 24 ?? 03 c6 81 c2 ?? ?? ?? ?? 0f b7 c0 89 54 24 ?? 89 55 00 89 15 ?? ?? ?? ?? 8d 14 75 ?? ?? ?? ?? 0f b7 e8 03 d5 89 44 24 ?? 03 d6 39 4c 24 ?? 76}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 0c 8b 7c 24 10 83 c1 ?? 03 cb 0f af d8 89 4c 24 ?? 66 89 0d ?? ?? ?? ?? 8b c8 8b 3f 0f af ce 2b ca 0f b7 c9 2b d9 89 1d ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 0c 8b 44 24 10 81 c7 ?? ?? ?? ?? 83 44 24 ?? ?? be ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 89 38 8b 44 24 ?? 0f b7 f8 81 ef ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_A_2147731274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.A"
        threat_id = "2147731274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 ce 03 ca 81 f9 9d 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {33 d2 8b c3 2b c6 05 bc 2b 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {81 c2 48 59 a3 01 8d 78 a7 89 0d ?? ?? ?? ?? 89 55 00 be 06 00 00 00 81 ff 38 1d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AO_2147731299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AO!MTB"
        threat_id = "2147731299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 13 8d 5b 04 66 89 3d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 c0 ?? 0f b7 f0 8d 81 ?? ?? ?? ?? 33 c9 2b c5 8b e8 8b c6 1b 0d ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 0f b7 cf 83 c1 ?? 89 53}  //weight: 1, accuracy: Low
        $x_1_2 = {03 c8 89 15 ?? ?? ?? ?? b8 ?? ?? ?? ?? 2b c6 66 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 c0 2b c5 2b c6 2d ?? ?? ?? ?? ff 4c 24 ?? 66 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {2b c8 1b f2 66 89 4d ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_4 = {6b c0 03 99 2b 45 ?? 1b 55 ?? 66 89 45 ?? 8b 15 ?? ?? ?? ?? 83 c2 ?? a1 ?? ?? ?? ?? 83 d0 ?? 8b 0d ?? ?? ?? ?? 33 f6 03 d1 13 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_AB_2147731379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AB!MTB"
        threat_id = "2147731379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 2b d6 83 ea 06 0f b7 fa 0f b7 c9 81 c3 ?? ?? ?? ?? ba 06 00 00 00 2b d1 89 5d 00 03 c2 83 c5 04 ff 4c 24 10 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 8b 00 a3 ?? ?? ?? ?? 0f b7 df b8 a3 ff ff ff 2b c6 2b c3 03 d0 89 7c 24 14 81 f9 ?? ?? ?? ?? 75 ?? 83 3d ?? ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_3 = {13 d3 89 54 24 18 2b 0d ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 5d 00 0f b7 d7 2b c2 83 e9 06 83 e8 09 66 89 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 54 24 18 05 10 00 a1 ?? ?? ?? ?? 8b 54 24 18 05 ?? ?? ?? ?? 89 02 0f b7 d5 a3 ?? ?? ?? ?? 8d 43 08 89 44 24 10 39 15 ?? ?? ?? ?? 72 [0-32] 83 44 24 18 04 83 6c 24 1c 01 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_AP_2147731536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AP!MTB"
        threat_id = "2147731536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 4c 24 10 0f b6 f2 2b f0 81 c6 ?? ?? ?? ?? 3b f1 8a 4c 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 5c 24 10 0f b6 fa 8b f0 2b f7 03 dd 83 c6 ?? 33 ff}  //weight: 1, accuracy: Low
        $x_1_3 = {0f a4 f7 01 2b c8 81 e9 ?? ?? ?? ?? 03 f6 33 db 03 f1 13 fb 89 35 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AQ_2147731630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AQ!MTB"
        threat_id = "2147731630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 83 c0 ?? 99 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 54 24 ?? 69 c9 ?? ?? ?? ?? 03 ce 66 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b c8 69 c0 ?? ?? ?? ?? 69 c9 ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 2a 83 c2 04 ff 4c 24 ?? 8d 3c 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AR_2147731656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AR!MTB"
        threat_id = "2147731656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 39 7c 24 18 72 [0-4] 02 cd 05 54 a0 09 01 83 c6 04 89 02 [0-47] 81 fe ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AR_2147731656_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AR!MTB"
        threat_id = "2147731656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b de 89 54 24 ?? 81 c3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 89 10 50 00 6b 7c 24 ?? ?? 8b 35 ?? ?? ?? ?? 83 44 24 ?? ?? f7 de 2b f7 8b 7c 24 ?? 66 03 de}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 04 c9 0f b7 d1 2b 44 24 ?? 81 c6 ?? ?? ?? ?? 66 03 f8 89 74 24 ?? 8b 44 24 ?? 89 35 ?? ?? ?? ?? 89 54 24 ?? 66 89 3d ?? ?? ?? ?? 89 30 8b f3 81 c6 ?? ?? ?? ?? 8b c5 83 d0 ?? 89 44 24 ?? 8b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_AR_2147731656_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AR!MTB"
        threat_id = "2147731656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 c5 ec 3c 06 01 89 28}  //weight: 10, accuracy: High
        $x_1_2 = {2b d3 8b da 83 44 24 10 04 83 6c 24 14 01 0f 85 3f 00 69 d2}  //weight: 1, accuracy: Low
        $x_1_3 = {83 44 24 1c 04 8b 54 24 20 03 f9 83 6c 24 30 01 8b 4c 24 10 0f 85 3f 00 69 4c 24}  //weight: 1, accuracy: Low
        $x_10_4 = {81 c3 48 00 03 01 89 5c 24 14 89 19}  //weight: 10, accuracy: High
        $x_10_5 = {30 35 88 27 04 01 [0-79] 89 02}  //weight: 10, accuracy: Low
        $x_1_6 = {83 44 24 10 04 81 c2 ?? ?? ?? ?? ff 4c 24 1c 89 0d ?? ?? ?? ?? 0f 85 3f 00 69 c8}  //weight: 1, accuracy: Low
        $x_10_7 = {05 10 f9 07 01 [0-10] 89 06}  //weight: 10, accuracy: Low
        $x_1_8 = {2b 44 24 10 2d d0 6c 01 00 89 44 24 10 8b 44 24 14 8b 00}  //weight: 1, accuracy: High
        $x_11_9 = {8d 4c 03 01 [0-10] 8b 0a 69 f6 [0-47] 81 c1 54 31 09 01 [0-15] 89 0a [0-10] 83 c2 04 [0-31] 75}  //weight: 11, accuracy: Low
        $x_1_10 = {b8 59 00 00 00 2b 05 ?? ?? ?? ?? 83 f0 0d 89 05 00 81 2d ?? ?? ?? ?? 01 00 00 00 81 3d 02 00 00 00 00 75 d6 e9}  //weight: 1, accuracy: Low
        $x_10_11 = "!This -7Afram cannot be run in DOS mode." ascii //weight: 10
        $x_1_12 = "X:\\hemiterata\\confervaceous\\spireward\\wordsmith.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_AS_2147731695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AS!MTB"
        threat_id = "2147731695"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 0f af 0d ?? ?? ?? ?? e8 ?? ?? ff ff 05 ?? ?? ?? ?? 03 c1 6a 00 a3}  //weight: 1, accuracy: Low
        $x_1_2 = {0f be 1c 1e e8 ?? ?? ff ff 32 c3 8b 5d ?? 88 04 1e 46}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AT_2147731696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AT!MTB"
        threat_id = "2147731696"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f9 03 f7 8b 7c 24 ?? 8b ce 69 f6 ?? ?? ?? ?? 2b c8 03 ca 0f b7 d1 03 f2 8b ce 2b 0d ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 89 1f 83 e9 ?? 83 c7 ?? 83 6c 24 ?? ?? 0f b7 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AU_2147731734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AU!MTB"
        threat_id = "2147731734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 81 c7 ?? ?? ?? ?? 0f b7 d1 8b 00 89 44 24 ?? 0f b6 c3 89 44 24 ?? 03 c2 03 f8 8d 3c 7a 03 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 14 8b 7c 24 10 81 c7 ?? ?? ?? ?? 89 7c 24 ?? 89 38 8b c6 05 ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 83 d5 ?? 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AV_2147731809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AV!MTB"
        threat_id = "2147731809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 2b da 8b 15 ?? ?? ?? ?? 1b d6 01 1d ?? ?? ?? ?? 8b 75 ?? 0f b7 c9 11 15 ?? ?? ?? ?? 8b 54 24 ?? 8d 04 42 8d 84 08 ?? ?? ?? ?? 0f af f8 03 f9 30 00 8d 41 ?? 81 c6 ?? ?? ?? ?? 8b c8 2b 0d ?? ?? ?? ?? 89 75 00 83 c5 04 ff 4c 24 14}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c8 8d 54 09 ?? 81 fa ?? ?? ?? ?? 7c ?? 66 83 c0 ?? 66 a3 ?? ?? ?? ?? 8b 7c 24 ?? 8b 4c 24 ?? 03 fe 13 cd 81 7c 24 ?? ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 0b 20 00 8b c6 2b 05 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0b 05 ?? ?? ?? ?? 83 c3 04 ff 4c 24 ?? 66 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_AW_2147731889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AW!MTB"
        threat_id = "2147731889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c1 6b f8 ?? 0f b7 c3 03 c5 66 03 3d ?? ?? ?? ?? 66 89 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c7 6b d0 ?? 0f b7 cb 03 d1 89 54 24 ?? 89 15 ?? ?? ?? ?? 99 2b f0 a1 ?? ?? ?? ?? 1b c2 81 c6 ?? ?? ?? ?? 83 d0 ?? 89 44 24 ?? 8b c1}  //weight: 1, accuracy: Low
        $x_1_3 = {03 d8 8a 0d ?? ?? ?? ?? 8b 54 24 ?? 89 2e 8d 43 ?? 83 c6 04 66 a3 ?? ?? ?? ?? 83 6c 24 ?? ?? 89 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AX_2147731935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AX!MTB"
        threat_id = "2147731935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 2f 8d 41 ?? 0f b7 c8 b8 ?? ?? ?? ?? 69 f1 ?? ?? ?? ?? 03 f2 f7 e6 c1 ea}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c3 83 c6 ?? 2b c1 03 f0 6b c1 ?? 83 c6 ?? 81 c5 ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 89 2f 03 c6 69 f0 ?? ?? ?? ?? b8 ?? ?? ?? ?? 03 f1 f7 e6 c1 ea}  //weight: 2, accuracy: Low
        $x_1_3 = {8b c3 83 c6 ?? 2b c1 03 f0 2b 0d ?? ?? ?? ?? 83 c7 04 8b 15 ?? ?? ?? ?? 83 c1 fe 03 ce}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AX_2147731935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AX!MTB"
        threat_id = "2147731935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c7 2b c2 8d 54 18 e1 8d 04 2a 8d 7c 07 49 89 3d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 3b c6 72 ?? 8a 44 24 14 2b f5 03 de 28 05 ?? ?? ?? ?? 8d 74 2b ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 18 8b 0d ?? ?? ?? ?? 83 44 24 10 ?? 81 7c 24 10 ?? ?? ?? ?? 89 08 8d 44 1f 07 0f b7 f8 0f 82}  //weight: 2, accuracy: Low
        $x_1_2 = {29 7c 24 18 c7 44 24 14 ?? ?? ?? ?? 89 7c 24 10 ff 4c 24 14 8b 74 24 14 8b 6c 24 10 8b 5c 24 18 8a 1c 2b 2b f1 83 ee ?? ff 44 24 10 89 35 ?? ?? ?? ?? 2b f1 88 5d 00 8d 1c 10 83 ee ?? 03 cb 83 7c 24 14 ?? 75 ca}  //weight: 1, accuracy: Low
        $x_2_3 = {8b c8 8b c2 8b 54 24 10 03 ca 89 4c 24 0c 8b 4c 24 18 83 d0 ?? ff 4c 24 1c 89 44 24 14 0f b7 05 ?? ?? ?? ?? 3b c2 8b 44 24 0c 0f 87 ?? ?? ?? ?? 8d 4a ?? 66 89 35 ?? ?? ?? ?? 03 ce 8d 72 34 03 f1 89 35 ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
        $x_1_4 = {57 88 01 41 89 4c 24 1c e8 ?? ?? ?? ?? 8b f8 0f b7 05 ?? ?? ?? ?? 03 fe 83 d2 ?? 3b c6 72 ?? a1 ?? ?? ?? ?? 83 c0 ?? 03 c6 66 83 c3 ?? a3 ?? ?? ?? ?? 8d 34 85 e8 ff ff ff 89 35 ?? ?? ?? ?? 8b 44 24 18 8b 4c 24 14 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_AY_2147731963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AY!MTB"
        threat_id = "2147731963"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 ea f7 ed c1 fa ?? 8b da c1 eb ?? 03 da 30 00 0f b6 c1 83 c0 ?? 0f b7 f7 03 35 ?? ?? ?? ?? 03 c5 99 89 44 24 ?? a3 ?? ?? ?? ?? 8b c2}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c5 83 c0 ?? 99 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 44 24 ?? 81 c6 ?? ?? ?? ?? 8b 6c 24 ?? 2b c3 89 35 ?? ?? ?? ?? 8d 14 40 89 75 00 c1 e2 05 83 c5 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AZ_2147733306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AZ!MTB"
        threat_id = "2147733306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 2b d6 a3 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 ea ba ?? ?? ?? ?? 8b 8c 18 ?? ?? ?? ?? 0f b7}  //weight: 1, accuracy: Low
        $x_2_2 = {0f b7 c7 8b d6 8b 35 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 6b c0 ?? bf ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 89 8c 1e ?? ?? ?? ?? 83 c3 04 2b d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BA_2147733612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BA!MTB"
        threat_id = "2147733612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 0f b7 15 ?? ?? ?? ?? 2b d0 66 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8 2e 8b c8 33 f6 2b 0d ?? ?? ?? ?? 1b 35 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 99 03 c1 13 d6 66 a3 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 ?? 8b 44 24 04 f7 e1 c2 ?? ?? 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BB_2147733652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BB!MTB"
        threat_id = "2147733652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 81 c5 ?? ?? ?? ?? 0f b7 f0 89 2d ?? ?? ?? ?? 89 29 8d 6e ?? 8d 4d ?? 03 ce}  //weight: 1, accuracy: Low
        $x_1_2 = {69 4c 24 20 ?? ?? ?? ?? 83 44 24 10 ?? 8d 0c 69 8b 2d ?? ?? ?? ?? 2b ce ff 4c 24 14 8b 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BC_2147733714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BC!MTB"
        threat_id = "2147733714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 65 78 65 00 40 47 65 74 46 69 72 73 74 56 69 63 65 43 69 74 79 40 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BC_2147733714_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BC!MTB"
        threat_id = "2147733714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Born" ascii //weight: 1
        $x_1_2 = "Fitsecond" ascii //weight: 1
        $x_1_3 = "Pastput" ascii //weight: 1
        $x_1_4 = {c1 e0 06 33 c9 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 13 d1 [0-17] 83 c0 62 2b 05 ?? ?? ?? ?? 33 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BC_2147733714_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BC!MTB"
        threat_id = "2147733714"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d0 0f b7 0d ?? ?? ?? ?? 03 d1 0f b7 05 ?? ?? ?? ?? 03 c2 66 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? a1 ?? ?? ?? ?? 89 82}  //weight: 1, accuracy: Low
        $x_1_2 = {2b ca 88 0d ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 0f b6 0d 20 00 0f b7 05 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 03 c1 2b 05 ?? ?? ?? ?? a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_B_2147733772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.B"
        threat_id = "2147733772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\3\\.41\\.34DLOperatingSyk3456bb" ascii //weight: 1
        $x_1_2 = "Ln03q4Windows Server" wide //weight: 1
        $x_1_3 = "Direct3D 9 Runtime" wide //weight: 1
        $x_1_4 = "D3D9.dll" wide //weight: 1
        $x_1_5 = {bf 4b 08 00 00 8d 35 ?? ?? ?? ?? 89 66 18 89 6e 40 89 5e 20 85 c0 74 05 e8 ?? ?? ff ff c2 0c 00 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ursnif_BD_2147733838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BD!MTB"
        threat_id = "2147733838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce 6b c9 ?? 2b cf 83 f8 ?? a1 ?? ?? ?? ?? 89 0d}  //weight: 1, accuracy: Low
        $x_2_2 = {0f b7 54 24 ?? 39 15 ?? ?? ?? ?? 73 ?? 89 3d ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 94 18 ?? ?? ?? ?? 8b 02 30 00 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BD_2147733838_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BD!MTB"
        threat_id = "2147733838"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c5 03 f7 83 e8 52 0f b6 c0 0f af c7 69 d0 7f a4 00 00 b0 57 8a ca c0 e1 04 02 ca 2a c1 0f b6 c8 8d 04 11 69 c0 13 14 58 1e 2b d0 8b 44 24 10 05 7c 25 39 03 8d 14 50 a1 ?? ?? ?? ?? 03 c7 03 d2 69 f8 7f a4 00 00 2b d1 0f b7 c6 8d 4a 9f 2b d6 81 ef 7b 36 03 00 88 0d ?? ?? ?? ?? 0f af f8 8d 43 ae 03 c2 0f b7 c0 8b d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BE_2147733888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BE!MTB"
        threat_id = "2147733888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b c2 0f b7 0d ?? ?? ?? ?? 2b c8 66 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b d0 0f b7 0d ?? ?? ?? ?? 03 d1}  //weight: 2, accuracy: Low
        $x_1_2 = {03 ca 88 0d ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BE_2147733888_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BE!MTB"
        threat_id = "2147733888"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c0 2b f0 8d 47 b5 83 c6 4a 0f af 35 ?? ?? ?? ?? 2b f1 0f b7 c9 03 c1 0f b7 c0 83 c0 07 03 c6 8d 7e 51 69 d0 89 1c 00 00 8d 81 04 d0 ff ff 2b d6 03 c2 0f b7 c8 0f af ca 8d 04 32 03 c0 2b cf 2b c1 05 5c 96 ff ff 05 cc cb ff ff 03 c2 8d 34 47 0f b6 05 ?? ?? ?? ?? 03 f1 0f b7 d6 81 ea 55 70 00 00 0f b7 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BF_2147734436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BF!MTB"
        threat_id = "2147734436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 4e 0f b6 15 ?? ?? ?? ?? 2b ca 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 88 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 0f af 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 6b 05}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 8b 55 ?? 2b d0 8b 45 ?? 1b c1 8b 4d ?? 33 f6 2b ca 1b f0 89 4d ?? 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 8b 55 ?? 81 ea ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 03 55 fc 03 55 fc 89 55 fc 6b 45 fc ?? 0f b6 0d ?? ?? ?? ?? 03 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BH_2147734567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BH!MTB"
        threat_id = "2147734567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 cb 03 d1 8d 0c 37 81 f9 15 00 83 c6 ?? 03 c8 03 ca 03 f1 8b 4c 24 ?? 0f b6 c9 81 f9 30 00 83 c2 ?? 8d 2c 06 8b fb 03 ea 0f af 3d ?? ?? ?? ?? 8b 54 24 ?? 2b 3d ?? ?? ?? ?? 8b 12}  //weight: 1, accuracy: Low
        $x_1_2 = {03 de 89 54 24 ?? 89 15 ?? ?? ?? ?? be 04 00 00 00 39 74 ?? ?? 89 11 8b 4c 24 ?? 0f b6 d1 0f b6 cb 0f 42 d1 89 1d ?? ?? ?? ?? 01 74 24 ?? 8a ca 0f b7 d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BI_2147734820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BI!MTB"
        threat_id = "2147734820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fe 03 eb 2b f8 81 fd 20 00 8b ea 2b 2d ?? ?? ?? ?? 2b f3 3d ?? ?? ?? ?? 8d 7c 2f 1e 8b 6c 24 10 8b 6d 00 89 3d ?? ?? ?? ?? 89 35}  //weight: 1, accuracy: Low
        $x_1_2 = {2b cf 83 e9 4c 8b f9 89 3d ?? ?? ?? ?? b9 05 00 00 00 eb 30 00 8b 74 24 10 81 c5 ?? ?? ?? ?? 89 2e 8b 35 20 00 2b cf 83 e9 4c 89 0d 20 00 83 44 24 10 04 8b ca 2b cb 83 e9 4c 83 6c 24 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SS_2147734991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SS!MTB"
        threat_id = "2147734991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 11 8b 4c 24 0c 89 54 24 10 8b 54 24 18 83 c2 3d 03 d1 89 15 ?? ?? ?? ?? 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4b 08 03 c8 66 89 0d ?? ?? ?? ?? 8b 4c 24 0c 3b 7c 24 18 8b 54 24 14 0f 42 3d ?? ?? ?? ?? 83 c1 3d 03 c1 8b 4c 24 10 81 c1 ?? ?? ?? ?? 0f b7 c0 89 0a 89 4c 24 10 89 0d ?? ?? ?? ?? 8d 50 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SR_2147735010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SR!MTB"
        threat_id = "2147735010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a d0 81 ff d0 eb 6c 2d 75 19 00 a0 ?? ?? ?? ?? 8b 75 00 2a c2 02 05}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c6 ac 43 d5 01 0f b6 ca 81 c1 8a 1d 00 00 0f b7 c3 89 75 00 03 c1 8b 0d ?? ?? ?? ?? 83 c5 04 ff 4c 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SR_2147735010_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SR!MTB"
        threat_id = "2147735010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8b f2 c1 e0 02 2b f0 2b f7 81 ee 49 0d 00 00 89 35}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8c 28 c7 e8 ff ff 0f b7 05 ?? ?? ?? ?? 3b c7 76 0e a1 ?? ?? ?? ?? 0f af c6 66 a3 ?? ?? ?? ?? 8d 04 13 81 c1 60 e7 ae 01 03 f0 89 0d ?? ?? ?? ?? a1 d4 33 44 00 89 35 ?? ?? ?? ?? 89 8c 28 c7 e8 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SQ_2147735016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SQ!MTB"
        threat_id = "2147735016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8d 6a fa 03 eb 03 c1 89 6c 24 2c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 6c 24 14 8b 54 24 24 81 c5 cc 9d e5 01 66 39 74 24 12 89 28 0f b6 c3 0f b6 d2 0f 42 d0 89 1d ?? ?? ?? ?? 83 44 24 18 04 0f b7 c7 8d 79 fa 03 f8 89 6c 24 14 ff 4c 24 28 89 2d ?? ?? ?? ?? 89 54 24 24 88 15 ?? ?? ?? ?? 74 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SP_2147735044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SP!MTB"
        threat_id = "2147735044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 14 2b c2 8d 4c 01 1f a1 ?? ?? ?? ?? 8d bc 30 45 e9 ff ff 0f b6 c3 8d 84 10 01 f6 ff ff 89 0d ?? ?? ?? ?? 8b 37 89 44 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 1c 0f b6 c3 81 c6 64 db b1 01 8d 44 08 f7 89 35 ?? ?? ?? ?? 89 37 0f b6 0d ?? ?? ?? ?? 8d 5c 08 f7 0f b6 05 ?? ?? ?? ?? 89 5c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BK_2147735088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BK!MTB"
        threat_id = "2147735088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 10 8b 2f 2b c8 83 e9 ?? 8b f1 2b f0 83 ee 5f 66 89 35 ?? ?? ?? ?? 66 89 1d ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 10 81 c5 ?? ?? ?? ?? 0f b7 f6 89 29 89 2d ?? ?? ?? ?? 39 35 ?? ?? ?? ?? 73 10 00 83 44 24 10 04 0f b7 fb 8b ce 2b cf ff 4c 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BK_2147735088_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BK!MTB"
        threat_id = "2147735088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4d e0 89 4d d4 8b 55 b8 69 d2 86 5e e1 04 89 55 f4 8b 45 e4 03 45 d8 89 45 cc 8b 4d d0 2b 4d b4 89 4d f8 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea 89 55 fc 8b 45 b4 69 c0 53 a1 fd 00 89 45 f0 8b 4d cc 69 c9 c9 6b 5d 08 89 4d bc 8b 55 ec 2b 55 e0 89 55 e8 8b 45 dc 05 0b 39 6d 05 89 45 d0 8b 4d f0 2b 4d bc 89 4d b4 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {53 00 6a 00 73 00 6c 00 57 00 76 00 41 00 65 00 71 00 61 00 00 00 00 00 55 44 6a 57 44 53 4e 5a 74 5a 00 00 75 00 4f 00 69 00 51 00 48 00 41 00 72 00 51 00 74 00 75 00 00 00 00 00 63 3a 00 00 52 44 47 6f 6a 68 54 48 4d 57}  //weight: 1, accuracy: High
        $x_1_4 = {5a 00 20 00 64 00 6d 00 72 00 43 00 6d 00 6f 00 53 00 78 00 00 00 00 00 4d 00 78 00 73 00 71 00 6f 00 50 00 4f 00 78 00 47 00 54 00 00 00 00 00 56 69 6f 44 49 58 74 42 79 51 00 00 66 00 73 00 6b 00 66 00 5a 00 20 00 43}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 6f 00 64 00 53 00 62 00 4a 00 00 00 00 00 47 59 7a 43 63 42 46 4e 62 47 00 00 64 00 4c 00 64 00 4e 00 70 00 46 00 6b 00 6f 00 57 00 44 00 00 00 00 00 67 00 59 00 70 00 6b 00 5a 00 6c 00 6e 00 44 00 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BL_2147735090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BL!MTB"
        threat_id = "2147735090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 fa 8b d8 2b d9 03 fe 83 eb 03 81 ff ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 24 10 8b c2 2b c1 81 c6 ?? ?? ?? ?? 83 c0 ?? 89 75 00 83 c5 ?? ff 4c 24 14 8d 4c 00 ?? c7 05 ?? ?? ?? ?? 00 00 00 00 0f b7 d1 89 6c 24 10 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SO_2147735115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SO!MTB"
        threat_id = "2147735115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 10 81 c7 20 fe 0f 01 8d 54 00 3d 89 3d ?? ?? ?? ?? 89 bc 31 eb f0 ff ff 0f b7 ca 0f b6 15 ?? ?? ?? ?? 83 ea 02 74 3b 83 ea 5c 74 2a 83 ea 17 74 14}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 54 07 ca 8b 3d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b bc 37 eb f0 ff ff 0f b7 f1 03 de 8d 04 58 0f b6 1d ?? ?? ?? ?? 8d 84 28 a7 ad ff ff 0f b6 2d ?? ?? ?? ?? 0f af eb 81 fd 6e 81 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SN_2147735116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SN!MTB"
        threat_id = "2147735116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 0f b7 08 8b 45 f8 8b 40 1c 8d 04 88 8b 04 18 03 c3 ff d0 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SN_2147735116_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SN!MTB"
        threat_id = "2147735116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 0f b6 05 ?? ?? ?? ?? 2b d1 83 c0 e1 83 ea 44 03 05 ?? ?? ?? ?? 03 c3 89 15 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 4d fd fe ff 8b b4 3b c3 e0 ff ff 03 c2 a3 ?? ?? ?? ?? 81 fd f1 72 8e 35 75 0d 0f b6 c2 6b c0 48 02 c1 a2}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c6 68 02 34 01 89 35 ?? ?? ?? ?? 89 b4 3b c3 e0 ff ff 83 c7 04 8b 35 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 6b d6 48 03 d1 89 15 ?? ?? ?? ?? 81 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BM_2147735129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BM!MTB"
        threat_id = "2147735129"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 8b 35 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 2b d1 0f b7 cb 03 ce 81 f9 ?? ?? ?? ?? 75 30 00 0f b7 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 0f b7 cd 03 ca 89 0d ?? ?? ?? ?? 8b 0f}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b7 c5 89 0f 0f b7 fb 2b c7 89 0d ?? ?? ?? ?? 83 e8 ?? 99 8b c8 8b f2 8b c7 8b 7c 24 10 99 2b c1 1b d6 83 c0 ?? a3 ?? ?? ?? ?? 83 d2 00 83 c7 04 83 6c 24 14 ?? 89 15 ?? ?? ?? ?? 89 7c 24 10 74 0a a1 ?? ?? ?? ?? e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SM_2147735139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SM!MTB"
        threat_id = "2147735139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 ca 8d 8c 0f de d4 ff ff 89 0d ?? ?? ?? ?? 05 c0 24 60 01 a3 ?? ?? ?? ?? 89 06 8b 3d ?? ?? ?? ?? 8d 42 b2 66 39 15}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c2 2d d1 57 00 00 66 a3 ?? ?? ?? ?? 8b c7 2b c1 83 c0 19 2b ca a3 ?? ?? ?? ?? a1 44 96 46 00 49 8d b4 28 2e f5 ff ff 8b 06 49 83 eb 04 74 33}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AA_2147735389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AA!MTB"
        threat_id = "2147735389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Towardyear\\Shouldon\\sureSummer\\Createsingle\\allowtoBy.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AA_2147735389_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AA!MTB"
        threat_id = "2147735389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 03 ee 13 f9 81 7c 24 18 ?? ?? ?? ?? 8b 0d 68 74 57 00 8d b4 11 cc f4 ff ff 89 2d 40 80 56 00 89 3d 44 80 56 00 8b 0e 75 10 2b 05 04 80 56 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 24 20 8d 83 ?? ?? ?? ?? 03 c1 89 44 24 1c 0f b6 c6 8b 3f 66 6b c8 15 8b 44 24 24 2b 44 24 1c 83 c0 41 03 c6 66 03 4c 24 12 66 89 0d ?? ?? ?? ?? 89 44 24 18 81 fb 1b 69 81 25 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 44 30 04 8a d0 80 c2 04 66 03 fd 8b 2b 02 ca 66 89 3d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 ?? 83 7c 24 24 00 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 44 28 f7 8b dd 81 c3 17 ff ff ff 83 d7 ff 66 a3 00 80 56 00 81 c1 30 ce 16 01 89 0d 18 8c 57 00 89 0e a1 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 74 24 20 81 c7 ?? ?? ?? ?? 0f b6 d2 89 54 24 20 8b 54 24 14 83 7c 24 20 fe 0f b6 d2 89 54 24 14 0f b6 c0 0f 42 d0 89 3e 89 54 24 14 83 c6 04 8a 35 ?? ?? ?? ?? 0f b6 c6 48 88 15 ?? ?? ?? ?? ff 4c 24 28}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 4c 10 a0 66 01 0d ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 8d 44 30 04 89 2b 8b c8 66 39 3d ?? ?? ?? ?? 76 0f 0f b7 cf 2b c8 83 c1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_BN_2147735543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BN!MTB"
        threat_id = "2147735543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 f3 8d 14 76 03 d0 2b ca 1b ff 8b d5 2b 15 ?? ?? ?? ?? 83 ea 09 66 89 15 ?? ?? ?? ?? 8b 54 24 10 8b 12 89 15 ?? ?? ?? ?? 8b d1 2b d3 83 ea 09 66 89 15 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 0c 06 03 e9 a1 ?? ?? ?? ?? 8b 54 24 10 05 ?? ?? ?? ?? 89 02 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 2d ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
        $x_1_3 = {83 44 24 10 04 2b c6 2d ?? ?? ?? ?? ff 4c 24 14 99 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BO_2147735544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BO!MTB"
        threat_id = "2147735544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0e 8b d5 2b d0 03 15 ?? ?? ?? ?? 8b c3 8d bc 12 ?? ?? ?? ?? 0f b7 d7 2b c2 81 c1 ?? ?? ?? ?? 83 e8 ?? 89 0e 99 83 c6 04 ff 4c 24 10 66 89 3d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BO_2147735544_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BO!MTB"
        threat_id = "2147735544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af d1 8d 84 38 1c 04 ff ff 8b c8 6b c9 0b 03 d6 2b cf a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 03 f1 8b 0d ?? ?? ?? ?? 8b de c1 e3 04 2b 5c 24 10 03 cb 83 7c 24 10 06}  //weight: 1, accuracy: Low
        $x_1_2 = "Studyobserve.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BP_2147735590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BP!MTB"
        threat_id = "2147735590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 55 2b d7 66 01 15 ?? ?? ?? ?? 8b 44 24 18 81 c6 ?? ?? ?? ?? 83 d3 00 0f a4 f3 01 99 03 f6 2b f0 a1 ?? ?? ?? ?? 1b da 8b 54 24 10 03 f1 13 dd 05 ?? ?? ?? ?? 89 02 0f b7 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 04 36 0f b7 f8 0f b7 05 ?? ?? ?? ?? 2b c2 89 44 24 14 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6b d2 55 2b c2 99 2b f0 1b da 83 44 24 10 04 ff 4c 24 1c 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BQ_2147735694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BQ!MTB"
        threat_id = "2147735694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 28 0f b6 54 28 ?? 88 4c 24 ?? 0f b6 4c 28 ?? 8a 44 28 ?? 88 54 24 ?? 8d 54 24 ?? 52 8d 74 24 ?? 8d 7c 24 ?? 88 4c 24 ?? e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 4c 24 ?? 8b 44 24 ?? 0f b6 54 24 ?? 88 0c 03 0f b6 4c 24 ?? 43 88 14 03 8b 54 24 ?? 43 88 0c 03 83 c5 04 83 c4 04 43 3b 2a 72}  //weight: 1, accuracy: Low
        $x_1_3 = {89 4c 24 04 83 44 24 04 06 8b 4c 24 0c 8a d0 d2 e2 80 e2 c0 08 55 00 [0-128] 8a c8 80 e1 fc c0 e1 04 08 0f 8b 4c 24 04 d2 e0 5d 24 c0 08 06 59 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GU_2147735724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GU"
        threat_id = "2147735724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wKLEHL@K#nwknb" wide //weight: 1
        $x_1_2 = "\\GWHWERW.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BR_2147735809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BR!MTB"
        threat_id = "2147735809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 0f b7 de 2b cf 8d b9 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 cb 89 3d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 0c 83 c2 ?? 8b 5c 24 10 0f b7 c9 2b c8 03 d1 8b 1b 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 10 8d 34 55 ?? 00 00 00 81 c3 ?? ?? ?? ?? 0f b7 c6 89 1d ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? 89 19 8b 1d ?? ?? ?? ?? 3b d8 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BS_2147735960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BS!MTB"
        threat_id = "2147735960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e3 08 81 e3 c1 ca af 10 81 ?? ?? ?? c4 4b 3e 5f 81 ?? ?? ?? c4 4b 3e 5f b8 6c 16 71 10 81 ?? ?? ?? 86 7d 8f 5c 25 6d 07 da 48 81 ?? ?? ?? 86 7d 8f 5c c1 e8 0a 81 ?? ?? ?? d4 e9 48 5e 81 ?? ?? ?? d4 e9 48 5e 8b}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e3 08 81 e3 c1 ca af 10 81 ?? ?? c4 4b 3e 5f 81 ?? ?? c4 4b 3e 5f b8 6c 16 71 10 81 ?? ?? 86 7d 8f 5c 25 6d 07 da 48 81 ?? ?? 86 7d 8f 5c c1 e8 0a 81 ?? ?? d4 e9 48 5e 81 ?? ?? d4 e9 48 5e 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {35 1a 8c b1 43 bb cc 34 c4 5b 81 [0-3] 92 1e cb 19 c1 e3 1f 81 [0-3] 46 ca 49 4b 81 [0-3] d8 e8 14 65 81 f3 a0 7c c9 20 8b [0-3] a3 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_4 = {35 1a 8c b1 43 bb cc 34 c4 5b 81 ?? ?? 92 1e cb 19 c1 e3 1f 81 ?? ?? 46 ca 49 4b 81 ?? ?? d8 e8 14 65 81 f3 a0 7c c9 20 8b ?? ?? 89 15 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 75 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 31 57 8b 79 04 89 75 d0 c7 45 ec a2 a2 f0 be 81 45 ec 7e 94 fe 07 8b 45 ec 89 45 fc c7 45 f4 fe d6 c9 a1 25 a2 ec d5 6e 81 45 f4 98 cc 38 33 c1 e3 09 81 45 f4 6a 5c fd 2a c1 eb 13 81 45 f4 b9 79 37 9e}  //weight: 1, accuracy: High
        $x_1_6 = {8b 45 f4 89 45 b4 c7 45 e8 24 b9 af a3 81 45 e8 dc 46 50 5c 81 e3 61 f9 7c 7e 81 6d e8 0a 22 1f 7b 25 ec 36 55 53 81 45 e8 50 6c 70 0e 81 6d e8 78 c5 b7 10 81 45 e8 f0 6c bc 60 81 f3 cc f8 6f 1f 81 45 e8 42 0e aa 1c}  //weight: 1, accuracy: High
        $x_1_7 = {8d 04 24 50 6a ?? ff 35 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 59 c3 b8 ?? ?? ?? ?? e8 [0-32] 68 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? 6b c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 33 c6 05 ?? ?? ?? ?? 6e c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 32 c6 05 ?? ?? ?? ?? 6c c6 05 ?? ?? ?? ?? 65 c6 05 ?? ?? ?? ?? 64 ff 15}  //weight: 1, accuracy: Low
        $x_1_8 = {6a ff 50 64 a1 00 00 00 00 50 8b 44 24 0c 64 89 25 00 00 00 00 89 6c 24 0c 8d 6c 24 0c 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_BT_2147739717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BT!MTB"
        threat_id = "2147739717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 10 05 2b cb a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 71 b8 8b 4c 24 10 05 ?? ?? ?? ?? 89 01 0f b7 fe a3 ?? ?? ?? ?? 8d 47 40 99 8b c8 0f b6 05 ?? ?? ?? ?? 66 89 35 ?? ?? ?? ?? 8b ea 66 3b c6 73}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 2b c7 83 e8 48 88 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b7 15 ?? ?? ?? ?? 8b c7 2b c2 83 c0 40 99 03 c8 13 ea 83 44 24 10 04 ff 4c 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BU_2147739746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BU!MTB"
        threat_id = "2147739746"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 0f b7 15 ?? ?? ?? ?? 0f b7 c0 f7 da 8d 04 40 2b d0 8b 44 24 14 03 f2 0f b7 d7 89 54 24 18 0f b7 15 ?? ?? ?? ?? 2b 54 24 18 8b 00 4a 89 35 ?? ?? ?? ?? 89 44 24 0c 89 54 24 24}  //weight: 1, accuracy: Low
        $x_1_2 = {6b c6 39 2b d0 66 89 15 ?? ?? ?? ?? 8b 44 24 10 83 44 24 14 04 0f b7 c0 0f b7 d7 89 54 24 20 2b d0 8b 44 24 24 83 c0 ?? 03 c2 83 6c 24 28 01 89 44 24 24 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 6c 24 1c 8b 54 24 14 8d 04 09 81 c6 ?? ?? ?? ?? 2b c3 0f b7 c0 89 74 24 10 89 32 8d 51 fe 89 35 ?? ?? ?? ?? 8b f0 8b 44 24 30 8d 14 56 83 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 44 24 14 04 83 c1 ae 8b 74 24 20 03 ca 83 6c 24 28 01 0f b7 c9 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_BV_2147739922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BV!MTB"
        threat_id = "2147739922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 f1 81 c7 ?? ?? ?? ?? 8b c6 2b c3 89 7d 00 66 0f b6 1d ?? ?? ?? ?? 83 e8 ?? 66 3b d9 73 [0-21] 8d 84 00 ?? ?? ?? ?? 0f b7 d2 2b c6 03 c2 83 c5 04 83 6c 24 10 ?? 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DA_2147739935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DA!MTB"
        threat_id = "2147739935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a da 89 15 ?? ?? ?? ?? 02 db 80 c3 0d 8b 54 24 28 8a c1 2a 44 24 10 81 c6 04 9c 01 01 2c 52 89 35 ?? ?? ?? ?? 02 d8 8b 44 24 24 89 34 02 83 c0 04 8b 15 ?? ?? ?? ?? 89 44 24 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DA_2147739935_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DA!MTB"
        threat_id = "2147739935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 55 2f 02 d3 f6 ea 8a d0 8b 45 1c 05 ?? ?? ?? ?? 89 45 24 fe c8 f6 e9 02 d0 02 55 47 30 14 31 83 3d ?? ?? ?? ?? 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {55 51 50 58 59 5d 59 5b c2}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 0f af c8 8b c6 33 d2 f7 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_A_2147739960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.A!MTB"
        threat_id = "2147739960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 34 02 c0 02 c2 02 44 24 14 89 44 24 18 a2 ?? ?? ?? ?? 8b 44 24 14 81 c5 9c 94 4d 01 8a 0d ?? ?? ?? ?? 0f b7 f0 8b c6 2b c3 8b 5c 24 20 83 c0 04 89 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_A_2147739960_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.A!MTB"
        threat_id = "2147739960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 b8 94 5b 01 89 44 24 14 89 02 a3 ?? ?? ?? ?? 8d 04 75 e1 ff ff ff 0f b7 d0 8b c6 3b da 8b 5c 24 20 0f 42 1d ?? ?? ?? ?? 2b c2 03 05 ?? ?? ?? ?? 83 44 24 10 04}  //weight: 1, accuracy: Low
        $x_1_2 = {bf 49 0b 01 00 c7 44 24 44 42 36 81 00 0f 42 df 2b 05 ?? ?? ?? ?? 03 c7 8b 3d ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 89 44 24 1c a3 ?? ?? ?? ?? b8 56 00 00 00 0f 42 d8 a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 2b d7 83 c6 c5 83 c0 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DB_2147740054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DB!MTB"
        threat_id = "2147740054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d0 2b d1 8b 0d ?? ?? ?? ?? 83 c1 63 03 ca 89 0d ?? ?? ?? ?? 81 c6 38 84 0b 01 0f b6 c8 89 35 ?? ?? ?? ?? 66 83 c1 63 89 b4 3b ?? ?? ?? ?? 83 c7 04 8b 1d ?? ?? ?? ?? 66 03 cb 0f b7 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DB_2147740054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DB!MTB"
        threat_id = "2147740054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {89 ce 90 83 e6 03 75 0a 89 fb 66 01 da c1 ca 03 89 d7 30 10 40 c1 ca 08 e2 e6}  //weight: 3, accuracy: High
        $x_1_2 = "c:\\smile\\Section\\Are\\which\\book\\salt\\range\\Subject\\objecthigh.pdb" ascii //weight: 1
        $x_1_3 = "mixseat.exe" ascii //weight: 1
        $x_1_4 = "protocol\\StdFileEditing\\server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_DSK_2147740751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DSK!MTB"
        threat_id = "2147740751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 7c fd bc 01 81 7c 24 24 69 77 01 00 8b 54 24 18 89 44 24 14 a3 ?? ?? ?? ?? 89 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ANG_2147741119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ANG!MTB"
        threat_id = "2147741119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 4d fc 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ff ff a1 30 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {03 4d f4 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ff ff 30 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_C_2147741306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.C"
        threat_id = "2147741306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\3\\.41\\.34DLOperatingSyk3456bb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_Soka_2147741471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.Soka!MTB"
        threat_id = "2147741471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 0f af c1 2b c2 a2 ?? ?? ?? ?? 0f af c1 2b c2 8b f0 8b 44 24 ?? 81 c7 ?? ?? ?? ?? 89 38 8d 44 19 ?? 0f b7 c0 6a ?? 5a 2b d0 0f b6 05 ?? ?? ?? ?? 03 ca 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AC_2147741541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AC!MTB"
        threat_id = "2147741541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 8b c3 0f b6 d2 0f af d1 a3 ?? ?? ?? 00 88 15 ?? ?? ?? 00 8b 0d ?? ?? ?? 00 8b 74 24 10 83 c1 c4 03 cb 89 4c 24 14 8b 36 3d ?? ?? ?? ?? 75 68}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 14 8b 12 8a 4c 24 13 02 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 0f b7 fb 8d 54 3a ff 88 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 3d ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? 85 f6}  //weight: 1, accuracy: Low
        $x_1_3 = {39 7c 24 18 76 1a 8d 3c 09 0f b6 d2 2b fb 0f b6 cb 0f af d1 89 3d ?? ?? ?? 00 88 15 ?? ?? ?? 00 8b 4c 24 10 81 c6 ?? ?? ?? ?? 89 31 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {99 8b f2 8b 2d ?? ?? ?? ?? 8b 54 24 14 81 c5 ?? ?? ?? ?? 89 2a 89 2d ?? ?? ?? ?? 8d 2c 07 83 c2 04 ff 4c 24 18 8d 7c 6f 54 89 3d ?? ?? ?? ?? 89 54 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_PK_2147741554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PK!MTB"
        threat_id = "2147741554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 09 8b 45 ?? 83 c0 04 89 45 ?? 81 7d f0 ?? ?? 00 00 73 69 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 91 ?? ?? ff ff 89 15 ?? ?? ?? ?? 33 c0 a0 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8d 54 01 07 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ff ff a1 ?? ?? ?? ?? 6b c0 29 8b 0d ?? ?? ?? ?? 03 c8 66 89 0d ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_2147741795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif!ibt"
        threat_id = "2147741795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 81 58 6e 43 00 6b ba 01 00 00 00 6b c2 0a c6 80 58 6e 43 00 6c b9 01 00 00 00 6b d1 06 c6 82 58 6e 43 00 33 b8 01 00 00 00 6b c8 03 c6 81 58 6e 43 00 6e ba 01 00 00 00 c1 e2 02 c6 82 58 6e 43 00 65 b8 01 00 00 00 6b c8 07 c6 81 58 6e 43 00 32 ba 01 00 00 00 6b c2 05 c6 80 58 6e 43 00 6c b9 01 00 00 00 c1 e1 00 c6 81 58 6e 43 00 65}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 ff 15 00 90 41 00 6a 00 6a 00 ff 15 04 90 41 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 10 90 41 00 8d 4d b0 51 6a 00 6a 00 ff 15 18 90 41 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 14 90 41 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 ac ff ff ff ff c7 45 64 c8 d2 e0 45 c7 45 58 b4 6f f8 23 c7 45 60 e5 a0 b3 0d c7 45 5c cf 8c 67 0c c7 45 48 f7 37 08 05 c7 45 50 3f 26 49 52 c7 45 30 9d fc 30 3c c7 45 4c 09 b0 b7 5e c7 45 24 5c b6 b6 52 c7 45 54 4f fd e6 2b c7 45 3c 4b 7d c7 60 c7 45 20 c5 f7 e0 57 c7 45 40 f6 9c 89 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_AE_2147742020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AE!MTB"
        threat_id = "2147742020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\finger\\thusWear.pdb" ascii //weight: 1
        $x_1_2 = {8b 5c 24 10 8b 1b 8b fd 2b 3d ?? ?? ?? 00 8b c1 2b c6 4f 48 89 3d ?? ?? ?? 00 89 1d ?? ?? ?? 00 81 fe ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 5c 24 10 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? 00 89 0b 0f b6 0d ?? ?? ?? 00 81 f9 ?? ?? ?? ?? 75 ?? 8d 0c 00 2b cf 8d b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AF_2147742238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AF!MTB"
        threat_id = "2147742238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 2b ce 69 f6 ?? ?? ?? ?? 05 ?? ?? ?? ?? 2b de 89 02 83 c2 04 ff 4c 24 14 66 8b fb a3 ?? ?? ?? 00 66 89 3d ?? ?? ?? 00 89 54 24 10 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 10 8b 12 89 15 ?? ?? ?? 00 13 fd 83 c3 f7 0f b7 d6 83 d7 ff 81 7c 24 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_P_2147742280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.P!MSR"
        threat_id = "2147742280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 6c 1e 00 00 68 c3 33 01 00 68 1b 23 00 00 68 d8 5a 00 00 6a 00 6a 64 e8}  //weight: 1, accuracy: High
        $x_1_2 = {c6 45 a7 00 03 c9 2b c9 0b c9 03 c0 8b 7d d0 ff d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SA_2147742390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SA"
        threat_id = "2147742390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 74 24 0c 52 ff 50 ?? 8b 54 ?? ?? 8b 48 ?? 3b 4a ?? 75 0e 8b 00 3b 02 75 08 b0 01}  //weight: 1, accuracy: Low
        $x_5_2 = "Silvergun.dll" wide //weight: 5
        $x_5_3 = "verb Sa" wide //weight: 5
        $x_1_4 = {8d 44 24 18 68 ee 07 00 00 50 68 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? ff 15 20 60 44 00 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_SA_2147742390_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SA"
        threat_id = "2147742390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\divide\\broad\\Hole\\DoThird.pdb" ascii //weight: 1
        $x_1_2 = "wcscat_s(outmsg, (sizeof(outmsg) / sizeof(outmsg[0]))" wide //weight: 1
        $x_1_3 = "m_policy.GetPolicyValue" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_B_2147742541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.B!MTB"
        threat_id = "2147742541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 cb 2b c1 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 4c 24 ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 01 0f b7 c3 83 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_B_2147742541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.B!MTB"
        threat_id = "2147742541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e9 5f 8b 1d ?? ?? ?? ?? 8b ee 6b ed 45 03 ef 39 1d ?? ?? ?? ?? 76 06 01 35 ?? ?? ?? ?? 8b 54 24 10 05 20 af 8e 01 a3 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_B_2147742541_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.B!MTB"
        threat_id = "2147742541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c0 4d 8b ?? ?? ?? ?? ?? 2b ?? 8b ?? f4 2b ?? 89 ?? f4 a1}  //weight: 1, accuracy: Low
        $x_1_2 = {70 66 37 01 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 03 ?? f0 a1 ?? ?? ?? ?? 89 ?? 42 e9 ff ff ?? ?? ?? ?? ?? ?? 6b ?? 4d 8b ?? f4 2b ?? 8b ?? f4 2b ?? 89 ?? f4 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SB_2147742546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SB"
        threat_id = "2147742546"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\Yard\\Ball\\Pair\\difficulthas.pdb" ascii //weight: 2
        $x_2_2 = "deMuiaer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AG_2147742707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AG!MTB"
        threat_id = "2147742707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ce 83 e6 03 75 [0-32] 66 01 da 6b d2 ?? c1 ca 05 [0-32] 30 10 40 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AG_2147742707_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AG!MTB"
        threat_id = "2147742707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 10 8b 1b 8b c8 2b ce 83 e9 04 83 ef 04 89 1d ?? ?? ?? 00 81 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 10 8d 4c 06 41 a1 ?? ?? ?? 00 05 ?? ?? ?? ?? 89 02 0f b6 15 ?? ?? ?? 00 a3 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AH_2147742898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AH!MTB"
        threat_id = "2147742898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 07 03 15 ?? ?? ?? ?? 89 55 e0 8b 45 e8 83 e8 4e 2b 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 2b c8 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b 55 e0 83 c2 78 3b 55 f0}  //weight: 1, accuracy: Low
        $x_1_2 = "PerhapsDance.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AH_2147742898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AH!MTB"
        threat_id = "2147742898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 8b 39 81 fb ?? ?? ?? ?? 75 ?? 8d 8a ?? ?? ff ff 66 03 c1 8b 4c 24 10 66 a3 ?? ?? ?? 00 83 44 24 10 04 81 c7 78 e0 3a 01 89 39 8d 4b 49 8d 0c 51 03 f1 8b 0d ?? ?? ?? 00 8d 0c b1 03 ce 83 6c 24 14 01 0f b7 d1 0f 85 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PA_2147742958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PA!MTB"
        threat_id = "2147742958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 f8 0f af 41 ?? 89 41 ?? a1 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 0f af da 8b 80 ?? ?? ?? ?? 05 4e 0e 07 00 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? 83 e8 3b 09 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 88 1c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PA_2147742958_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PA!MTB"
        threat_id = "2147742958"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 03 f6 2b f2 05 74 b3 b8 01 8b 54 24 18 81 c6 ?? ?? ?? ?? 83 44 24 ?? 04 03 f1 89 44 24 14 a3 ?? ?? ?? ?? 89 02 8b c6 2b 05 ?? ?? ?? ?? 83 c0 06 ff 4c 24 ?? 0f b7 d0 89 54 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 8b 00 89 44 24 14 0f b7 c2 89 44 24 10 8b c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AI_2147743168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AI!MTB"
        threat_id = "2147743168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 09 89 4c 24 10 8b ca f7 d9 2b c8 8b 44 24 1c 03 c1 89 44 24 1c 81 ff ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 46 2a 03 c2 8a cb 2a 0d ?? ?? ?? ?? 03 f8 8b 45 00 80 e9 08 88 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 fe ?? ?? ?? ?? 75 ?? 83 7c 24 1c 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 14 8b 12 0f b7 f3 8b fe 6b ff ?? 89 15 ?? ?? ?? ?? 8b d6 2b 15 ?? ?? ?? ?? 8d 04 0f 81 ea ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 0f 85 ?? 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4c 24 10 2b d7 81 c1 ?? ?? ?? ?? 6a ?? 89 4c 24 14 8d 42 06 89 0d ?? ?? ?? 00 8b 54 24 1c 89 44 24 20 89 0a 0f b7 0d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2b da 83 eb 08 89 1d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 45 00 8b c2 6b c0 ?? 2b c6 03 c7 6b c0 ?? 2b c2 05 ?? ?? ?? ?? 39 15 ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_6 = {8d 44 3a c3 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 54 24 14 05 ?? ?? ?? ?? 2b f5 89 02 a3 ?? ?? ?? ?? 83 c2 04 ff 4c 24 18 8d 46 cd a3 ?? ?? ?? ?? 89 54 24 14 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_PDSK_2147743507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PDSK!MTB"
        threat_id = "2147743507"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 44 29 02 03 cd 88 44 24 12 8a 59 03 8a c3 24 f0 c0 e0 02 0a 01 88 44 24 13 a1 ?? ?? ?? ?? 3d e9 05 00 00 0f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_VDSK_2147743752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VDSK!MTB"
        threat_id = "2147743752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 55 fe 8a d6 80 e2 f0 88 75 ff c0 e2 02 0a 14 ?? 88 55 fd 8a d6 80 e2 fc c0 e2 04 0a 54 ?? 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PVD_2147743755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PVD!MTB"
        threat_id = "2147743755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 54 24 11 8a d6 80 e2 f0 88 74 24 10 c0 e2 02 0a 14 38 88 54 24 12 8a d6 80 e2 fc c0 e2 04 0a 54 38 01 88 54 24 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_VDS_2147743912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VDS!MTB"
        threat_id = "2147743912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 54 01 02 88 95 fb f7 ff ff 8a 54 01 03 8a ca 88 95 fa f7 ff ff 80 e1 f0 c0 e1 02 0a 0c 03 88 8d f9 f7 ff ff 8b 0d ?? ?? ?? ?? 81 f9 e9 05 00 00 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARA_2147744048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARA!MTB"
        threat_id = "2147744048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 69 d2 ?? ?? ?? ?? 2b d1 88 0d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 03 c7 81 c6 dc 51 ed 01 8d 04 45 3a 00 00 00 89 35 ?? ?? ?? ?? 89 b5 a4 e1 ff ff 0f b7 d8 0f b6 05 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 16}  //weight: 1, accuracy: Low
        $x_1_2 = {83 44 24 10 ?? 83 c7 ?? 03 fb 81 7c 24 ?? ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARV_2147744049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARV!MTB"
        threat_id = "2147744049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 d0 8b f3 2b f2 83 c1 ?? 83 ee ?? ff 4c 24 ?? 89 4c 24 ?? 0f 85 76 00 69 ff ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 29 8b 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 81 fa ?? ?? ?? ?? 75 ?? 6b ff ?? 8d 7c 1f ?? eb ?? 8b 15 ?? ?? ?? ?? 8d 7c 1a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PB_2147744082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PB!MTB"
        threat_id = "2147744082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 45 f8 8a 00 88 45 ?? 8b 45 fc 03 45 f8 8b 4d f0 03 4d f8 8b 55 f0 8a 04 02 88 01 8b 45 fc 03 45 f8 8b 4d f0 8a 55 f7 88 14 01 eb c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PB_2147744082_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PB!MTB"
        threat_id = "2147744082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 0f a4 c2 01 8d 34 00 8b ea 81 c6 91 7f 00 00 83 d5 00 8b 44 24 10 8b 18}  //weight: 1, accuracy: High
        $x_20_2 = {8b 4c 24 10 83 44 24 10 04 81 c3 9c f5 cd 01 89 19 8d 0c 78 8d bc 0f ?? ?? ff ff 0f b6 ca 2b c8 03 cf ff 4c 24 ?? 0f 85}  //weight: 20, accuracy: Low
        $x_1_3 = {bb 6c 30 00 00 66 2b fb 8b 5c 24 14 8b 1b 8d 2c c5 00 00 00 00 89 1d ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_20_4 = {66 03 f8 a1 ?? ?? ?? 00 0f b7 d7 2b d1 8d 54 10 d6 89 15 ?? ?? ?? 00 a1 ?? ?? ?? 00 8b 54 24 14 05 a0 3c 50 01 89 02}  //weight: 20, accuracy: Low
        $x_20_5 = {8b 75 00 ba 40 00 00 00 0f b7 c8 81 c6 c0 0d df 01 2b d1 69 c0 6e 67 00 00 89 54 24 1c 8a 54 24 14 2a d3 89 75 00}  //weight: 20, accuracy: High
        $x_1_6 = {03 d9 8d ba ce 49 00 00 8a 54 24 13 8d 3c 7f 0f b6 ca 2b f9 ff 4c 24 18 89 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 44 24 10 8b 28 a1 ?? ?? ?? 00 2b c3 03 f1 03 35 ?? ?? ?? 00 2b c2 bb 7a c5 8b 36 83 e8 23}  //weight: 1, accuracy: Low
        $x_20_8 = {8b 44 24 10 81 c5 58 b4 2b 01 89 28 0f b6 05 ?? ?? ?? ?? 8d 7b ?? 3b c6 76 ?? 8d 7e ?? 03 fb 28 1d ?? ?? ?? ?? 83 44 24 10 04 8d 3c 7d ?? ?? 00 00 03 f9 03 fb ff 4c 24 ?? 0f 85}  //weight: 20, accuracy: Low
        $x_1_9 = {8b f3 03 fa 2b f1 8d 7c 38 09 8b 44 24 10 8b 28 81 ee 90 55 00 00}  //weight: 1, accuracy: High
        $x_20_10 = {8b 44 24 10 81 c5 5c 0f ad 01 89 28 b8 70 aa ff ff 2b c1 03 f0 39 0d ?? ?? ?? 00 73 ?? 8b c6 2b c1 83 c0 08}  //weight: 20, accuracy: Low
        $x_1_11 = {8b 7c 24 18 89 0d ?? ?? ?? ?? 6b ce 5c 8b 3f 89 7c 24 1c 8b f8 2b f9 81 fb 36 75 a9 25}  //weight: 1, accuracy: Low
        $x_20_12 = {8b 4c 24 1c 8b f3 8b 54 24 18 81 c1 68 c8 32 01 2b f7 89 4c 24 1c 89 0d ?? ?? ?? ?? 83 c6 0f 89 35 ?? ?? ?? ?? 89 0a}  //weight: 20, accuracy: Low
        $x_1_13 = {8b 38 8a e2 2a e1 80 c4 0e 88 25 ?? ?? ?? 00 81 fb b7 5d 96 01 75}  //weight: 1, accuracy: Low
        $x_20_14 = {8b 54 24 18 81 c7 7c 90 3d 01 83 44 24 18 04 0f b6 f4 89 3a 8d 14 09 2b d3 83 ea 4c 8b ca 2b ce 83 c1 0e ff 4c 24 38 0f 85}  //weight: 20, accuracy: High
        $x_20_15 = {8b 74 24 1c 81 c7 8c 95 c5 01 89 7c 24 ?? 89 3d ?? ?? ?? ?? 89 3e 6b f9 ac 83 7c 24 ?? ?? 89 3d ?? ?? ?? ?? 75}  //weight: 20, accuracy: Low
        $x_1_16 = {8b 7c 24 1c 8b 3f 89 7c 24 20 81 fb cc e6 20 10 75 ?? 85 f6 75}  //weight: 1, accuracy: Low
        $x_1_17 = {8b 28 b3 33 2a da 66 2b fe 66 83 ef 13 66 01 3d ?? ?? ?? 00 02 db 02 d9 81 f9 b5 d4 bd 1c 88 1d ?? ?? ?? 00 75 27}  //weight: 1, accuracy: Low
        $x_20_18 = {81 c5 b0 46 58 01 89 28 39 3d ?? ?? ?? 00 ba fe ff ff ff 72 07 83 2d ?? ?? ?? 00 02 8b 74 24 18 83 c0 04 83 6c 24 14 01 0f 85}  //weight: 20, accuracy: Low
        $x_1_19 = {8b bc 2b 59 fc ff ff 0f b6 f0 8b c6 c1 e0 05 2b c6 8b e8 8b c1 2b c5 81 fa 38 e0 a8 20 0f 85}  //weight: 1, accuracy: High
        $x_20_20 = {8b 6c 24 10 81 c7 3c 62 1d 01 89 3d ?? ?? ?? 00 89 bc 2b 59 fc ff ff a1 ?? ?? ?? 00 2b 05 ?? ?? ?? 00 8b 15 ?? ?? ?? 00 3d 0b 02 00 00 8b 3d ?? ?? ?? 00 8d 72 bb 75}  //weight: 20, accuracy: Low
        $x_1_21 = {8b 44 24 10 66 83 c2 4a 66 03 f2 8b 10 8b 44 24 14 0f b7 f9 66 89 35 ?? ?? ?? 00 89 15 ?? ?? ?? 00 89 7c 24 18 8d 44 38 07 81 fb 35 97 2d 25 0f 85}  //weight: 1, accuracy: Low
        $x_20_22 = {03 c2 8b 15 ?? ?? ?? 00 81 c2 a4 08 52 01 8d 44 38 4a 8b 7c 24 10 89 15 ?? ?? ?? 00 89 17 8b d0 2b d1 81 c2 59 24 00 00 0f b7 ca}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_ARI_2147744176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARI!MTB"
        threat_id = "2147744176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 4c 24 37 80 c9 9c 88 d5 0f b6 d5 8b 7c 24 2c 8b 44 24 10 8a 2c 07 88 4c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SA_2147744188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SA!MTB"
        threat_id = "2147744188"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b 4d ac 7f ?? 8b 03 8b 50 0c 8b 70 14 2b d6 8b c1 8d 34 0a 99 f7 ff 8b 45 ec 2b 50 14 8b 40 0c 8a 14 02 8a 06 32 c2 88 06 8b 45 b0 03 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SP_2147744249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SP!MSR"
        threat_id = "2147744249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "littleuSettingspreviously" wide //weight: 1
        $x_1_2 = "dforensicfrom" wide //weight: 1
        $x_1_3 = "vbarBsandboxoptionaldeemed" wide //weight: 1
        $x_1_4 = "IkexploitsafterkQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Ursnif_ARN_2147744514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARN!MTB"
        threat_id = "2147744514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d8 13 fa 89 7c 24 ?? 8b 7c 24 ?? 8b 15 ?? ?? ?? ?? 69 c3 ?? ?? ?? ?? 01 44 24 ?? 0f b7 c7 03 44 24 ?? 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARD_2147744515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARD!MTB"
        threat_id = "2147744515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 f8 8b 44 24 ?? 3b c7 74 ?? 8b df 0f af d9 6b db ?? 03 c3 89 44 24 ?? 81 ff ?? ?? ?? ?? 74 ?? b3 ?? f6 eb 83 c6 ?? 02 c1 81 fe ?? ?? ?? ?? 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 ff 2b e8 6a ?? 58 1b c7 03 cd 66 8b 2d ?? ?? ?? ?? 13 d0 8b c1 89 15 ?? ?? ?? ?? 6b c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARH_2147744516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARH!MTB"
        threat_id = "2147744516"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 0f b6 05 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 03 c2 89 44 24 ?? 3d 0f c6 00 00 74}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 2b ca 83 e9 ?? ff 4c 24 ?? 0f 85 25 00 0f b6 15 ?? ?? ?? ?? 83 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARR_2147744641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARR!MTB"
        threat_id = "2147744641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 0f af c3 ff 4c 24 ?? 0f b7 c0 0f b7 d8 8d b4 19 ?? ?? ?? ?? 0f 85 48 00 8b 44 24 ?? 8b 4c 24 ?? 83 44 24 ?? ?? 81 c5 b4 9d d8 01 89 28 8b 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ARJ_2147744642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ARJ!MTB"
        threat_id = "2147744642"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 0c 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 31 8d 0c 50 8b 15 ?? ?? ?? ?? 03 cb 8d 0c 4d ?? ?? ?? ?? 0f b7 d9 8d 0c 3a 81 f9 ?? ?? ?? ?? 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAR_2147744644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAR!MTB"
        threat_id = "2147744644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 2b c5 1b 54 24 ?? 8b e8 89 54 24 ?? eb 30 00 83 f8 ?? 74 ?? 3d ?? ?? ?? ?? 74 ?? 83 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cd 6b c9 ?? 83 44 24 ?? ?? 2b f9 8b 0d ?? ?? ?? ?? 03 f7 89 35 ?? ?? ?? ?? 89 08 a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8b c8 6b c9 ?? 03 d1 81 7c 24 ?? ?? ?? ?? ?? 8d 44 10 ?? 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAV_2147744645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAV!MTB"
        threat_id = "2147744645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c1 8b 4c 24 ?? 89 1a 83 c2 ?? 6b f8 ?? ff 4c 24 1c 8b 44 24 0c 89 54 24 ?? 0f 85 35 00 81 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAI_2147744697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAI!MTB"
        threat_id = "2147744697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 e0 58 6f 01 89 4c 24 18 89 0b 8b 5c 24 24 89 0d ?? ?? ?? ?? 8d 0c 33 8d 0c 4d ?? ?? ?? ?? 03 cb 81 3d ?? ?? ?? ?? 6e 1e 00 00 89 4c 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAN_2147744744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAN!MTB"
        threat_id = "2147744744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 47 fc 83 c2 05 05 d0 b3 e6 01 8b f2 89 47 fc 2b 74 24 14 4e a3 ?? ?? ?? ?? ff 4c 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c5 81 c1 f8 04 7c 01 2b c7 89 0a 83 e8 08 83 c2 04 0f af c5 89 54 24 14 69 c0 ?? ?? ?? ?? ff 4c 24 18 0f b7 f0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_AAD_2147744745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAD!MTB"
        threat_id = "2147744745"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 18 8b 54 24 14 81 c2 b8 ec 5a 01 89 54 24 14 89 17 0f b7 f9 89 15 ?? ?? ?? ?? 8d 57 0d 89 54 24 2c 66 39 5c 24 0e 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 44 24 0d 83 44 24 18 ?? 2b f8 83 c7 2f 03 fa ff 4c 24 24 74 ?? 8b 1d ?? ?? ?? ?? 8b 54 24 28 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAH_2147744759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAH!MTB"
        threat_id = "2147744759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 64 65 b2 01 89 44 24 1c 83 eb 1f a3 ?? ?? ?? ?? 89 06 8b 44 24 10 0f b7 c0 3d 5f b9 0c 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AAJ_2147744874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AAJ!MTB"
        threat_id = "2147744874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ca 81 e9 70 48 00 00 81 c7 c0 54 60 01 8b f1 89 3d ?? ?? ?? ?? 8d 04 36 89 7d 00 39 05 ?? ?? ?? ?? 73 42 00 03 c2 a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AVA_2147744875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AVA!MTB"
        threat_id = "2147744875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 0f b7 f3 2b 44 24 18 81 c1 8c cb c5 01 83 e8}  //weight: 1, accuracy: High
        $x_1_2 = {83 c5 04 03 05 ?? ?? ?? ?? 03 d8 6a 08 5a 81 fd 86 23 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AVR_2147744929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AVR!MTB"
        threat_id = "2147744929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 83 c2 04 89 55 f8 81 7d f8 96 16 00 00 0f 83 ?? ?? ?? ?? b8 04 00 00 00 c1 e0 02 8b 88 ?? ?? ?? ?? 89 4d ?? 83 7d ?? ?? 74}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 b3 ff 00 00 2b 05 ?? ?? ?? ?? 2b c7 66 03 d0 8b 44 24 10 83 c0 04 66 89 15 ?? ?? ?? ?? 89 44 24 10 3d fc 15 00 00 0f 82}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 6c 24 10 69 c1 05 34 01 00 83 c5 04 89 6c 24 10 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 fd fa 13 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_RAV_2147745147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RAV!MTB"
        threat_id = "2147745147"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c7 8d 53 03 83 c1 04 03 d0 ff 4c 24 1c 89 4c 24 14 74 ?? a1 ?? ?? ?? ?? 8b 7c 24 20 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c7 38 51 9b 01 8d 34 42 03 c6 89 3b 8b 35 ?? ?? ?? ?? 3b f2 89 3d ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 74 24 14 81 c7 70 b6 37 01 89 3e 83 c6 04 83 6c 24 ?? ?? b1 ?? 89 74 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 6c 24 14 8b d1 2b 15 ?? ?? ?? ?? 83 c5 04 83 ea 03 83 6c 24 18 01 0f b7 d2 89 6c 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_KMG_2147745170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KMG!MTB"
        threat_id = "2147745170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cf 2b ce 0f b6 f3 81 e9 30 5a 01 00 05 1c ba 0d 01 2b f1 89 45 00 81 ee e8 70 01 00 83 c5 04 ff 4c 24 10 a3 70 d8 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RAA_2147745451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RAA!MTB"
        threat_id = "2147745451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 81 c1 04 c7 80 01 89 0a 66 89 3d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 2b d0 0f b7 c2}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c5 10 8e 07 01 2b d0 8b 44 24 ?? 66 03 f2 66 89 35 ?? ?? ?? ?? 89 28 83 c0 ?? ff 4c 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c1 6c 86 34 01 0f b7 c0 89 0e 8b 74 24 ?? 89 44 24 ?? 89 4c 24 ?? 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_RAR_2147745497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RAR!MTB"
        threat_id = "2147745497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 d3 b8 4c 00 00 00 2b c2 8b 15 ?? ?? ?? ?? 2b c1 03 f0 81 c7 4c d4 25 01 89 35}  //weight: 1, accuracy: Low
        $x_1_2 = {81 ea fa 43 00 00 0f b7 da 0f b7 cb 83 c6 04 81 fe ff 08 00 00 8d 84 08 ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_RAI_2147745549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RAI!MTB"
        threat_id = "2147745549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c5 dc a3 ed 01 8d 1c b9 8b 7c 24 10 89 2f 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 2d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 54 24 10 8d 4c 18 bc 81 c5 bc 67 dd 01 4b 89 2a 0f af d9 66 39 35 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 10 8b 44 24 14 81 c7 fc c1 fd 01 89 3d ?? ?? ?? ?? 89 bc 28 ?? ?? ?? ?? 0f b7 c2 39 05 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
        $x_1_4 = {83 44 24 10 04 8d 91 ?? ?? ?? ?? 0f b6 c0 8b da 2b d8 81 c7 d4 3e 6a 01 83 c3 57 81 7c 24 10 fb 05 00 00 89 7d 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_PVS_2147745608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PVS!MTB"
        threat_id = "2147745608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b c0 03 8b d1 2b d0 66 89 15 ?? ?? ?? ?? 8b 44 24 14 83 44 24 14 04 81 c6 08 6d 84 01 89 30 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 7c 3f fd 81 c5 dc a3 ed 01 8d 1c b9 8b 7c 24 10 89 2f 81 3d}  //weight: 2, accuracy: High
        $x_2_3 = {8a c1 04 2a 00 05 ?? ?? ?? ?? 81 c7 68 e6 32 01 89 7d 00 0f b6 15 ?? ?? ?? ?? 8d 41 42 3b d1 77}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_PVK_2147745609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PVK!MTB"
        threat_id = "2147745609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 0a 8d 84 30 ?? ?? ?? ?? 03 c0 0f b7 f0 81 c1 60 d6 2e 01 8b c6 2b 45 f8 89 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 fc 8b 4d dc 33 f8 2b df 8b 7d f8 81 c7 47 86 c8 61 83 6d f4 01 89 7d f8 0f 85}  //weight: 2, accuracy: High
        $x_2_3 = {69 f6 35 0e 01 00 8b 54 24 10 81 c1 30 48 18 01 0f b7 f8 89 0a 06 00 8b 0d}  //weight: 2, accuracy: Low
        $x_2_4 = {30 41 04 8b [0-5] 03 c1 83 e0 03 0f b6 ?? 05 [0-4] 30 41 05 81 fa e2 02 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {2b c7 2b c6 2d 82 ca 00 00 81 c5 ?? ?? ?? ?? 8b f0 2b f1 89 2b 07 00 0f b6 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_VDK_2147745610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VDK!MTB"
        threat_id = "2147745610"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {81 c2 c0 e2 5e 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e4 8b 0d ?? ?? ?? ?? 89 88 06 00 8b 15}  //weight: 3, accuracy: Low
        $x_3_2 = {0f b7 c0 2b e8 83 c0 f6 81 c2 10 da 07 01 03 e8 89 54 24 14 8b 44 24 10 89 15 ?? ?? ?? ?? 89 10}  //weight: 3, accuracy: Low
        $x_3_3 = {8b d3 2b d1 81 c2 4b 3c 01 00 81 c6 e0 d1 ef 01 89 15 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 b4 28 05 00 a1}  //weight: 3, accuracy: Low
        $x_1_4 = {8b 4d fc 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_5 = {81 c3 47 86 c8 61}  //weight: 1, accuracy: High
        $x_1_6 = {33 c8 2b f9}  //weight: 1, accuracy: High
        $x_3_7 = {8b 45 e8 33 d2 b9 04 00 00 00 f7 f1 8b 45 dc 0f be 0c 10 8b 55 e8 0f b6 44 15 e4 33 c1 8b 4d e8 88 44 0d e4 eb}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_RVV_2147745614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RVV!MTB"
        threat_id = "2147745614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 10 05 34 a3 98 01 89 06 a3 ?? ?? ?? ?? 0f b7 c5 39 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 24 28 b8 fd ff 00 00 2b c3 2b 44 24 18 66 03 f0 8b 44 24 24 05 ec 65 f5 01 66 89 35 ?? ?? ?? ?? 89 07 bf ca ff 00 00 89 44 24 24 a3 ?? ?? ?? ?? b8 a2 20 00 00 66 39 05 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_RW_2147745687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RW!MSR"
        threat_id = "2147745687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dIe.y-KZX-Lujpm-Kw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RRA_2147745691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RRA!MTB"
        threat_id = "2147745691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 15 1f 00 00 66 39 4c 24 0c 8d 46 06 8b 4c 24 18 66 a3 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 04 89 4c 24 18 81 f9 a6 1e 00 00 0f 82 98 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RRV_2147745796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RRV!MTB"
        threat_id = "2147745796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 8d 14 2e 05 ?? ?? ?? ?? 89 01 66 89 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? c1 e1 03 0f b7 f1 0f b6 cb 66 03 ce 66 83 e9 26 66 03 d1 83 c7 04 66 89 15 ?? ?? ?? ?? 81 ff b9 03 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RVR_2147745819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RVR!MTB"
        threat_id = "2147745819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 24 8d 42 02 03 c3 81 c7 f8 cb fb 01 0f b7 c0 89 3d ?? ?? ?? ?? 89 39 8d 70 a2 69 c0 41 64 00 00 89 74 24 24 03 05 ?? ?? ?? ?? 0f b7 c8 8b 44 24 14 83 c0 04 89 4c 24 10 89 44 24 14 3d ?? ?? ?? ?? 73}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af da 2b de 8b 4c 24 10 05 34 83 98 01 89 84 0f 9a e1 ff ff bf ?? ?? ?? ?? 83 c1 04 2b fb 89 4c 24 10 81 f9 5e 1f 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_VKD_2147745989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VKD!MTB"
        threat_id = "2147745989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c2 94 8b c9 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 e0 8b 0d ?? ?? ?? ?? 89 88 67 eb ff ff 06 00 8b 15}  //weight: 2, accuracy: Low
        $x_2_2 = {8b d7 8b ca b8 ff 01 00 00 03 c1 2d ff 01 00 00 89 45 fc a1 ?? ?? ?? ?? 8b 4d fc 89 08}  //weight: 2, accuracy: Low
        $x_2_3 = {0f b6 c1 66 8b ca 66 2b c8 66 83 c1 14 0f b7 f1 8b 4c 24 1c 83 c1 04 89 4c 24 1c 81 f9 f4 0f 00 00 0f 82}  //weight: 2, accuracy: High
        $x_2_4 = {0f be 04 08 8b 8d ?? ?? ff ff 0f b6 94 0d ?? ?? ff ff 31 c2 88 d3 88 9c 0d ?? ?? ff ff 8b 85 ?? ?? ff ff 83 c0 01 89 85 ?? ?? ff ff e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_RRR_2147746194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RRR!MTB"
        threat_id = "2147746194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af ca 69 c9 e6 3d 00 00 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 05 a4 10 51 01 a3 ?? ?? ?? ?? 89 84 39 c3 f2 ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c7 24 1c 12 01 89 3d ?? ?? ?? ?? 89 bc 19 68 fc ff ff 8b 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8d 0c 42 8d 84 08 46 c8 ff ff 8b 0d ?? ?? ?? ?? 03 ce 89 4c 24 10 81 f9 06 01 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {81 c6 a0 37 d0 01 89 35 ?? ?? ?? ?? 89 b4 3a 09 e4 ff ff a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 6b c0 a6 03 d0}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c1 c4 93 e1 01 89 0d ?? ?? ?? ?? 89 8c 3a 2b f8 ff ff 8b 1d ?? ?? ?? ?? 0f b7 f6 0f b7 d6 b9 4e 00 00 00 2b ca 2b cb 83 c7 04 03 c1 81 ff ad 08 00 00 0f 82}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 54 24 1c 05 4c e0 25 01 8b 1d ?? ?? ?? ?? 89 44 24 24 a3 ?? ?? ?? ?? 89 84 13 f4 f0 ff ff 8d 56 f9 8b 5c 24 20 8d 14 57 0f b7 c6 66 89 15 ?? ?? ?? ?? 39 05 ?? ?? ?? ?? 77}  //weight: 1, accuracy: Low
        $x_1_6 = {69 ff 7a 3a 00 00 03 fb 0f b7 c7 89 44 24 20 03 c1 8d 84 00 dc 70 00 00 89 44 24 14 83 44 24 18 04 69 db 7a 3a 00 00 03 5c 24 24 81 7c 24 18 e2 22 00 00 66 89 3d ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_VA_2147747975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VA!MTB"
        threat_id = "2147747975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 00 fb 0f af c8 81 c6 10 58 08 01 89 b4 2f 84 f2 ff ff 8b 2d ?? ?? ?? ?? 83 c7 04 03 cd 81 ff 54 0e 00 00 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_KDS_2147748120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KDS!MTB"
        threat_id = "2147748120"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_2 = {30 84 37 00 fe ff ff}  //weight: 1, accuracy: High
        $x_2_3 = {69 c0 fd 43 03 00 8d 8d f8 f7 ff ff 51 05 c3 9e 26 00 05 00 a1}  //weight: 2, accuracy: Low
        $x_1_4 = {30 04 3e 46}  //weight: 1, accuracy: High
        $x_3_5 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8d 45 f8 50 56 ?? ?? ?? ?? ?? ?? a0 ?? ?? ?? ?? 30 04 1f 05 00 a1}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_VR_2147748448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VR!MTB"
        threat_id = "2147748448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 10 8b c8 2b ca 81 c6 20 ef 8f 01 83 c1 04 89 b4 2b 7e ea ff ff 81 3d ?? ?? ?? ?? d1 24 00 00 8d 84 08 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 6c 24 10 a1 ?? ?? ?? ?? 8d 84 28 ?? ?? ?? ?? 89 44 24 14 8b 00 bd c3 f4 d8 11 8d 9c 37 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8d 84 0f ?? ?? ?? ?? 3b d5 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 54 24 10 2d 9f 5c 00 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 84 10 ?? ?? ?? ?? 89 44 24 14 8b 00 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8d 7c 31 09 0f af c7 2b c1 a3 ?? ?? ?? ?? 81 fe 9f 8d ab 2f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_VAR_2147748535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VAR!MTB"
        threat_id = "2147748535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 1c 81 c1 84 de 40 01 6a a6 58 2b c3 89 4c 24 18 2b c6 89 0d ?? ?? ?? ?? 03 e8 a1 ?? ?? ?? ?? f7 db 83 d7 00 89 8c 10 fb e4 ff ff f7 df 8b 44 24 28 3b 05 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {03 de 8d 7c 1b 40 05 ?? 5b c8 01 89 01 6a 43 59 2b ce 2b ca 03 f9 81 3d ?? ?? ?? ?? 7c 24 00 00 89 1d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_KVD_2147748602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KVD!MTB"
        threat_id = "2147748602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d1 0f af c2 33 85 ?? ff ff ff 8b 4d c0 8b 55 ?? 03 04 8a 8b 0d ?? ?? ?? ?? 03 8d ?? fe ff ff 88 01 06 00 8b 95 ?? ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 84 3e f5 d0 00 00 8b 0d ?? ?? ?? ?? 88 04 31 8b 4d fc 33 cd 5f e8 ?? ?? ?? ?? c9 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_DHA_2147749693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHA!MTB"
        threat_id = "2147749693"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 d7 01 15 ?? ?? ?? ?? 8b d0 2b d7 bd 97 2b 00 00 03 d5 0f b7 fa 81 c1 00 27 80 01 89 0e 8b 35 ?? ?? ?? ?? 0f b7 d7 2b f7 03 f5 83 c3 ?? 83 c2 ?? 81 fb ?? ?? ?? ?? 0f b7 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DHB_2147751487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHB!MTB"
        threat_id = "2147751487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af cf be e0 ff ff ff 69 f9 7d 71 00 00 89 7c 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 81 c2 ?? ?? ?? ?? 89 54 24 ?? 89 11 8d 0c 75 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b7 d9 39 7c 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RB_2147751752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RB!MTB"
        threat_id = "2147751752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 02 89 ?? 24 ?? 85 c9 74 1b 8b 10 2b 54 24 ?? 8b ?? 24 ?? 01 54 24 ?? 83 44 24 ?? ?? 83 c0 ?? 49 89 ?? 75 e5 8b 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RC_2147751754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RC!MTB"
        threat_id = "2147751754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 40 8b 4c 24 2c 01 44 24 24 0f af c8 8b 44 24 24 2b c1 a3}  //weight: 1, accuracy: High
        $x_1_2 = "H:\\flow\\reproductivity\\act\\scripts.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RC_2147751754_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RC!MTB"
        threat_id = "2147751754"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d9 01 1d ?? ?? ?? ?? 8b 5c 24 ?? 33 c9 85 d2 0f 94 c1 85 c9 74 ?? 2b ca}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c8 03 f1 8b c8 2b ce 83 c1 ?? 8d 84 00 ?? ?? ?? ?? 2b c1 03 c6 83 3d ?? ?? ?? ?? ?? 89 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 75 ?? 8d 4e ?? 03 f6 2b f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RD_2147751831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RD!MTB"
        threat_id = "2147751831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 99 8b f0 33 c0 3b d0 8b ?? ?? ?? 89 ?? ?? ?? 89}  //weight: 1, accuracy: Low
        $x_1_2 = {8a c2 6b d2 ?? 02 c3 04 ?? 0f b6 d8 03 da 8a 4c 24 ?? 83 c5 ?? 02 cb 83 6c 24 ?? ?? 89 6c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PC_2147751939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PC!MTB"
        threat_id = "2147751939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 d0 88 85 ?? ?? ?? ?? 0f b6 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 88 8d ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da 88 95 ?? ?? ?? ?? 0f b6 85 ?? ?? ?? ?? c1 f8 03 0f b6 8d ?? ?? ?? ?? c1 e1 05 0b c1 88 85 ?? ?? ?? ?? 0f b6 95 ?? ?? ?? ?? f7 da 88 95}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PC_2147751939_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PC!MTB"
        threat_id = "2147751939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 7f 2b dd c7 44 24 ?? 00 00 00 00 8d 0c 40 2b cb 0f b7 c9 bf 2a 00 00 00 2b f9 2b fd 03 c7 8b 3d ?? ?? ?? 00 8b 8c 37 ?? ?? ff ff 81 c1 64 c8 31 01 89 8c 37 ?? ?? ff ff 8d 7c 00 fb 0f b7 ff 89 7c 24 10 0f b7 ff 8d 94 2a 5c b3 fe ff 8b ef 2b ea 83 c6 04 8d 44 28 ?? a3 ?? ?? ?? 00 81 fe ?? ?? 00 00 0f 82 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RE_2147752127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RE!MTB"
        threat_id = "2147752127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 05 2b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 52 e8 ?? ?? ?? ?? 83 ?? ?? 03 ?? ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? ?? 89 ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e9 2c 0f ?? ?? ?? ?? ?? ?? 2b ?? a1 ?? ?? ?? ?? 2b ?? a3 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 83 ?? ?? 2b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? ?? 2b ?? 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RF_2147752397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RF!MTB"
        threat_id = "2147752397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c1 14 52 09 01 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 03 ?? ?? a1 ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 69 ?? ?? ?? ?? ?? ba 64 01 00 0f b7 55 ?? 2b ca 66 ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RF_2147752397_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RF!MTB"
        threat_id = "2147752397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 57 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 8b ?? a3 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 83 ?? ?? 89 ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 83 ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b d2 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 ?? ?? ?? ?? ?? 8b ?? c7 ?? ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RF_2147752397_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RF!MTB"
        threat_id = "2147752397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 10 89 55 e4 8b ?? ?? 83 ?? ?? 89 ?? ?? 83 ?? ?? ?? 0f ?? ?? ?? ?? ?? 8b ?? ?? 83 ?? ?? 0f ?? ?? ?? 2b ?? a1 ?? ?? ?? ?? 2b ?? a3 ?? ?? ?? ?? 8b ?? ?? 8b ?? ?? 8a ?? 88 ?? 8b ?? ?? 83}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c1 3b 2b ?? ?? ?? ?? ?? 89 ?? ?? eb ?? 8b ?? ?? ?? ?? ?? 83 ?? ?? 2b ?? ?? 89 ?? ?? ?? ?? ?? eb ?? 8b ?? ?? 83 ?? ?? 2b ?? ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 2b ?? 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RF_2147752397_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RF!MTB"
        threat_id = "2147752397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "c:\\They\\by\\Say\\Drive\\650-Break\\Product.pdb" ascii //weight: 10
        $x_1_2 = "GetCPInfo" ascii //weight: 1
        $x_1_3 = "GetStartupInfoW" ascii //weight: 1
        $x_1_4 = "GetLocaleInfoW" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_6 = "SetSecurityDescriptorDacl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SA_2147752441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SA!MSR"
        threat_id = "2147752441"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Willprotect safe" wide //weight: 1
        $x_1_2 = "brought\\sign\\fine\\left\\cent\\believenight.pdb" ascii //weight: 1
        $x_1_3 = "EnterCriticalPolicySection" ascii //weight: 1
        $x_1_4 = "Microsoft.CRTProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RG_2147752532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RG!MTB"
        threat_id = "2147752532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c2 2a 33 c0 2b ?? ?? 1b ?? ?? 8b ?? ?? 33 ?? 2b ?? 1b ?? 89 ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? 33 ?? 89 ?? ?? 89 ?? ?? 8b ?? ?? 03 ?? ?? ?? ?? ?? 33 ?? 89 ?? ?? 89 ?? ?? 8b ?? ?? 33 ?? 03 ?? ?? 13 ?? ?? a3 ?? ?? ?? ?? 8b ?? ?? ?? ?? ?? 03 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DHC_2147752534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHC!MTB"
        threat_id = "2147752534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 a3 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 06 7d 40 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af 14 8d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 45 08 69 c0 15 0c 00 00 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 3b 0d ?? ?? ?? ?? 75 02 eb 02 eb aa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DHD_2147752535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHD!MTB"
        threat_id = "2147752535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c1 0f af 05 ?? ?? ?? ?? 69 c0 59 5b 00 00 8d 48 dc 0f b7 c9 0f b7 f1 0f af f0 69 f6 59 5b 00 00 89 35 00 8b c6 8b 35 ?? ?? ?? ?? 2b f2 03 f3 8b d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DHE_2147752536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHE!MTB"
        threat_id = "2147752536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b d2 39 a1 ?? ?? ?? ?? 2b c2 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 6b c9 39 8b 15 ?? ?? ?? ?? 2b d1 89 55 ec 8b 45 ec 83 e8 54 33 c9 2b 45 f0 1b 4d f4 a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 c2 18 6d 0c 02 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AM_2147754149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AM!MSR"
        threat_id = "2147754149"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 84 0a c0 b7 00 00 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 e9 65 e8 34 00 89 0d ?? ?? ?? ?? 8b 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_VD_2147754213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VD!MTB"
        threat_id = "2147754213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 24 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PVR_2147754413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PVR!MTB"
        threat_id = "2147754413"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 10 0f b6 c9 d3 ca 8b 4d f8 83 c0 04 33 d1 2b d3 89 50 fc 8b 55 f4 4b 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_KSV_2147754468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KSV!MTB"
        threat_id = "2147754468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 44 24 14 8b 16 02 c3 0f b6 c8 8b 44 24 10 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GM_2147754550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GM!MTB"
        threat_id = "2147754550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c0 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ff c7 05 [0-16] 01 05 ?? ?? ?? ?? 8b ff a1 [0-16] 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 89 45 f4 8b 0d ?? ?? ?? ?? 03 4d ?? 89 0d ?? ?? ?? ?? 8b 55 ?? 89 55 ?? 8b 45 [0-64] 8d 84 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_D_2147755282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.D!MTB"
        threat_id = "2147755282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8b ff c7 05 [0-48] 01 05 [0-32] 8b ff a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {03 4d fc 89 0d ?? ?? ?? ?? 8b 55 ?? 89 55 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_E_2147755284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.E!MTB"
        threat_id = "2147755284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 [0-48] 01 05 [0-48] 8b ff a1 [0-32] 8b 0d [0-32] 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 89 45 ?? 8b 0d [0-32] 03 4d ?? 89 0d [0-32] 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_E_2147755284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.E!MTB"
        threat_id = "2147755284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 59 11 00 00 [0-48] 81 c2 59 11 00 00 [0-255] 00 00 [0-96] 31 0d [0-255] 89 11}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 2d e8 ff 00 8b 11 81 ea [0-10] 89 10 [0-255] ba 39 00 00 00 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_3 = "RuP2XbA$Sse3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_E_2147755284_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.E!MTB"
        threat_id = "2147755284"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 00 6b c6 40 01 65 c6 40 02 72 c6 40 03 6e c6 40 04 65 c6 40 05 6c c6 40 06 33}  //weight: 1, accuracy: High
        $x_1_2 = {c7 03 48 65 61 70 66 c7 43 04 43 72 66 c7 43 06 65 61}  //weight: 1, accuracy: High
        $x_1_3 = "jrrmrryrjgyn" ascii //weight: 1
        $x_1_4 = "rrmrryrjgyn" ascii //weight: 1
        $x_1_5 = "qwlljiupqt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DHF_2147755767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DHF!MTB"
        threat_id = "2147755767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 8b c8 8b f2 8b 44 24 28 99 03 c1 8b 4c 24 14 13 f2 2b 44 24 10 89 44 24 10 1b f7 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b fe 89 74 24 18 8b 74 24 28 89 3d ?? ?? ?? ?? 8b 54 24 20 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AJ_2147756281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AJ!MTB"
        threat_id = "2147756281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 30 0c 30 b8 01 00 00 00 83 f0 04 83 6c 24 0c 01 83 7c 24 0c 00 0f 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_PS_2147756346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PS!MTB"
        threat_id = "2147756346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 0f b7 f8 8b 4c 24 ?? 8b 44 24 ?? 83 44 24 ?? ?? 05 ?? ?? ?? ?? 0f b7 f7 83 c6 ?? 89 01 03 f2 89 44 24 ?? 8d 4b ?? a3 ?? ?? ?? ?? 03 ce ff 4c 24 ?? 0f b7 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SF_2147756430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SF!MTB"
        threat_id = "2147756430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 b9 1d 0c c7 84 ?? ?? 00 00 00 00 00 00 00 c7 84 ?? ?? 00 00 00 f4 23 00 00 66 c7 84 ?? ?? 00 00 00 8c 0c c7 84 ?? ?? 00 00 00 f7 7e 00 00 66 8b 94 ?? ?? 00 00 00 66 89 d6 66 81 f6 e4 2c 66 89 74 ?? ?? 66 c7 44 ?? ?? cc 55 66 8b b4 ?? ?? 00 00 00 66 8b 7c ?? ?? 66 81 f6 fb 2f 66 89 74 ?? ?? 66 89 d6 66 29 f6 66 89 b4 ?? ?? 00 00 00 66 39 f9 89 44 ?? ?? 66 89 54}  //weight: 1, accuracy: Low
        $x_1_2 = {05 d8 2d 00 00 8b 8c ?? ?? 00 00 00 8b 54 ?? ?? 81 c1 09 c5 00 00 89 02 8b 44 ?? ?? 89 48 ?? 8b 44 ?? ?? 8b 8c ?? ?? 00 00 00 81 c1 d9 08 00 00 8b 94 ?? ?? 00 00 00 81 c2 09 81 ff ff 89 48 ?? 66 8b 74 ?? ?? 66 89 f0 25 1b 3e 00 00 66 89 c7 8b 84 ?? ?? 00 00 00 66 89 bc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GA_2147756455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GA!MTB"
        threat_id = "2147756455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 01 8a 54 24 0c 32 d0 41 88 16 46 ff 4c 24 08 75 ee}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GA_2147756455_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GA!MTB"
        threat_id = "2147756455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 74 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d [0-16] 83 7d [0-16] 0f 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GA_2147756455_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GA!MTB"
        threat_id = "2147756455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 f0 2b de 8b 37 03 eb b3 59 f6 eb 8a da 2a d8 81 3d [0-8] 88 1d [0-4] 8b 1d [0-4] 81 c6 [0-4] 8a ca 2a cb 89 37 80 c1 ?? 83 c7 ?? 83 6c 24 ?? 01 89 35 [0-4] 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SG_2147756864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SG!MTB"
        threat_id = "2147756864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 03 45 f8 8b 4d f4 03 4d f8 8a 11 88 10 8b 45 f8 83 c0 01 89 45 f8 eb}  //weight: 1, accuracy: High
        $x_1_2 = {03 45 fc 8b 55 08 03 02 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: High
        $x_1_3 = {ba b2 19 00 00 31 0d ?? ?? ?? 00 a1 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GB_2147758249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GB!MTB"
        threat_id = "2147758249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 37 4e c7 44 24 [0-48] 81 e3 ?? ?? ?? ?? 81 6c 24 [0-48] 81 44 24 [0-48] 81 6c 24 [0-48] c1 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GC_2147758895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GC!MTB"
        threat_id = "2147758895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 02 8b 4d ?? 8d 54 01 ?? 8b 45 ?? 89 10 8b 4d ?? 8b 11 83 ea ?? 8b 45 ?? 89 10 8b e5}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ff c7 05 [0-48] 01 05 [0-32] 8b ff 8b 0d [0-32] 8b 15 [0-32] 89 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GC_2147758895_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GC!MTB"
        threat_id = "2147758895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c8 83 c1 ?? 03 cf 89 0d [0-4] 8b 7c 24 ?? 81 c3 [0-4] 0f b6 c8 66 2b ca 89 1d [0-4] 89 1f 83 c7 ?? 8b 1d [0-4] 66 03 cb 66 03 4c 24 ?? 66 03 f1 89 7c 24 ?? ff 4c 24 ?? 8b 7c 24 ?? 66 89 74 24 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GD_2147759118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GD!MTB"
        threat_id = "2147759118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 f7 f3 8a 04 32 88 45 ?? 8a 04 37 88 04 32 8a 55 ?? 8b c1 88 14 37 [0-48] c7 44 24 [0-32] 0b c8 c7 44 24 [0-32] b8 ?? ?? ?? ?? 2b c3 03 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DEA_2147759179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DEA!MTB"
        threat_id = "2147759179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 8b 54 24 14 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 2c 03 44 24 28 03 d7 33 c1 8b 0d ?? ?? ?? ?? 33 c2 2b e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 14 8b d7 d3 e2 8b c7 03 54 24 28 c1 e8 05 03 44 24 30 33 d0 c7 05 ?? ?? ?? ?? 00 00 00 00 8b 44 24 18 03 c7 33 d0 a1 ?? ?? ?? ?? 2b ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_DED_2147759255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DED!MTB"
        threat_id = "2147759255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 14 8b c7 d3 e0 8b cf c1 e9 05 03 4c 24 2c 03 44 24 28 89 15 ?? ?? ?? ?? 33 c1 8b 4c 24 18 03 cf 33 c1 8b 0d ?? ?? ?? ?? 2b e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 5d f8 8b d3 8b 4d fc 8b c3 83 25 ?? ?? ?? ?? 00 d3 e2 03 55 e4 c1 e8 05 03 45 e0 33 d0 8d 04 1e 33 d0 2b fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_GF_2147759301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GF!MTB"
        threat_id = "2147759301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f3 33 b5 [0-32] 2b fe 25 [0-32] 81 6d [0-32] bb [0-32] 81 45 [0-32] 8b 4d ?? 83 25 [0-32] 8b c7 d3 e0 8b cf c1 e9 ?? 03 8d [0-64] 33 c1 8b 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 48 29 c3 81 fb ?? ?? ?? ?? 75 f3}  //weight: 1, accuracy: Low
        $x_1_2 = {ac 30 d0 aa c1 ca ?? e2 f7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 03 d1 8d 8a ?? ?? ?? ?? 2b ce 8b f1 1b c7 8b f8 3b 54 24 14 74 0e 8b 44 24 10 40 89 44 24 10 83 f8 ?? 7c d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 f8 00 25 ?? ?? ?? ?? 81 6d f8 ?? ?? ?? ?? bb ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? 8b 4d f8 83 25 ?? ?? ?? ?? ?? 8b c7 d3 e0 8b cf c1 e9 05 03 4d dc 03 45 e0 33 c1 8b 4d f4 03 cf 33 c1 29 45 fc 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 89 55 f8 25 ?? ?? ?? ?? 81 6d f8 ?? ?? ?? ?? bb ?? ?? ?? ?? 81 45 f8 ?? ?? ?? ?? 8b 45 fc 8b 4d f8 8b f0 d3 e6 8b c8 c1 e9 05 03 4d e0 03 75 e4 89 15 ?? ?? ?? ?? 33 f1 8b 4d f4 03 c8 33 f1 8b 0d ?? ?? ?? ?? 2b fe 81 f9 ?? ?? ?? ?? 75 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 33 45 0c 89 45 08 8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc 8b 55 fc 81 c2 ?? ?? ?? ?? 89 55 fc c1 45 08 04 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 fc 33 d2 b9 ?? ?? ?? ?? f7 f1 89 45 fc 8b 55 08 81 c2 ?? ?? ?? ?? 89 55 08 8b 45 fc 05 ?? ?? ?? ?? 89 45 fc 8b 45 08 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 30 8b 4c 24 20 66 8b 14 48 66 89 d6 66 83 ?? ?? c7 44 24 60 ?? ?? ?? ?? 66 89 d7 66 83 c7 ?? 66 83 fe ?? 66 0f 42 d7 8b 44 24 58 35 ?? ?? ?? ?? 8b 5c 24 0c 89 5c 24 60 8b 74 24 10 66 39 14 4e 0f 94 c3 80 e3 01 88 5c 24 43 8b 74 24 0c 69 f6 ?? ?? ?? ?? 66 83 fa 00 0f 95 c3 8a 7c 24 43 89 74 24 60 8b 74 24 34 01 c1 39 f1 0f 92 c0 20 df 20 c7 89 4c 24 20 f6 c7 01 75 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MK_2147759334_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MK!MTB"
        threat_id = "2147759334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 6c 24 1c 4e 8d 84 30 ?? ?? ?? ?? 0f b7 d0 8a 04 2f 88 07 89 54 24 10 8b 15 ?? ?? ?? ?? 47 3b d3 77 1e 0f b6 c1 66 0f b6 c9 66 03 cb 66 83 e9 ?? 66 01 4c 24 10 8a 4c 24 10 a3 ?? ?? ?? ?? 2a cb 0f b7 6c 24 10 8b 44 24 14 2b c5 03 c6 3b d3 77 12 0f b6 d1 89 15 03 8a d0 2a d3 80 ea ?? 02 ca 85 f6 75 98}  //weight: 1, accuracy: Low
        $x_1_2 = {3b 05 d0 00 03 10 74 1a 8b 15 ?? ?? ?? ?? 29 11 8b f2 69 f6 ?? ?? 00 00 2b f0 8b c6 03 d0 8d 5c 13 ca 83 e9 08 81 f9 ?? ?? ?? ?? 7f d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_AV_2147759359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.AV!MSR"
        threat_id = "2147759359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c5 c0 82 5e 01 89 28 0f b7 15 ?? ?? ?? ?? 8d 04 09 2b c7 03 c6 3b d0 73 12 8b d1 2b d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DEF_2147759617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DEF!MTB"
        threat_id = "2147759617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d3 83 c4 30 0f be 0c 01 89 4d 14 0a 5d 14 f6 d2 f6 d1 0a d1 22 d3 88 10}  //weight: 1, accuracy: High
        $x_1_2 = "124365SDSCzsfdfgrSFdghfdghfghcvFSczsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_DEI_2147760227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DEI!MTB"
        threat_id = "2147760227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e0 8b cf c1 e9 05 03 8d ?? fe ff ff 03 85 ?? fe ff ff 33 f6 33 c1 8b 8d ?? fe ff ff 03 cf 33 c1 29 45 6c 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_KA_2147761006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KA"
        threat_id = "2147761006"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 3a 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 47 29 28 44 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 4e 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 41 55 29 28 41 3b 4f 49 43 49 3b 47 41 3b 3b 3b 42 41 29 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 08 69 c9 0d 66 19 00 03 ce 88 4c 3a 08 47 89 08 83 ff 08 72 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DEJ_2147761055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DEJ!MTB"
        threat_id = "2147761055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e0 8b ce c1 e9 05 03 8d ?? fd ff ff 03 85 ?? fd ff ff 03 fe 33 c1 33 c7 89 85 ?? fd ff ff 8b 85 ?? fd ff ff 29 45 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_F_2147761063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.F!MTB"
        threat_id = "2147761063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 24 89 c3 03 5c 24 ?? 89 5c 24 ?? 8b 74 24 ?? 8b 6c 24 ?? 8a 26 8a 6d ?? 30 ec 88 26 ff 44 24 ?? 8b 5c 24 ?? 3b 5c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_H_2147761073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.H!MTB"
        threat_id = "2147761073"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31 [0-32] 8b e5}  //weight: 1, accuracy: Low
        $x_1_2 = {81 c1 3c 5e 00 00 a1 [0-64] 31 0d [0-16] c7 05 [0-32] a1 [0-32] 01 05 [0-32] 8b 15 [0-32] a1 [0-16] 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DEK_2147761118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DEK!MTB"
        threat_id = "2147761118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d3 e2 8b c8 c1 e9 05 03 8d ?? fe ff ff 03 95 ?? fe ff ff 89 3d ?? ?? ?? ?? 33 d1 8b 4d f8 03 c8 33 d1 29 55 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_I_2147761581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.I!MTB"
        threat_id = "2147761581"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 33 89 7c 24 ?? 81 6c 24 [0-48] 81 44 24 [0-48] 81 6c 24 [0-48] 81 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_Q_2147761777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.Q!MTB"
        threat_id = "2147761777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff c7 05 [0-48] 01 1d [0-32] 8b ff a1 [0-16] 8b 0d [0-32] 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = {03 f0 8b 45 ?? 03 30 8b 4d ?? 89 31}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RU_2147762851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RU!MTB"
        threat_id = "2147762851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 20 00 8b c3 99 2b c2 56 d1 f8 89 4d fc 57 8b c8 89 5d f4 33 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_VIS_2147768501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VIS!MSR"
        threat_id = "2147768501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 8c 10 c0 b2 07 00 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 81 ea be ac 00 00 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MR_2147770232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MR!MTB"
        threat_id = "2147770232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\Barsend\\WarStretch\\PageMust\\Bottominstrument\\Group.pdb" ascii //weight: 1
        $x_1_2 = "Group.dll" ascii //weight: 1
        $x_1_3 = "Stillbig5" ascii //weight: 1
        $x_1_4 = "Industryshine8" ascii //weight: 1
        $x_1_5 = "Thoughtwhose" ascii //weight: 1
        $x_1_6 = "Tail noise Corporation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Ursnif_KM_2147776677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.KM!MTB"
        threat_id = "2147776677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 b3 0c 00 00 6a 00 e8 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MS_2147779981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MS!MTB"
        threat_id = "2147779981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 29 05 [0-4] 8b [0-3] 8a [0-3] 8b [0-3] 2a d1 83 [0-4] 05 [0-4] 80 [0-2] 89 07 83 [0-4] 8b [0-3] 88 [0-3] a3 [0-4] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RW_2147780961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RW!MTB"
        threat_id = "2147780961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 c2 e0 0e 00 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 ?? 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? e9}  //weight: 5, accuracy: Low
        $x_1_2 = "c:\\lead\\Ice\\Press\\Protect\\Class\\person.pdb" ascii //weight: 1
        $x_5_3 = {80 eb 3d 8b 00 05 c0 20 0f 01 89 01 8b 0d ?? ?? ?? ?? a3 ?? ?? ?? ?? 0f b6 c3}  //weight: 5, accuracy: Low
        $x_1_4 = "c:\\Grew_Practice\\137\\until\\Poor_fair\\Voice-Rock\\class.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ursnif_PAB_2147781097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.PAB!MTB"
        threat_id = "2147781097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Schoolpress@@8" ascii //weight: 1
        $x_1_2 = "Triangleart@@8" ascii //weight: 1
        $x_1_3 = "Begin Fun" ascii //weight: 1
        $x_1_4 = "Dark@@4" ascii //weight: 1
        $x_1_5 = "GetCurrentProcess" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "TerminateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MFP_2147782171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MFP!MTB"
        threat_id = "2147782171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {bb b2 72 35 fc ba bf 3a 15 4b 0f 45 d3 85 f9 89 44 24 50 0f 94 44 24 2c 0f 45 da 83 fe 0a 0f 9c 44 24 38 0f 4d da 41 b8 bf 3a 15 4b b9 66 66 41 c9 be 4b c4 69 10 31 ff 81 f9 4a c4 69 10}  //weight: 5, accuracy: High
        $x_5_2 = {0f af f0 89 f0 83 f0 ?? 85 f0 40 0f 94 c5 83 fa 0a 0f 9c c3 40 30 eb bb 6c 95 b0 0f bf b2 df 8f 21 0f 45 df 85 f0 89 dd 0f 44 ef 83 fa 0a 4c 89 4c 24 08 0f 4d eb}  //weight: 5, accuracy: Low
        $x_5_3 = {0f af d0 89 d0 83 f0 ?? 85 d0 41 0f 94 c0 83 f9 0a 0f 9c c3 44 30 c3 bb 61 20 ca 7d be a9 33 3d 09 0f 45 de 85 d0 89 d8 0f 44 c6 83 f9 0a 8b 4c 24 5c 0f 4d c3 3b 0d 96 6f 02}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Ursnif_SB_2147782931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SB!MTB"
        threat_id = "2147782931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {66 89 44 24 14 8b c6 0f af 44 24 0c 83 64 24 24 00 69 c0 e3 48 00 00 0f b7 c0 57 0f b7 f8 6a 00 89 44 24 14 6a 02}  //weight: 10, accuracy: High
        $x_10_2 = {66 83 c0 08 69 f6 84 04 00 00 0f b7 e8 0f b7 c5 03 f0 6b c0 4b 03 c3 89 6c 24 0c 03 e8 8b c5 69 c0 63 3b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SB_2147782931_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SB!MTB"
        threat_id = "2147782931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bENHWRJNRw@#GHNe.pdb" ascii //weight: 1
        $x_1_2 = "ZK9 LTD" ascii //weight: 1
        $x_1_3 = "7 Broxbourne Road" ascii //weight: 1
        $x_1_4 = "Certum EV TSA SHA2" ascii //weight: 1
        $x_1_5 = "htnRne" wide //weight: 1
        $x_1_6 = "znfu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SMKA_2147783402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SMKA!MTB"
        threat_id = "2147783402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b c0 5f 8b 4d e8 2b c8 0f b7 05 e0 3f 44 00 2b c1 66 a3 e0 3f 44 00 8b 45 0c 2d d2 12 00 00 0f b7 0d e0 3f 44 00 2b c1 0f b6 0d de 3f 44 00 03 c1 0f b6 0d de 3f 44 00 03 c8 88 0d de 3f 44 00}  //weight: 1, accuracy: High
        $x_1_2 = {83 e8 07 2b 45 0c a2 de 3f 44 00 a1 0c 40 44 00 6b c0 5f 8b 4d e8 2b c8 0f b7 05 e0 3f 44 00 2b c1 66 a3 e0 3f 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RT_2147783571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RT!MTB"
        threat_id = "2147783571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af ca 85 c9 8b 54 24 ?? 03 d0 89 54 24 ?? 8b 54 24 ?? 8b 4c 24 ?? 31 0a 83 c0 04 3b 44 24 ?? 7e ?? c7 44 24 ?? 04 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_G_2147784098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.G!MTB"
        threat_id = "2147784098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 43 01 00 00 8b 4d ?? 66 89 01 8b 55 ?? 0f b7 02 2d da 00 00 00 8b 4d ?? 66 89 01 ba 48 01 00 00 8b 45 ?? 66 89 50 02 8b 4d ?? 0f b7 51 02 81 ea da 00 00 00 8b 45 ?? 66 89 50 02 b9 4e 01 00 00 8b 55 ?? 66 89 4a 04 8b 45 ?? 0f b7 48 04 81 e9 da 00 00 00 8b 55 ?? 66 89 4a 04 b8 3f 01 00 00 8b 4d ?? 66 89 41 06 8b 55 ?? 0f b7 42 06 2d da 00 00 00 8b 4d ?? 66 89 41 06 ba 4c 01 00 00 8b 45 ?? 66 89 50 08 8b 4d ?? 0f b7 51 08 81 ea da 00 00 00 8b 45 ?? 66 89 50 08 b9 40 01 00 00 8b 55 ?? 66 89 4a 0a 8b 45 ?? 0f b7 48 0a 81 e9 da 00 00 00 8b 55 ?? 66 89 4a 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GN_2147785248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GN!MTB"
        threat_id = "2147785248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 38 28 00 00 8b c1 99 03 d8 a1 ?? ?? ?? ?? 6a 00 13 fa 03 de 8b 15 ?? ?? ?? ?? 13 fa 83 c3 bb 89 5d ?? 83 d7 ff 2b d9 8b 0d ?? ?? ?? ?? 83 c0 c4 6a 31 52 89 7d ?? 81 c3 61 01 00 00 56 8d 3c 41}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 07 89 45 ?? 0f b7 c6 2b f8 8d 83 ?? ?? ?? ?? 52 83 c7 26 66 03 f0 57 66 89 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BW_2147787043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BW!MTB"
        threat_id = "2147787043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Close\\Eight\\age\\king\\Organ\\sea\\music\\Kinghill.pdb" ascii //weight: 1
        $x_1_2 = "Plandee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BW_2147787043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BW!MTB"
        threat_id = "2147787043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bread mass Againbat human cause" ascii //weight: 1
        $x_1_2 = "c:\\life\\Copy\\spring\\rain\\Ever\\mind\\cent\\burnCold.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_XU_2147788173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.XU!MTB"
        threat_id = "2147788173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Grema Kargo" ascii //weight: 1
        $x_1_2 = "admin@gremaonline.ru" ascii //weight: 1
        $x_1_3 = "rewgqrwg.pdb" ascii //weight: 1
        $x_1_4 = "mJ_k4Xj" ascii //weight: 1
        $x_1_5 = "ZHY6y" ascii //weight: 1
        $x_1_6 = "2H+7z*U1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ABM_2147788979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ABM!MTB"
        threat_id = "2147788979"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 8b ec 83 ec 08 66 c7 45 f8 07 00 66 c7 45 fc 09 00 0f b7 45 fc 6b c0 06 0f b7 ?? ?? ?? ?? ?? 2b c1 66 89 45 f8 c7}  //weight: 10, accuracy: Low
        $x_3_2 = "fell\\Test.pdb" ascii //weight: 3
        $x_3_3 = "Bluemean" ascii //weight: 3
        $x_3_4 = "Test.dll" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BJ_2147789181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BJ!MTB"
        threat_id = "2147789181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b8 c9 43 eb 99 f7 e9 8b 4c 24 28 c1 fa 08 8b c2 c1 e8 1f 03 c2 0f af 44 24 44 99 83 c1 3e f7 f9 2b c7 8b 7c 24 0c 8d 94 06 cc fd ff ff 89 54 24 4c}  //weight: 1, accuracy: High
        $x_1_2 = {0f af c6 0f af 44 24 40 89 84 24 c8 00 00 00 b8 87 61 18 86 f7 e1 8b 84 24 c8 00 00 00 2b ca d1 e9 03 ca c1 e9 04 03 c1 29 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_VN_2147794363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.VN!MTB"
        threat_id = "2147794363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DVERI FADO, TOV" ascii //weight: 1
        $x_1_2 = "admin@dverifadotov.space" ascii //weight: 1
        $x_1_3 = "Bud. 115 prospekt Gagarina" ascii //weight: 1
        $x_1_4 = "Dnipropetrovsk Oblast" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_YOH_2147794629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.YOH!MTB"
        threat_id = "2147794629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 48 a6 00 00 52 8b 45 ?? 05 58 a6 00 00 50 6a 00 6a 00 8b 4d ?? 0f b7 91 ?? ?? ?? ?? 81 f2 e4 07 00 00 52 6a 00 6a 00 6a 00 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f1 8b 45 d8 0f be 8c 10 ?? ?? ?? ?? 8b 55 d8 8b 82 ?? ?? ?? ?? 03 c1 8b 4d d8 8b 91 ?? ?? ?? ?? 8b 4d d8 0f b6 94 11 ?? ?? ?? ?? 03 c2 33 d2 b9 00 01 00 00 f7 f1 8b 45 d8 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DC_2147796653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DC!MTB"
        threat_id = "2147796653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 0f b6 c0 66 2b c3 66 83 c0 09 0f b7 d0 8b 44 24 20 05 9c c1 0d 01 89 54 24 0c 89 01 83 c1 04 a3 ?? ?? ?? ?? a0 ?? ?? ?? ?? 2a c2 89 4c 24 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DD_2147796672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DD!MTB"
        threat_id = "2147796672"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 24 20 8b df 2a c1 89 1d ?? ?? ?? ?? 8b 4c 24 0c 04 53 02 c6 8b 09 81 c1 3c 36 0e 01 89 0d ?? ?? ?? ?? 8b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DE_2147796762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DE!MTB"
        threat_id = "2147796762"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 cb 8b c1 0f af 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 04 11 8d 04 45 4a 00 00 00 a3 ?? ?? ?? ?? 8d 04 32 81 c5 34 b2 08 01 66 03 d8 89 2d ?? ?? ?? ?? 8b 44 24 14 66 89 1d ?? ?? ?? ?? 89 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DF_2147796763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DF!MTB"
        threat_id = "2147796763"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c6 99 8b c8 89 3d ?? ?? ?? ?? 0f a4 ca 01 8b 54 24 34 8d 46 fd 03 c9 83 c1 bb 8d 04 41 0f b7 c0 89 44 24 40 8b 02 05 a8 f8 02 01 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DG_2147796851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DG!MTB"
        threat_id = "2147796851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 2b ca 81 3d ?? ?? ?? ?? d2 0c 00 00 8d 51 fa 75 ?? 81 ef d2 0c 00 00 8d 0c 17 8d 14 4d ?? ?? ?? ?? 8b 74 24 0c 8b 4c 24 20 83 44 24 0c 04 81 c1 64 12 02 01 89 0d ?? ?? ?? ?? 89 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_YZ_2147797325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.YZ!MTB"
        threat_id = "2147797325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 5c 6b d2 47 0f b6 c3 2b c2 99 2b c8 19 15 ?? ?? ?? ?? eb 22 8b 44 24 5c 8a d8 6b c0 30 02 d9 80 eb 09 0f b6 cb 2b c1 99 88 1d ?? ?? ?? ?? 8b c8 89 15 ?? ?? ?? ?? 83 7c 24 24 08 89 0d ?? ?? ?? ?? 73 7a 66 0f b6 f3 66 6b f6 06 66 03 f1 0f b7 d6 8b c2 6b c0 60 3d 4f 21 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_SMK_2147797326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.SMK!MTB"
        threat_id = "2147797326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 6c 24 20 2f 8b d7 6b d2 2f 8b d9 2b da b2 26 f6 ea 66 03 f3 8a d8 2a 5c 24 14 66 89 35 ?? ?? ?? ?? 88 1d ?? ?? ?? ?? 8b c5 6b c0 03 83 e8 08 81 7c 24 10 87 00 00 00 99 a3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 77 40 66 0f b6 cb 8d 04 3f 66 03 c1 66 03 c6 b9 fb 79 00 00 66 2b c1 [0-32] b1 26 f6 e9 8b 0d ?? ?? ?? ?? 2a c3 8a d8 88 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 6b c0 26 2b 44 24 1c 0f b7 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CT_2147805839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CT!MTB"
        threat_id = "2147805839"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 47 3c 03 c7 0f b7 50 06 0f b7 70 14 6b d2 28 81 f1 0e 15 00 00 0f b7 c9 03 d0 89 4d f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CR_2147811318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CR!MTB"
        threat_id = "2147811318"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2b 75 dc 03 c6 89 01 8b f7 83 c1 04 eb 07 c7 45 f4 01 00 00 00 ff 4d f4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GBC_2147811346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GBC!MTB"
        threat_id = "2147811346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 16 85 d2 89 55 ec 74 19 ff 45 08 8a 4d 08 33 d7 8b 7d ec 33 d0 d3 ca 89 16 83 c6 04 ff 4d f4 75 de}  //weight: 10, accuracy: High
        $x_10_2 = {8a cb d3 c0 33 c6 33 45 0c 8b f0 89 32 83 c2 04 ff 4d 08 75 ce}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CM_2147811657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CM!MTB"
        threat_id = "2147811657"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {a5 a5 a5 8b 4d d0 33 4d d4 68 00 04 00 00 2b 4d fc 03 4d ec 8d 4c 11 ff 8b 55 f8}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GU_2147812810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GU!MTB"
        threat_id = "2147812810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2a c1 2a c1 04 5a 34 37 32 c1 34 37 2a c1 04 5a c0 c0 07 c0 c0 07 2a c1 2a c1 34 37 c0 c0 07 c0 c8 07 2c 5a aa 4a 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ME_2147812925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ME!MTB"
        threat_id = "2147812925"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 c0 49 b9 b5 a6 ff ff bf b1 ff ff ff 2b fa 2b f9 8d 14 2e 03 c7 83 fa 36}  //weight: 5, accuracy: High
        $x_5_2 = {8b 5c 24 10 81 c5 84 28 41 01 89 2b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_NC_2147813645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.NC!MTB"
        threat_id = "2147813645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 c8 89 4c 24 18 8b 4c 24 10 83 d5 00 0f b6 c1 0f b6 ca 0f af c8 89 6c 24 20 89 4c 24 10 8b c1 8b 4c 24 18 2a c1 89 44 24 10}  //weight: 10, accuracy: High
        $x_3_2 = "little-shore\\358\\Level.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_K_2147815877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.K"
        threat_id = "2147815877"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 2c 24 d3 cc d5 05 c3}  //weight: 1, accuracy: High
        $x_1_2 = "d:\\in\\the\\town\\where\\ahung.pdb" ascii //weight: 1
        $x_1_3 = "malexgatheredNmoveth.manbeast2very" ascii //weight: 1
        $x_1_4 = "CT$yhrtgfdr4hery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ESG_2147816501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ESG!MSR"
        threat_id = "2147816501"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d:\\in\\the\\town\\where\\ahung.pdb" ascii //weight: 1
        $x_1_2 = "movethmeatmanfifthyieldinglseasons.Vair" wide //weight: 1
        $x_1_3 = "zmfifthtsaying,KCattlebeastmoved.B" ascii //weight: 1
        $x_1_4 = "SeedlandsforWfacevoid" wide //weight: 1
        $x_1_5 = "CT$yhrtgfdr4hery" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_XB_2147817124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.XB!MTB"
        threat_id = "2147817124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 89 e5 56 8a 45 14 8b 4d 10 8b 55 0c 8b 75 08 8a 24 0a 34 ff 00 c4 88 24 0e 5e 5d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DJ_2147828590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DJ!MTB"
        threat_id = "2147828590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CT$yhrtgfdr4hery" ascii //weight: 1
        $x_1_2 = "yPtnHMg.pdb" ascii //weight: 1
        $x_1_3 = "yisgland.m" ascii //weight: 1
        $x_1_4 = "CattleclesserqmeQ" ascii //weight: 1
        $x_1_5 = "giveletdon.ttwo.p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CA_2147828759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CA!MSR"
        threat_id = "2147828759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AKqFNOgxbVvgJcYrSDX" ascii //weight: 2
        $x_2_2 = "AiwQGLrtZHXUjGdA" ascii //weight: 2
        $x_2_3 = "BOhrJinzrmYQ" ascii //weight: 2
        $x_2_4 = "CdgtDopAnEZoanbNGJgb" ascii //weight: 2
        $x_2_5 = "GNrIveueCrnLUKHIjO" ascii //weight: 2
        $x_2_6 = "HgLzPyBoLNLRvIdRQgQdJ" ascii //weight: 2
        $x_2_7 = "NlZZBGOvenpSFH" ascii //weight: 2
        $x_2_8 = "OFXtCZRvfaTKHwvzA" ascii //weight: 2
        $x_2_9 = "OsFOIohVlqSPPrKEcYL" ascii //weight: 2
        $x_2_10 = "PTYJcdmHNPBGwowPFDnxc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_EB_2147836523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.EB!MTB"
        threat_id = "2147836523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 c0 0f b6 4d e7 c1 e9 04 0f b6 d0 83 e2 0f 33 ca c1 e8 04 33 04 8b 89 45 c0 eb c5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_EB_2147836523_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.EB!MTB"
        threat_id = "2147836523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 1c 00 00 89 35 ?? ?? ?? ?? 81 25 ?? ?? ?? ?? 70 02 00 00 89 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? 81 35 ?? ?? ?? ?? e0 30 00 00 89 2d ?? ?? ?? ?? 81 35 ?? ?? ?? ?? 5b 18 00 00 89 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_LK_2147843781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.LK!MTB"
        threat_id = "2147843781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 4d fc 0d 8b 45 08 0f b6 00 3c 60 7e 0e 8b 45 08 0f b6 00 0f be c0 83 e8 20 eb 09 8b 45 08 0f b6 00 0f be c0 01 45 fc 83 45 08 01 8b 45 08 0f b6 00 84 c0 75 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXB_2147850008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXB!MTB"
        threat_id = "2147850008"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b 71 14 8b d6 2b d0 2b 54 24 08 8a 12 88 16 8d 50 01 01 51 14 83 ca ff 2b d0 01 54 24 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_DK_2147850207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.DK!MTB"
        threat_id = "2147850207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {83 7d 10 00 8b 07 89 45 f8 74 04 85 c0 74 1c 33 45 fc 43 33 45 0c 8a cb d3 c8 8b 4d f8 83 c7 04 89 4d fc 89 06 83 c6 04 4a 75}  //weight: 4, accuracy: High
        $x_1_2 = {8d 34 08 33 75 e8 68 00 30 00 00 33 75 ec 50 6a 00 83 c6 0e ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNL_2147851358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNL!MTB"
        threat_id = "2147851358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 8b c6 2b fe 8a 14 07 32 55 0c 88 10 40 49 75 f4}  //weight: 10, accuracy: High
        $x_10_2 = {33 45 fc 43 33 45 0c 8a cb d3 c8 8b 4d f8 83 c7 04 89 4d fc 89 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNM_2147851368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNM!MTB"
        threat_id = "2147851368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b 71 04 8b d6 2b d0 2b 54 24 08 8a 12 88 16 8d 50 01 01 51 04 83 ca ff 2b d0 01 54 24 0c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNO_2147851459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNO!MTB"
        threat_id = "2147851459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 11 8b de 2b df 03 d3 89 11 83 c1 ?? 48 8b fa}  //weight: 10, accuracy: Low
        $x_10_2 = {69 c0 0d 66 19 00 05 5f f3 6e 3c a3 ?? ?? ?? ?? 0f b7 c0 6a 19 99 5b f7 fb 80 c2 61 88 14 31 41 3b cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNP_2147851576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNP!MTB"
        threat_id = "2147851576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 c8 0f b6 d3 83 e1 0f c1 ea 04 33 ca c1 e8 04 33 04 8e 83 7d fc}  //weight: 10, accuracy: High
        $x_10_2 = {35 40 8c fa ae 8b 0f 8b 56 f4 03 4d 08 89 45 fc}  //weight: 10, accuracy: High
        $x_1_3 = "269e3863.dll" ascii //weight: 1
        $x_1_4 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNQ_2147851639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNQ!MTB"
        threat_id = "2147851639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 10 0f b6 04 97 66 31 04 91 8b 54 24 20 8a ca 8b 44 24 14 80 f1 69 02 4c 70 0a}  //weight: 10, accuracy: High
        $x_1_2 = "stwn404ya13.dll" ascii //weight: 1
        $x_1_3 = "PFrdne5RL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_Z_2147891360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.Z!MTB"
        threat_id = "2147891360"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b d0 0f b6 8a ?? ?? ?? ?? 8b 45 ?? 99 be ?? ?? ?? ?? f7 fe 03 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 0f be 94 02 ?? ?? ?? ?? 33 ca 8b 45}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_Y_2147893824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.Y!MTB"
        threat_id = "2147893824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d3 c0 83 f3 ?? 89 02 83 c2}  //weight: 2, accuracy: Low
        $x_2_2 = {d3 e0 83 c7 ?? 03 d8 4e 85 f6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_ASF_2147895374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.ASF!MTB"
        threat_id = "2147895374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 69 74 2e 64 6c 6c 00 42 72 65 61 6b 67 6f 6f 64 00 42 72 69 67 68 74 00 43 6f 61 73 74 6d 69 6e 64 00 53 6f 6c 64 69 65 72 6d 61 67 6e 65 74 00 53 79 6d 62 6f 6c 73 6c 69 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_X_2147897076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.X!MTB"
        threat_id = "2147897076"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 03 0a 0f b7 d9 0f af c3 03 c7 66 3b 0d}  //weight: 2, accuracy: High
        $x_2_2 = {f6 eb 49 8a d9 2a d8 8a c3 8a 1c 2e 88 1e 0f b6 d8 2b df 46 8d 54 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BZ_2147897298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BZ!MTB"
        threat_id = "2147897298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d3 c1 ca ?? 83 c4 ?? 03 d6 03 d0 03 fa 33 df}  //weight: 2, accuracy: Low
        $x_2_2 = {8b d7 c1 ca ?? 03 d6 03 d0 8b 45 ?? 03 da 33 fb 89 7d}  //weight: 2, accuracy: Low
        $x_2_3 = {8b c2 c1 e8 ?? 03 c2 6b c0 ?? 2b c8 8a b9 ?? ?? ?? ?? 32 fb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Ursnif_BY_2147898623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BY!MTB"
        threat_id = "2147898623"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 54 24 34 8b f5 8b 81 c4 00 00 00 81 f6 ?? ?? ?? ?? 8b 6c 24 20 8b 7c 24 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNF_2147900203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNF!MTB"
        threat_id = "2147900203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b ca 0f b6 85 ?? ?? ?? ?? 03 c1 88 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 2b 8d ?? ?? ?? ?? 8b 55 ?? 8d 44 11 ?? 33 85 ?? ?? ?? ?? 88 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GMZ_2147900512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GMZ!MTB"
        threat_id = "2147900512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c8 33 d1 8b 45 ?? 8b 8d ?? ?? ?? ?? 03 14 81 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 0f b6 4d ?? 03 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXA_2147902939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXA!MTB"
        threat_id = "2147902939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 0b fb 33 f7 8b 7d 08 23 7d f4 8b df 23 de 33 d9 89 9a ?? ?? ?? ?? 23 45 0c 33 7d f8 33 45 fc 8b 9a ?? ?? ?? ?? 0b fe 33 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXZ_2147903359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXZ!MTB"
        threat_id = "2147903359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 4d fc 8b 45 f8 8b 00 83 e1 01 c1 e1 03 d3 e0 01 05 ?? ?? ?? ?? ff 4d fc ?? ?? ff 75 f4 ff 15 ?? ?? ?? ?? ff 75 fc 83 45 f8 04 ff 75 f4 ff 15 ?? ?? ?? ?? 3d 02 01 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXZ_2147903359_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXZ!MTB"
        threat_id = "2147903359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {88 4d fb 0f b6 45 fb 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 0f be 11 33 d0 a1 38 20 45 00 03 85 ?? ?? ?? ?? 88 10 e9 ?? ?? ?? ?? 83 3d f8 21 45 00 3e ?? ?? a1 ?? ?? ?? ?? c6 40 10 46 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXY_2147903466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXY!MTB"
        threat_id = "2147903466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cf 8b c7 c1 e9 ?? 03 4d ?? c1 e0 ?? 03 45 ?? 33 c8 8d 04 3e 33 c8 2b d9 8b cb 8b c3 c1 e9 ?? 03 4d ?? c1 e0 ?? 03 45 ?? 33 c8 8d 04 1e 33 c8 8d b6 47 86 c8 61 2b f9 ff 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CCHU_2147903510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CCHU!MTB"
        threat_id = "2147903510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 55 f8 52 8b 45 f8 50 8b 4d 08 51 8b 15 ?? ?? ?? ?? 52 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXN_2147903518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXN!MTB"
        threat_id = "2147903518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b7 14 41 0f be 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f be 8d ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 2b f1 33 c6 03 d0 a1 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 10 0f b6 4d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GXV_2147903530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GXV!MTB"
        threat_id = "2147903530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 24 17 00 08 33 48 1a 24 48 48 24 83 4c ff cc 10 4c c4 83 60 3b cc 8b 4c 20 cc 04 00 48 00 61 93 cc 24 8b 00 09}  //weight: 5, accuracy: High
        $x_5_2 = {30 58 17 24 cc b0 48}  //weight: 5, accuracy: High
        $x_1_3 = "Towarddifficult" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_RDD_2147903590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.RDD!MTB"
        threat_id = "2147903590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 43 01 99 8b f8 8b da 8b 54 24 24 03 fd}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_GNT_2147904526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.GNT!MTB"
        threat_id = "2147904526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c1 35 83 f1 1a 0f b7 95 ?? ?? ?? ?? 0f b7 85 ?? ?? ?? ?? 2b d0 0b ca 88 4d ?? 83 3d ?? ?? ?? ?? 64}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_FU_2147906789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.FU!MTB"
        threat_id = "2147906789"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hecoxi ripokenegahoku gole rejonopijeyi birufuye" ascii //weight: 1
        $x_1_2 = "Kovutemipi gocu" ascii //weight: 1
        $x_1_3 = "Kotixawoyugukufo vifatozomabemu fi juyo pexazikixinoco yozepigepuya diru" ascii //weight: 1
        $x_1_4 = "Fovecotireto pagojeroyipa rocowodoko soki wugariyeyo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_MBXV_2147924161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.MBXV!MTB"
        threat_id = "2147924161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 61 62 34 32 39 6b 6f 32 37 2e 64 6c 6c 00 48 65 6a 61 63 38 35 54 00 56 69 73 69 62 6c 65 45 6e 74 72 79 00 58 50 4f 75 51 33 36}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_OKA_2147929800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.OKA!MTB"
        threat_id = "2147929800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 53 68 04 22 41 00 ff 15 ?? ?? ?? ?? eb ?? 33 db 83 ee 01 78 0d e8 a6 ed ff ff 30 04 37 83 ee 01 79}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_CCJT_2147931448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.CCJT!MTB"
        threat_id = "2147931448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 44 24 14 8b 16 02 c3 0f b6 c8 8b 44 24 10 d3 ca 33 d0 2b d3 89 16 83 c6 04 4b 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BAA_2147934830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BAA!MTB"
        threat_id = "2147934830"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 31 0f af f8 8d 50 ?? 89 15 ?? ?? ?? ?? 8d 50 ?? 81 c6 ?? ?? ?? ?? 2b c2 8d 84 00 ?? ?? ?? ?? 89 31 2b fa 83 c1 04 83 eb 01 a3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_BAB_2147934834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.BAB!MTB"
        threat_id = "2147934834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 c0 2b c6 89 94 29 ?? ?? ?? ?? 8d 44 07 3f 8b 3d ?? ?? ?? ?? 83 c1}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ursnif_NU_2147956621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ursnif.NU!MTB"
        threat_id = "2147956621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ursnif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d6 2b d1 2b c5 83 c2 ?? 3b d7 8b e8 89 2d ?? ?? ?? 00 75 0c 8b c7 69 c0 ?? ?? 00 00 2b c6 8b f0}  //weight: 2, accuracy: Low
        $x_1_2 = {33 c9 85 f6 0f 94 c1 85 c9 74 2b b8 ?? ?? ?? ?? f7 e6 c1 ea 05 3b fa 74 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

