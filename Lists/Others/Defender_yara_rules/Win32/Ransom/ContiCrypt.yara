rule Ransom_Win32_ContiCrypt_PA_2147771596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PA!MTB"
        threat_id = "2147771596"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\conti_v3\\x64\\Release\\cryptor_dll.pdb" ascii //weight: 1
        $x_1_2 = "all of the data that has been encrypted by our software cannot be recovere" ascii //weight: 1
        $x_1_3 = "you to decrypt 2 random files completely free of charge" ascii //weight: 1
        $x_1_4 = ".PKVDT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PB_2147781238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PB!MTB"
        threat_id = "2147781238"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 53 0f b6 06 46 85 c0 74 ?? 51 ?? c7 04 e4 ?? ?? ?? ?? 59 bb ?? ?? ?? ?? 8b d6 c7 45 fc ?? ?? ?? ?? d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 [0-4] 8b c3 [0-4] aa 49 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cf 23 4d ?? 75 ?? 46 8b 45 ?? 0f b6 1c 30 8b 55 ?? d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_ContiCrypt_PD_2147781565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PD!MTB"
        threat_id = "2147781565"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45 ?? ?? c6 45}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 c0 2b c8 8b c1 c1 e0 ?? 2b c1 03 c0 99 f7 ff 8d 42 ?? 99 f7 ff 88 54 35 ?? 46 83 fe ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_MFP_2147782230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.MFP!MTB"
        threat_id = "2147782230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 b8 09 04 02 81 83 c1 7f f7 e9 03 d1 c1 fa 06 8b c2 c1 e8 1f 03 d0 6b c2 7f 2b c8 42 88 4c 05}  //weight: 5, accuracy: High
        $x_5_2 = {88 5d c7 c6 45 c8 ?? c6 45 c9 ?? c6 45 ca ?? c6 45 cb ?? c6 45 cc ?? ?? ?? ?? ?? c6 45 ce ?? c6 45 cf ?? c6 45 d0 ?? c6 45 d1 ?? c6 45 d2 ?? c6 45 d3 ?? c6 45 d4 ?? 48 89 45 6f 0f b6 45 c8 0f b6 45 c7}  //weight: 5, accuracy: Low
        $x_5_3 = {c6 45 88 67 c6 45 89 33 c6 45 8a 5f c6 45 8b 2d c6 45 8c 6c c6 45 8d 5f c6 45 8e 2b c6 45 8f 6e c6 45 90 57 c6 45 91 57 c6 45 92 50 0f b6 4d 88 48 89 45 67 0f b6 45 87}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_ContiCrypt_PH_2147782626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PH!MTB"
        threat_id = "2147782626"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb 8b 44 8c ?? 33 c6 89 44 8c ?? 41 83 f9 ?? 72 ?? 8d 44 24 ?? 50 53 53 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8b cb 8b 44 8c ?? 35 a5 43 07 6f 89 44 8c ?? 41 83 f9 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_KRT_2147793633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.KRT!MTB"
        threat_id = "2147793633"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 f8 33 45 f8 0b 47 10 83 e1 00 31 c1 8b 45 f8 03 77 14 8b 7f 0c 03 bb 58 f0 44 00 f3 a4 81 e7 00 00 00 00 03 3c e4}  //weight: 5, accuracy: High
        $x_5_2 = {33 5d 0c 89 df 8b 5d f8 8f 45 f8 8b 4d f8 8f 45 f8 8b 75 f8 f3 a4 8f 45 f8 8b 7d f8 81 e6 00 00 00 00 33 34 e4}  //weight: 5, accuracy: High
        $x_1_3 = {d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_ContiCrypt_PI_2147811760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PI!MTB"
        threat_id = "2147811760"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 06 ac [0-128] 32 c1 32 c1 [0-128] 32 c1 32 c1 [0-32] 2a c1 aa 4a 0f 85 ?? ?? ?? ?? 8b ec 5d c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PK_2147811993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PK!MTB"
        threat_id = "2147811993"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 06 ac 04 [0-64] 32 c1 32 c1 [0-64] 32 c1 2a c1 2a c1 [0-144] aa 4a 0f 85 [0-4] 8b ec 5d c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PADD_2147812342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PADD!MTB"
        threat_id = "2147812342"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e8 8b 08 8b 55 f0 8d 44 11 02 89 45 c0 8b 4d c0 51 8b 55 d4 52 ff 15 ?? ?? ?? ?? 8b 4d e0 89 01 8b 55 e0 83 c2 04 89 55 e0 8b 45 e8 83 c0 04}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 75 98 89 55 b8 33 d0 8b 45 ac 03 45 80 33 f0 89 45 ac 8b 45 b0 c1 c6 10 03 c6 c1 c2 07 89 45 b0 33 45 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_ContiCrypt_PL_2147812509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PL!MTB"
        threat_id = "2147812509"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 ?? ac}  //weight: 1, accuracy: Low
        $x_1_2 = {aa 4a 0f 85 [0-4] 8b ec 5d c2 0c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_CEDD_2147813078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.CEDD!MTB"
        threat_id = "2147813078"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 4d 08 89 4d f8 8b c5}  //weight: 1, accuracy: High
        $x_1_2 = {bb 32 00 00 00 33 5d 18 83 c3 3a 89 5d 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_AA_2147814437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.AA!MTB"
        threat_id = "2147814437"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 04 08 30 04 1f 8b 45 ?? 2b c6 48 23 c2 8b d1 8a 04 10 30 04 1f eb 30 00 8d 46 ?? 23 c2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_CRP_2147814586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.CRP!MTB"
        threat_id = "2147814586"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 90 88 07 46 47 90 49 90 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_LOD_2147814587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.LOD!MTB"
        threat_id = "2147814587"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c2 33 d2 bb 00 04 00 00 f7 f3 42 81 c2 00 02 00 00 33 c9 0f c8 93 0f cb 87 de 0f ce 87 f7 0f cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_SEL_2147814588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.SEL!MTB"
        threat_id = "2147814588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 03 34 9c 88 07}  //weight: 1, accuracy: High
        $x_1_2 = {b2 2f 32 ca 90 8a 06 90 32 c2 88 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_ContiCrypt_PM_2147814605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PM!MTB"
        threat_id = "2147814605"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 89 45 ?? 8b 4d ?? 3b 4d ?? 73 ?? 8b 55 ?? 03 55 ?? 0f b6 0a 8b 45 ?? 33 d2 be 0f 00 00 00 f7 f6 33 4c 95 ?? 8b 55 ?? 03 55 ?? 88 0a eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_OR_2147814738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.OR!MTB"
        threat_id = "2147814738"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 90 88 07 90 46 47}  //weight: 1, accuracy: High
        $x_1_2 = {8a 03 34 95 88 07 43 47}  //weight: 1, accuracy: High
        $x_1_3 = {8a 07 90 32 c2 0f b6 4f 01 90 32 ca 3c 01 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_ContiCrypt_RER_2147814740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.RER!MTB"
        threat_id = "2147814740"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 88 07 46 90 47 49}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_RES_2147814741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.RES!MTB"
        threat_id = "2147814741"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 03 90 34 a8 88 07 90 43 47 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_RE_2147815097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.RE!MTB"
        threat_id = "2147815097"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 90 88 07 90 46 90 47 90 49 83 f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_REL_2147815521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.REL!MTB"
        threat_id = "2147815521"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c0 2b c8 6b c1 ?? 99 f7 fb 8d 42 7f 99 f7 fb 88 54 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PN_2147816336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PN!MTB"
        threat_id = "2147816336"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 [0-48] 5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 63 00 6f 00 70 00 79 00 20 00 77 00 68 00 65 00 72 00 65 00 [0-32] 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "readme.txt" wide //weight: 1
        $x_1_3 = "CONTI_LOG.txt" wide //weight: 1
        $x_1_4 = {5c 63 6f 6e 74 69 5f 76 33 5c [0-32] 5c 63 72 79 70 74 6f 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PO_2147816380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PO!MTB"
        threat_id = "2147816380"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 03 8d ?? ?? c1 e1 02 2b c1 8b 4d ?? 0f b6 44 ?? ?? 8d 0c 19 30 03 8d 5b 04 b8 ?? ?? ?? ?? f7 ?? 8b 4d ?? c1 ea 03 8d 04 ?? c1 e0 02 2b f0 0f b6 44 ?? ?? 30 43 fd 8d 04 ?? 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_ContiCrypt_PP_2147908377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/ContiCrypt.PP!MTB"
        threat_id = "2147908377"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "ContiCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 ea 03 8d 04 ?? c1 e0 02 2b f0 0f b6 44 ?? ?? 30 [0-4] 8d 04 ?? 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

