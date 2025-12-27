rule Ransom_Win32_Crysis_DA_2147730469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.DA!MTB"
        threat_id = "2147730469"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILES ENCRYPTED.txt" ascii //weight: 1
        $x_1_2 = "TouchMeNot_.txt" ascii //weight: 1
        $x_1_3 = "@aol.com" ascii //weight: 1
        $x_1_4 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crysis_PA_2147733944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.PA!MTB"
        threat_id = "2147733944"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 00 00 00 00 83 04 24 04 8a 44 24 14 8b 4c 24 08 8a d0 80 e2 f0 02 d2 02 d2 08 11 8b 0c 24 8a d0 d2 e2 8b 4c 24 0c c0 e0 06 80 e2 c0 08 11 8b 4c 24 10 08 01 59 c2 10 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 11 0f b6 0c 1a 8d 04 1a 0f b6 50 01 88 54 24 ?? 0f b6 50 03 88 4c 24 ?? 0f b6 48 02 52 8d 44 24 ?? 88 4c 24 ?? 50 8d 4c 24 ?? 51 8d 54 24 ?? 52 e8 ?? ?? ?? ?? 8a 44 24 ?? 0f b6 4c 24 ?? 0f b6 54 24 ?? 88 04 3e 46 88 0c 3e 46 88 14 3e}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 0a 0f b6 54 29 01 8a 04 29 03 cd 88 54 24 ?? 0f b6 51 02 88 54 24 ?? 8a 51 03 89 5c 24 ?? 83 44 24 ?? 02 89 5c 24 ?? 83 44 24 ?? 04 8b 4c 24 ?? 8a da d2 e3 8b 4c 24 ?? 80 e3 c0}  //weight: 1, accuracy: Low
        $x_1_4 = {0a d8 8a c2 d2 e0 c0 e2 06 0a 54 24 ?? 88 1c 3e 24 c0 0a 44 24 ?? 80 ea 02 88 44 3e 01 88 54 24 ?? 80 44 24 ?? 02 8a 4c 24 ?? 8b 44 24 ?? 88 4c 3e 02 83 c5 04 83 c6 03 3b 28 72}  //weight: 1, accuracy: Low
        $x_1_5 = {8a 14 08 88 55 ?? 8b 45 ?? 8b 08 8b 55 ?? 8a 44 11 01 88 45 ?? 8b 4d ?? 8b 11 8b 45 ?? 8a 4c 02 02 88 4d ?? 8b 55 ?? 8b 02 8b 4d ?? 8a 54 08 03 88 55 ?? 0f b6 45 ?? 0f b6 4d ?? c1 e1 02}  //weight: 1, accuracy: Low
        $x_1_6 = {81 e1 c0 00 00 00 0b c1 88 45 ?? 0f b6 55 ?? 0f b6 45 ?? c1 e0 04 25 c0 00 00 00 0b d0 88 55 ?? 0f b6 4d ?? 0f b6 55 ?? c1 e2 06 81 e2 c0 00 00 00 0b ca 88 4d ?? [0-3] 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08 8b 55 ?? 83 c2 01 89 55 ?? 8b 45 ?? 03 45 ?? 8a 4d ?? 88 08}  //weight: 1, accuracy: Low
        $x_1_7 = {8a d0 d2 e2 8b 4d ?? 80 e2 c0 08 11 [0-100] 8b 4d ?? 8a d0 80 e2 ?? c0 e2 04 08 11 [0-100] 8b 4d ?? d2 e0 8b 4d ?? 24 c0 08 01}  //weight: 1, accuracy: Low
        $x_1_8 = {8a 08 88 4d ?? 8a 48 01 88 4d ?? 8a 48 02 0f b6 40 03 50 8d 45 ?? 50 8d 45 ?? 50 8d 45 ?? 50 88 4d ?? e8 ?? ?? ?? ?? 8a 45 ?? 83 45 ?? 04 88 04 3e 8a 45 ?? 83 c4 10 46 88 04 3e 8a 45 ?? 46 88 04 3e}  //weight: 1, accuracy: Low
        $x_1_9 = {8a d8 d2 e3 80 e3 c0 08 1a [0-100] 8a c8 80 e1 fc c0 e1 04 08 0f [0-100] 8b 4d ?? d2 e0 5b 24 c0 08 06}  //weight: 1, accuracy: Low
        $x_1_10 = {8a 08 88 4d ?? 8a 48 01 88 4d ?? 8a 48 02 8a 40 03 8d 75 ?? 8d 7d ?? 8d 55 ?? 88 4d ?? e8 ?? ?? ?? ?? 8b 45 ?? 8a 4d ?? 83 45 ?? 04 88 0c 03 8a 4d ?? 43 88 0c 03 8a 4d ?? 43 88 0c 03}  //weight: 1, accuracy: Low
        $x_1_11 = {33 c9 8b 54 24 ?? 8b 02 0f b6 5c 28 01 8a 14 28 03 c5 88 5c 24 ?? 0f b6 58 02 8a 40 03 88 5c 24 ?? 89 4c 24 ?? 83 44 24 ?? 02 89 4c 24 ?? 83 44 24 ?? 04 8b 4c 24 ?? 8a d8 d2 e3 8b 4c 24 ?? 46 46}  //weight: 1, accuracy: Low
        $x_1_12 = {80 e3 c0 0a da 8a d0 d2 e2 88 5c 3e ?? 8b 5c 24 ?? c0 e0 06 0a 44 24 ?? 80 e2 c0 0a 54 24 ?? 83 c5 04 88 54 3e ?? 88 04 3e 46 3b 2b 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_Win32_Crysis_PB_2147750231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.PB!MTB"
        threat_id = "2147750231"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 ff 69 04 00 00 75 ?? 6a 00 ff d3 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 [0-32] ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d 08 30 04 0e 46 3b f7 7c}  //weight: 10, accuracy: Low
        $x_1_2 = {69 c9 fd 43 03 00 89 0d ?? ?? ?? ?? 81 05 ?? ?? ?? ?? c3 9e 26 00 81 3d ?? ?? ?? ?? a5 02 00 00 8b 35 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crysis_CX_2147753837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.CX!MTB"
        threat_id = "2147753837"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 00 8d 85 7c bf ff ff 50 6a 05 6a 01 ff b5 58 f8 ff ff ff b5 74 f8 ff ff ff 15 78 22 42 00 8b 85 64 f4 ff ff 03 85 90 bf ff ff 8a 8d 8f bf ff ff 88 08 e9 70}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 89 4d fc 8b 45 fc 8b 00 03 45 08 c9 c2 04 00 55 8b ec 51 51 89 4d f8 ff 75 08 e8 6d 30 00 00 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crysis_A_2147762504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.A!hoa"
        threat_id = "2147762504"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "hoa: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\crysis\\Release\\PDB\\payload.pdb" ascii //weight: 1
        $x_1_2 = {8b 4d 0c 03 4d ?? 0f b6 11 0f b6 45 ?? 0f b6 4d ?? 03 c1 0f b6 c0 8b 4d ?? 0f b6 04 01 33 d0 8b 4d ?? 03 4d ?? 88 11 e9}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 0c 03 45 ?? 0f b6 08 0f b6 55 ?? 0f b6 45 ?? 03 d0 0f b6 d2 8b 45 ?? 0f b6 14 10 33 ca 8b 45 ?? 03 45 ?? 88 08 8b 4d ?? 03 4d ?? 0f b6 11 85 d2 75 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? eb ?? c7 45 ?? ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crysis_MK_2147775739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.MK!MTB"
        threat_id = "2147775739"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_3 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_4 = "FILES ENCRYPTED.txt" ascii //weight: 1
        $x_1_5 = "all your data has been locked us" ascii //weight: 1
        $x_1_6 = "Total Encrypted Files :" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Crysis_MKV_2147954317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crysis.MKV!MTB"
        threat_id = "2147954317"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crysis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 f8 8d 8f 00 72 01 00 8d 74 26 00 30 10 30 50 01 83 c0 02 39 c8 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

