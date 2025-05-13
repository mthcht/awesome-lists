rule Ransom_Win32_Basta_C_2147818215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.C"
        threat_id = "2147818215"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your data are stolen and encrypted" ascii //weight: 1
        $x_1_2 = "The data will be published on TOR website if you do not pay the ransom" ascii //weight: 1
        $x_1_3 = "Your company id for log in:" ascii //weight: 1
        $x_1_4 = "You can contact us and decrypt one file for free" ascii //weight: 1
        $x_2_5 = {2e 00 62 00 61 00 73 00 74 00 61 00 00 00 02 66 00 61 00 78 00}  //weight: 2, accuracy: Low
        $x_2_6 = {62 00 6f 00 6f 00 74 00 [0-16] 72 00 65 00 61 00 64 00 6d 00 65 00 2e 00 74 00 78 00 74 00 [0-48] 2e 00 6a 00 70 00 67 00}  //weight: 2, accuracy: Low
        $x_2_7 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Basta_AA_2147818219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AA"
        threat_id = "2147818219"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {8b 7d 08 be 01 00 00 00 c6 07 69 8d 45 08 50 e8 ?? ?? ?? ?? 8a 45 08 83 c4 04 88 04 3e 46 83 fe 28 72 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AA_2147819836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AA!MTB"
        threat_id = "2147819836"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c1 8b 4d ?? 8a 44 08 ?? 32 46 ?? 8b 4d ?? 89 55 ?? 88 41 ?? 8b ca 8b 47 ?? 40 0f af 07 c1 e0 ?? 3b d8 0f 8c}  //weight: 10, accuracy: Low
        $x_1_2 = "networkexplorer.DLL" ascii //weight: 1
        $x_1_3 = "NlsData0000.DLL" ascii //weight: 1
        $x_1_4 = "NetProjW.DLL" ascii //weight: 1
        $x_1_5 = "Ghofr.DLL" ascii //weight: 1
        $x_1_6 = "fg122.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_D_2147832075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.D!ldr"
        threat_id = "2147832075"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 68 6f 66 72 2e 44 ?? 4c}  //weight: 1, accuracy: Low
        $x_1_2 = {66 67 31 32 32 2e 44 ?? 4c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_SA_2147834261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.SA"
        threat_id = "2147834261"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "basta" ascii //weight: 5
        $x_2_2 = "vssadmin.exe delete shadows" ascii //weight: 2
        $x_1_3 = "-bomb" ascii //weight: 1
        $x_1_4 = "-encryptionpercent" ascii //weight: 1
        $x_1_5 = "-threads" ascii //weight: 1
        $x_1_6 = "-nomutex" ascii //weight: 1
        $x_1_7 = "-forcepath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Basta_AB_2147834343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AB"
        threat_id = "2147834343"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {c7 45 f0 00 00 00 00 ff 75 10 83 ec 18 8b cc 89 65 10 ff 75 0c e8 ?? ?? ?? ?? c7 45 fc 01 00 00 00 ff 75 08 c6 45 fc 00 e8 ?? ?? ?? ?? 83 c4 20 c7 45 fc 00 00 00 00 (8b 4d f4 c7 45 f0 01 00 00 00 8b|c7 45 f0 01 00 00 00 8b 45 08 8b)}  //weight: 10, accuracy: Low
        $x_10_3 = {2b c2 d1 f8 83 f8 ff 0f 84 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 2b f0 83 fe 03 [0-6] 83 ff 08 8d 4d d4 68 ?? ?? ?? ?? 0f 43 cb 83 c1 02 8d 34 41 56 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 ?? 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? ?? 83 c4 08 85 c0 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PA_2147835064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PA!MTB"
        threat_id = "2147835064"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 88 85 ?? ?? ?? ?? 0f b7 95 ?? ?? ?? ?? 0f b7 45 8c 2b d0 8b 8d ?? ?? ?? ?? 66 89 11 0f b6 55 87 33 95 ?? ?? ?? ?? 88 55 87 8b 45 f4 0f b6 08 8b 95 ?? ?? ?? ?? 0f b6 02 0b c8 88 4d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 fa 88 55 ?? 8b 8d ?? ?? ?? ?? 8b 11 8b 4d dc d3 e2 89 95 ?? ?? ?? ?? 8b 45 d0 33 45 b8 89 85 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 8b 11 23 55 d4 8b 45 c4 89 10 8b 0d ?? ?? ?? ?? 8b 55 d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Basta_PB_2147835450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PB!MTB"
        threat_id = "2147835450"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8b 1e 83 e1 ?? 8b 7e ?? 33 d8 8b 76 08 33 f8 33 f0 d3 cf d3 ce d3 cb 3b fe}  //weight: 1, accuracy: Low
        $x_1_2 = "Your network has been breached and all data was encrypted" ascii //weight: 1
        $x_1_3 = "access .onion website" ascii //weight: 1
        $x_1_4 = "cmd.exe /c start /MAX notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AC_2147836426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AC"
        threat_id = "2147836426"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {56 6a 00 6a 00 8b f1 56 68 ?? ?? ?? ?? 6a 00 6a 00 ff 15 ?? ?? ?? ?? 89 46 0c 5e c3}  //weight: 10, accuracy: Low
        $x_10_3 = {51 6a 10 e8 ?? ?? ?? ?? 83 c4 04 89 45 ?? [0-7] 85 c0 74 ?? 8b 4d 08 89 48 08 8b 4d 0c 89 48 04 8b 4d 10 89 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AF_2147840553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AF!MTB"
        threat_id = "2147840553"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7d 1a 8b 45 c4 03 45 d4 8b 4d ?? 8a 54 0d ?? 88 10 8b 45 d4 83 c0 01 89 45 d4 [0-32] 8b 55 f0 83 ?? 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f0 83 c2 01 89 55 f0 83 7d f0 03 7d 1a 8b 45 d0 03 45 e0 8b 4d f0 8a 54 0d e4 88 10 8b 45 e0 83 c0 01 89 45 e0 8b 55 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Basta_PE_2147840613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PE!MTB"
        threat_id = "2147840613"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e1 c1 ea ?? 69 c2 ?? ?? ?? ?? 2b c8 75 ?? ff d6 8b f8 ff d6 3b c7 74 f6 8b 4d fc 8b c1 99 f7 fb 8b 45 ?? 33 55 ?? 8a 04 02 30 81 ?? ?? ?? ?? 41 89 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_HW_2147841192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.HW!MTB"
        threat_id = "2147841192"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dfbjdfvslsd" ascii //weight: 1
        $x_1_2 = "vCyQODpLMmIYfIGTIJJviZvEimEbktcuAAZwLfOzShKtRqsboYFUoplxuXdiygQrE" ascii //weight: 1
        $x_1_3 = "E:\\cpp\\out\\out\\out.pdb" ascii //weight: 1
        $x_1_4 = "Defender update service local type" ascii //weight: 1
        $x_1_5 = "Copyright (c) 2003-2022 Glarysoft Ltd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Basta_DP_2147841845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.DP!MTB"
        threat_id = "2147841845"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AXRIKN.exe" ascii //weight: 1
        $x_5_2 = {b8 08 00 00 00 6b c8 00 8b 55 ec 8b 45 d4 8b 75 e8 8b 14 90 2b 14 0e 03 55 f0 89 55 d0 8b 45 d0 50 8b 4d 08 51}  //weight: 5, accuracy: High
        $x_1_3 = "JAOJNI.exe" ascii //weight: 1
        $x_5_4 = {8b 4d fc 83 c1 0e 89 4d fc 8b 55 f8 8b 42 08 89 45 f0 8b 4d f8 8b 51 08 8b 45 f0 03 50 3c 89 55 ec 8b 45 fc 99 2b c2 d1 f8 89 45 fc 8b 4d f8 8b 51 08 8b 45 ec 03 50 28 89 55 e8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Basta_PF_2147843640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PF!MTB"
        threat_id = "2147843640"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VisibleEntry" ascii //weight: 1
        $x_1_2 = {01 d0 0f b6 30 8b 4d e4 ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa 03 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 2b 29 c1 89 c8 89 c2 8b 45 e0 01 d0 0f b6 00 31 f0 88 03 83 45 e4 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_SDD_2147843645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.SDD!MTB"
        threat_id = "2147843645"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 75 08 e9 ?? ?? ?? ?? d1 e0 e9 ?? ?? ?? ?? 04 ?? e9 ?? ?? ?? ?? 5e e9 ?? ?? ?? ?? 8b ec e9 ?? ?? ?? ?? 32 02 e9 ?? ?? ?? ?? c9 e9 ?? ?? ?? ?? 6a 01 e9 ?? ?? ?? ?? 68 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 36}  //weight: 1, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_SDE_2147843646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.SDE!MTB"
        threat_id = "2147843646"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 02 e9 ?? ?? ?? ?? 8b 00 e9 ?? ?? ?? ?? 0f b7 4a ?? e9 ?? ?? ?? ?? 8b d0 e9 ?? ?? ?? ?? 32 02 e9 ?? ?? ?? ?? 8b d8 e9 ?? ?? ?? ?? 8d 73 ?? e9 ?? ?? ?? ?? 89 75 ?? e9 ?? ?? ?? ?? f7 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_CB_2147844274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.CB!MTB"
        threat_id = "2147844274"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 0d 30 00 00 00 8b 49 0c}  //weight: 1, accuracy: High
        $x_1_2 = {8b 49 0c 8b 09}  //weight: 1, accuracy: High
        $x_1_3 = {8d 51 30 8b 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PI_2147844965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PI!MTB"
        threat_id = "2147844965"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e9 05 29 c2 8a 06 46 c1 e0 05 29 c2 41 87 f2 f3 a4 89 d6 31 c0 8a 06 46 3c 20 0f 83 94 fc fb ff 08 c0 0f 84 [0-4] 89 c1 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_MKK_2147845734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.MKK!MTB"
        threat_id = "2147845734"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {bb af 00 00 00 e9 b0 96 fc ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b db e9 1b 83 06 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 4d 0c e9 42 70 fe ff}  //weight: 1, accuracy: High
        $x_1_4 = {fc e9 4e 8f fb ff}  //weight: 1, accuracy: High
        $x_1_5 = {ac e9 60 4a 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {02 c3 e9 47 36 01 00}  //weight: 1, accuracy: High
        $x_1_7 = {32 c3 e9 1b 8f fd ff}  //weight: 1, accuracy: High
        $x_1_8 = {8b ff e9 34 b3 01 00}  //weight: 1, accuracy: High
        $x_1_9 = {c0 c8 5f e9 92 bc 04 00}  //weight: 1, accuracy: High
        $x_1_10 = {aa e9 58 49 00 00}  //weight: 1, accuracy: High
        $x_1_11 = {8b d2 e9 85 3f f9 ff}  //weight: 1, accuracy: High
        $x_1_12 = {8b ed e9 ed ff ff ff}  //weight: 1, accuracy: High
        $x_1_13 = {49 e9 0b 34 05 00}  //weight: 1, accuracy: High
        $x_1_14 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AI_2147845799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AI!MTB"
        threat_id = "2147845799"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 08 8b fe bb ?? ?? ?? ?? 90 8b 4d ?? fc ac 90 02 c3 90 90 8b f6 32 c3 90 fc c0 c8 ?? aa fc 49 ac 90 02 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_MKZ_2147845826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.MKZ!MTB"
        threat_id = "2147845826"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ac 02 c3 e9 34 c9 fc ff}  //weight: 1, accuracy: High
        $x_1_2 = {fc 32 c3 e9 bc 6a ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {c0 c8 ee 90 e9 82 1f 03 00}  //weight: 1, accuracy: High
        $x_1_4 = {8b c0 90 e9 b9 17 fd ff}  //weight: 1, accuracy: High
        $x_1_5 = {aa 49 e9 44 14 02 00}  //weight: 1, accuracy: High
        $x_5_6 = "VisibleEntry" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PIA_2147846750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PIA!MTB"
        threat_id = "2147846750"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c e9 05 00 8b 4d 0c fc 8b e4 90 90 ac 02 c3 32 c3 c0 c8 3f aa 90 fc 90 8b c9 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PIB_2147847121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PIB!MTB"
        threat_id = "2147847121"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 34 18 a1 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 35 ?? ?? ?? ?? 03 c8 0f af de a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 35 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b cb c1 e9 10 88 0c 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AD_2147847453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AD!MTB"
        threat_id = "2147847453"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 39 74 24 ?? 76 ?? b8 ?? ?? ?? ?? 8b ce f7 ee c1 fa 03 8b c2 c1 e8 1f 03 c2 6b c0 ?? 2b c8 8b 44 24 ?? 8a 89 ?? ?? ?? ?? 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_SI_2147847577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.SI!MTB"
        threat_id = "2147847577"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d e0 8d 76 ?? b8 ?? ?? ?? ?? f7 ef 03 d7 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 6b c0 ?? 2b c8 8b 45 ?? 8a 8c 39 ?? ?? ?? ?? 32 8f ?? ?? ?? ?? 47 88 4c 06 ?? 3b 7d ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_B_2147847823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.B!ibt"
        threat_id = "2147847823"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "VisibleEntry" ascii //weight: 4
        $x_1_2 = {55 8b ec 83 ec 08 53 8b 1d ?? ?? ?? ?? 56 57 85 db 74 5b 8b 43 3c 83 7c 18 7c 00 74 51 8b 44 18 78 03 c3 89 45 f8 8b 48 18 85 c9 74 41 83 78 14 00 74 3b 8b 70 20 33 ff 8b 40 24 03 f3 03 c3 89 45 fc 85 c9 74 28 8b 06 03 c3 74 22 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 08 85 c0 74 1d 8b 45 f8 47 83 45 fc 02 83 c6 04 3b 78 18 72 d8 33 c0 ff d0 5f 5e 33 c0 5b 8b e5 5d c3 8b 45 fc 0f b7 08 8b 45 f8 8b 40 1c 8d 04 88 8b 04 18 03 c3 ff d0 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 5c 24 08 48 89 6c 24 10 48 89 74 24 18 57 41 56 41 57 48 83 ec 20 48 8b 0d ?? ?? ?? ?? 48 85 ff 74 78 48 63 47 3c 83 bc 38 8c 00 00 00 00 74 6a 8b ac 38 88 00 00 00 48 03 ef 8b 45 18 85 c0 74 59 83 7d 14 00 74 53 8b 75 20 33 db 44 8b 7d 24 48 03 f7 4c 03 ff 44 8b f3 85 c0 74 3f 90 8b 16 48 03 d7 74 37 48 8d 0d ?? ?? ?? ?? e8 b9 9b 02 00 85 c0 74 13 41 ff c6 48 83 c6 04 49 83 c7 02 44 3b 75 18 72 d8 eb 14 8b 45 1c 41 0f b7 0f 48 03 c7 8b 1c 88 48 03 df eb 02 33 db ff d3 48 8b 5c 24 40 33 c0 48 8b 6c 24 48 48 8b 74 24 50 48 83 c4 20 41 5f 41 5e 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Basta_AE_2147847937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AE!MTB"
        threat_id = "2147847937"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 14 01 a1 ?? ?? ?? ?? ff 80 ?? ?? ?? ?? 8b 47 ?? 33 87 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 35 ?? ?? ?? ?? 29 05 ?? ?? ?? ?? 8b 47 ?? 2d ?? ?? ?? ?? 0f af 41 ?? 89 41 ?? a1 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 47 ?? 31 82 ?? ?? ?? ?? 8b 87 ?? ?? ?? ?? 2b 87 ?? ?? ?? ?? 2d ?? ?? ?? ?? 0f af 47 ?? 89 47 ?? 8b 07 83 f0 ?? 29 47 ?? 8b 87 ?? ?? ?? ?? 35}  //weight: 1, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_CRUW_2147849327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.CRUW!MTB"
        threat_id = "2147849327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\git2\\Unicode Debug\\FingerText.pdb" ascii //weight: 3
        $x_2_2 = "VisibleEntry" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PIE_2147850035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PIE!MTB"
        threat_id = "2147850035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c3 c0 c8 ?? aa 49 fc ac fc fc fc 02 c3 8b d2 fc fc e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAA_2147897213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAA!MTB"
        threat_id = "2147897213"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c5 04 8b 82 9c 00 00 00 2d ?? ?? ?? ?? 31 87 dc 00 00 00 8b 87 94 00 00 00 83 e8 53 09 87 84 00 00 00 8b 47 4c 33 c1 83 e8 11}  //weight: 1, accuracy: Low
        $x_1_2 = {88 14 01 8b cb ff 47 3c 8b 57 3c 8b 47 60 c1 e9 08 88 0c 02 ff 47 3c 8b 4f 3c 8b 47 60 88 1c 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_MA_2147898646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.MA!MTB"
        threat_id = "2147898646"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 ca 58 2b c1 46 03 d0 89 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 1c 06 8b 15 ?? ?? ?? ?? 42 89 15 ?? ?? ?? ?? 81 fd 10 52 00 00 0f 8c}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c6 04 0f af 5d 38 8b 45 0c 2d ?? ?? ?? ?? 31 85 a0 00 00 00 8b 45 60 8b d3 c1 ea 08 88 14 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAB_2147902674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAB!MTB"
        threat_id = "2147902674"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 14 8b 91 ?? ?? ?? ?? 8b 45 f4 8b 4d 14 8b 14 82 33 51 5c 8b 45 14 8b 88 ?? ?? ?? ?? 8b 45 f4 89 14 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAD_2147904602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAD!MTB"
        threat_id = "2147904602"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af da 8b d3 c1 ea 10 88 14 01 8b d3 ff 46 48 a1 ?? ?? ?? ?? c1 ea 08 8b 48 48 a1 ?? ?? ?? ?? 88 14 08 a1 ?? ?? ?? ?? ff 40 48 8b 4e 48 8b 86 9c 00 00 00 88 1c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_XX_2147904776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.XX!MTB"
        threat_id = "2147904776"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 0d 30 00 00 00 e9}  //weight: 1, accuracy: High
        $x_1_2 = {8a f6 e9 9c cb 05 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 49 0c e9}  //weight: 1, accuracy: High
        $x_1_4 = "SendKeysSample.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_RT_2147907819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.RT!MTB"
        threat_id = "2147907819"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c5 2b 05 ?? ?? ?? ?? 33 d8 a1 ?? ?? ?? ?? 8b b0 ?? ?? ?? ?? 8b 50 ?? 8b 44 24 ?? 0b d3 0f af 35 ?? ?? ?? ?? 03 88 ?? ?? ?? ?? 0b 48 ?? a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAE_2147909751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAE!MTB"
        threat_id = "2147909751"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 46 14 8b 46 4c 33 86 b0 00 00 00 8b 4e 68 35 cf e7 0b 00 89 46 4c a1 ?? ?? ?? ?? 8b 40 44 31 04 11 83 c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_RU_2147910788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.RU!MTB"
        threat_id = "2147910788"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 12 86 d0 b7 a4 7d d4 ?? b1 ?? a0 ?? ?? ?? ?? ?? a7 ?? ?? ?? ?? 30 97 ?? ?? ?? ?? 42 b6 ?? d1 b3 ?? ?? ?? ?? d5 ?? d2 b1 ?? ?? ?? ?? b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AMMF_2147911016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AMMF!MTB"
        threat_id = "2147911016"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 41 48 8b 9e 80 00 00 00 a1 ?? ?? ?? ?? 0f af da 8b 88 84 00 00 00 8b 86 b8 00 00 00 8b d3 c1 ea 08 88 14 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAF_2147911364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAF!MTB"
        threat_id = "2147911364"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c7 04 8b 46 34 0f af 5e 3c 03 c2 33 81 c0 00 00 00 35 ?? ?? ?? ?? 89 81 c0 00 00 00 a1 ?? ?? ?? ?? 8b 4e 58 8b d3 c1 ea 08 88 14 08 ff 46 58 a1 ?? ?? ?? ?? 8b 80 d8 00 00 00 2d 64 d7 03 00 31 46 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_SIH_2147911626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.SIH!MTB"
        threat_id = "2147911626"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phy968jx3.dll" ascii //weight: 1
        $x_1_2 = {35 02 14 03 00 89 81 c0 00 00 00 a1 8c dc 0f 10 8b 4e 58 8b d3 c1 ea 08 88 14 08 ff 46 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AC_2147912089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AC!MTB"
        threat_id = "2147912089"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 0c 02 83 c2 04 8b 0d ?? ?? ?? ?? 8b 81 a0 00 00 00 01 41 5c 8b 85 d0 00 00 00 8b 0d ?? ?? ?? ?? 2d ?? ?? ?? ?? 09 05 ?? ?? ?? ?? 8b 85 f4 00 00 00 35 ?? ?? ?? ?? 29 81 dc 00 00 00 a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? 03 85 dc 00 00 00 31 85 b0 00 00 00 81 fa 74 01 07 00 0f 8c}  //weight: 4, accuracy: Low
        $x_1_2 = "VisibleEntry" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_AB_2147912090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AB!MTB"
        threat_id = "2147912090"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If you are reading this, it means we have encrypted your data and took your files" ascii //weight: 1
        $x_1_2 = "DO NOT PANIC! Yes, this is bad news, but we will have a good ones as well." ascii //weight: 1
        $x_1_3 = "YES, this is entirely fixable!" ascii //weight: 1
        $x_1_4 = "Our name is BlackBasta Syndicate" ascii //weight: 1
        $x_1_5 = "We have your data and encrypted your files, but in less than an hour, we can put things back on track: if you pay for our recovery services, you get a decryptor, the data will be deleted from all of our systems and returned to you" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_BB_2147913636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.BB!MTB"
        threat_id = "2147913636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 8b 0d 30 00 00 00 8b 49 0c 8b 49 0c}  //weight: 1, accuracy: High
        $x_1_2 = "git66\\dll_release\\Dither.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_MVK_2147913869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.MVK!MTB"
        threat_id = "2147913869"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 35 02 14 03 00 c1 ea 18 89 86 c0 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00 88 14 08 8b d3 ff 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 9c 28 fc ff c1 ea 10 31 46 50 8b 4e 50 a1 ?? ?? ?? ?? 81 f1 02 7c 15 00 01 88 f4 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_JKR_2147913870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.JKR!MTB"
        threat_id = "2147913870"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d 0c 8d 76 04 8b 56 fc 2b 54 0e fc 2b d0 8b c2 81 e2 ff ff ff 7f 33 56 fc 23 d3 c1 e8 1f 31 56 fc 83 ef 01 75 d9}  //weight: 1, accuracy: High
        $x_1_2 = "If you are reading this, it means we have encrypted your data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAG_2147914461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAG!MTB"
        threat_id = "2147914461"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f0 01 0f af 46 74 89 46 74 8b 86 ec 00 00 00 03 c1 33 c9 09 05 ?? ?? ?? ?? 41 8b 46 78}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_YAH_2147924780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.YAH!MTB"
        threat_id = "2147924780"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c8 81 c1 ?? ?? ?? ?? 33 c8 89 8e b4 00 00 00 8b 86 88 00 00 00 8b 1c 28 83 c5 04 a1 ?? ?? ?? ?? 0f af 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_KGQ_2147926046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.KGQ!MTB"
        threat_id = "2147926046"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c3 99 f7 fe 8b 45 00 8b 74 24 50 8b 7c 24 58 89 5c 24 20 32 14 30 0f b6 c1 0f b6 ca 0f af c8 a1 ?? ?? ?? ?? 40 a3 ?? ?? ?? ?? 8d 3c 87}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Basta_AAZ_2147933802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.AAZ!MTB"
        threat_id = "2147933802"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b7 c9 0f af c8 8b 44 24 24 66 2b 0c f8 66 01 0c 7a a1 ?? ?? ?? ?? 8a 44 43 1a 0a 44 24 14 30 04 2f a1 ?? ?? ?? ?? 0f b7 4c 42 2e 8d 34 42 b8 3f 15 00 00 2b 05 ?? ?? ?? ?? 2b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_PAGY_2147940392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.PAGY!MTB"
        threat_id = "2147940392"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 86 8c 00 00 00 88 0c 02 ff 05 ?? ?? ?? ?? 8b 46 58 8b 8e 8c 00 00 00 88 1c 01 ff 46 58 a1 ?? ?? ?? ?? 8b 8e e0 00 00 00 2b 88 cc}  //weight: 2, accuracy: Low
        $x_1_2 = {89 86 c0 00 00 00 a1 ?? ?? ?? ?? 8b 8e 8c 00 00 00 88 14 08 8b d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Basta_KTS_2147941172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Basta.KTS!MTB"
        threat_id = "2147941172"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Basta"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 f7 8b 44 24 14 31 14 98 33 d2 a1 ?? ?? ?? ?? f7 f3 0f b7 05 ?? ?? ?? ?? 03 d0 8b 44 24 5c 0f b7 44 68 06 8b 6c 24 10 23 d0 8b 44 24 50 0f af 14 88 89 14 88 41 3b 4c 24 40 7f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

