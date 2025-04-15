rule TrojanDownloader_Win32_Rugmi_B_2147898934_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.B!MTB"
        threat_id = "2147898934"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 0c 16 83 c2 ?? 39 c2}  //weight: 2, accuracy: Low
        $x_2_2 = {31 3c 03 83 c0 ?? 39 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SB_2147899734_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SB!MTB"
        threat_id = "2147899734"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0d 08 30 04 32 8d 41 ?? 83 e9 ?? 42 f7 d9 1b c9 23 c8 3b d7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SA_2147902124_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SA!MTB"
        threat_id = "2147902124"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 83 c1 ?? 89 4c 24 ?? 83 f8 ?? 74 ?? 8b 44 24 ?? 8a ?? 8b 0c 24 88 01 8b 04 24 83 c0 ?? 89 04 24 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = "\\NewToolsProject\\SQLite3Encrypt\\Release\\SQLite3Encrypt.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_C_2147902177_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.C!MTB"
        threat_id = "2147902177"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 c0 03 45 ?? 89 45 a4 8b 45 a4 8b ?? 33 85 58 ?? ?? ?? 8b 4d a4 89 01 8b 45 d4 83 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNS_2147906499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNS!MTB"
        threat_id = "2147906499"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 42 3c 0f be 0b 8b 7c 10 2c 8d 44 24 10 8b 6c 0b 04 8d 71 0c 50 6a 40 03 f3 03 fa 8b 5c 0b 08 53 57 c7 44 24 20 00 00 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 ff 54 24 2c 8b 0d ?? ?? ?? ?? 8b 44 24 04 8d ?? 08 8b ?? 04 8d ?? 08 89 ?? 24 8d ?? 08 f7 d8 03 ?? 3d f8 ?? 00 00 7d 0d f7 d8 3d f8 ?? 00 00}  //weight: 10, accuracy: Low
        $x_10_3 = {89 45 ec 8b 45 fc 8b 40 5c 89 45 f0 83 65 e8 00 8b 45 f0 83 38 00 74 3f ff 75 ec}  //weight: 10, accuracy: High
        $x_10_4 = {00 83 ec 10 03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff}  //weight: 10, accuracy: High
        $x_10_5 = {6a 04 58 6b c0 00 8b 4d f0 8b 55 e8 3b 14 01 74 ?? 6a 04 58 c1 e0 00 8b 4d f0 8b 55 e8 3b 14 01 74 08 6a 00}  //weight: 10, accuracy: Low
        $x_10_6 = {89 c1 41 8b 44 0e 04 4c 01 f1 48 83 c1 08 ba 04 00 00 00 8b 74 11 fc 01 c6 89 74 17 04 48 83 c2 04 48 81 fa ?? ?? 00 00 72 ?? 8b 05 ?? ?? ?? ?? 89 47 08}  //weight: 10, accuracy: Low
        $x_5_7 = {8b 4f 0c 03 c8 a1 ?? ?? ?? ?? 03 cf 03 f8 57 ff d1 83 c4 04 6a 00 ff}  //weight: 5, accuracy: Low
        $x_5_8 = {8b 5e 04 2b f7 8b 04 0e 8d 49 04 03 c3 89 41 fc 83 ea 01 75 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Rugmi_HNA_2147907068_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNA!MTB"
        threat_id = "2147907068"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 0f 95 c0 84 c0 74 15 8b 45 ?? 0f b6 00 8b 55 ?? 88 02 83 45 ?? 01 83 45 ?? 01 eb d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNC_2147907261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNC!MTB"
        threat_id = "2147907261"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 11 fc 01 c6 89 74 13 04 83 c2 04 81 fa fc 5f 00 00 72 eb}  //weight: 1, accuracy: High
        $x_1_2 = {03 43 0c 01 d8 01 d3 89 1c 24 ff d0 c7 04 24 00 00 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {8b 44 24 1c 33 d2 66 89 14 48 89 44 24 24 8d 04 33 89 44 24 20 8d 44 24 20 50 c6 44 24 2c 01 ff d7}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 fc 0f be 02 03 45 fc 89 45 fc 8b 4d fc 83 c1 01 51 ff 55 b0 89 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HND_2147907821_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HND!MTB"
        threat_id = "2147907821"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 03 8b 00 8b 55 08 03 42 e4 83 c0 02 8b 55 08 89 42 cc 8b 45 08 8b 40 cc 50 8b 07 50 ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 fc 83 c0 02 8d 14 85 00 00 00 00 8b 45 f8 01 d0 8b 08 8b 45 fc 8d 14 85 00 00 00 00 8b 45 0c 01 d0 8b 55 f0 01 ca 89 10 83 45 fc 01 eb c8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 8d 55 e0 c7 44 24 0c 08 00 00 00 8b 4d 0c 89 54 24 08 29 d8 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNF_2147909118_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNF!MTB"
        threat_id = "2147909118"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 ca 89 10 83 45 ?? 01 30 00 [0-48] 8b 45 ?? 39 45 ?? 76 [0-8] 8b 45 [0-8] 8b 08 [0-16] 01 ca [0-16] 83 45 ?? 01 [0-16] 83 c0 04 [0-8] 89 45 [0-8] eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNE_2147909713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNE!MTB"
        threat_id = "2147909713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 0f 95 c0 84 c0 74 ?? 8b 45 0c 0f b6 00 8b 55 30 00 [0-37] 55 89 e5 83 ec [0-32] 8d 50 ff [0-32] 88 02 [0-32] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNI_2147910066_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNI!MTB"
        threat_id = "2147910066"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 10 89 45 fc b8 ff ff ff ?? 03 45 10 89 45 10 8b 45 fc 85 c0 74 23 8b 45 0c 8b 55 08 0f be 00 88 02 b8 01 00 00 00 03 45 08 89 45 08 b8 01 00 00 00 03 45 0c 89 45 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_SG_2147912598_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.SG!MTB"
        threat_id = "2147912598"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hidden" wide //weight: 1
        $x_1_2 = "WixBurn" wide //weight: 1
        $x_1_3 = "aphagia.exe" wide //weight: 1
        $x_1_4 = "//appsyndication.org" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_EC_2147912710_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.EC!MTB"
        threat_id = "2147912710"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb 0c 8b 4d f8 8b 51 18 03 55 f4 89 55 f4 8b 45 f8 8b 48 10 39 4d f4 73 15 8b 55 e8 03 55 f4 8b 02 03 45 dc 8b 4d f0 03 4d f4 89 01 eb d4}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNN_2147912837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNN!MTB"
        threat_id = "2147912837"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 04 08 83 f8 00 74 ?? 8b 45 ?? 8b 4d ?? 0f be 04 08 8b 4d ?? 8b 55 ?? 66 89 04 51 8b 45 ?? 83 c0 01 89 45 ?? 8b 45 ?? 83 c0 01 89 45 ?? eb}  //weight: 1, accuracy: Low
        $x_1_2 = {24 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? 01 00 00 00 c7 44 24 ?? 00 00 00 00 c7 44 24 ?? 03 00 00 00 c7 44 24 ?? 80 00 00 00 c7 44 24 ?? 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {03 01 89 01 8b 45 ?? 83 c0 01 89 45}  //weight: 1, accuracy: Low
        $x_1_4 = {66 c7 04 48 00 00 8b 45 ?? 89 85 ?? ?? ?? ?? 8b 45 ?? 89 85 ?? ?? ?? ?? c6 85 ?? ?? ?? ?? 01 8b 45 ?? 89 45 ?? 8d 85 ?? ?? ?? ?? 89 04 24 ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_EM_2147915506_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.EM!MTB"
        threat_id = "2147915506"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 c4 83 65 e0 00 83 65 dc 00 83 65 d8 00 6a 00 6a 00 6a 00 6a 01 8b 45 fc ff 70 48}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNR_2147917803_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNR!MTB"
        threat_id = "2147917803"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {55 8b ec 51 51 83 65 fc 00 83 65 f8 00 33 c0 40 74 2e 8b 45 fc 8b 4d 08 0f b7 04 41 83 f8 5c 75 06 8b 45 fc 89 45 f8 8b 45 fc 8b 4d 08 0f b7 04 41 85 c0 75 02 eb 09 8b 45 fc 40 89 45 fc eb cd 8b 45 f8 8b 4d 08 8d 44 41 02 8b e5 5d c3}  //weight: 5, accuracy: High
        $x_1_2 = {59 6a 00 ff 15 17 00 [0-16] 8b 00 03 45 ?? 89 45 ?? 8b 45 ?? 89 45 ?? ff 75 ?? ff 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNT_2147918333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNT!MTB"
        threat_id = "2147918333"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 45 08 89 45 f8 8b 45 10 89 45 fc 8b 45 10 48 89 45 10 83 7d fc 00 74 1a 8b 45 08 8b 4d 0c 8a 09 88 08 8b 45 08 40 89 45 08 8b 45 0c 40 89 45 0c}  //weight: 5, accuracy: High
        $x_2_2 = {55 8b ec 51 51 8b 45 08 89 45 fc 8b 45 0c 89 45 f8 8b 45 0c 48 89 45 0c 83 7d f8 00 76 0f 8b 45 fc c6 00 00 8b 45 fc 40 89 45 fc eb de 8b 45 08 8b e5 5d c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNU_2147918597_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNU!MTB"
        threat_id = "2147918597"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 78 08 8d 04 3b 89 45 ?? 8b 46 3c 8b 44 06 2c 89}  //weight: 5, accuracy: Low
        $x_1_2 = {c7 04 24 00 00 00 00 89 44 24 04 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {89 04 24 ff d1 8d 65 ?? 59 5b 5e 5f 5d}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 0c 04 00 00 00 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_DA_2147921596_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.DA!MTB"
        threat_id = "2147921596"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af 74 24 0c 0f b6 0c 3a 03 f1 42 3b d0 72 ?? 5f 8b c6 5e c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNY_2147924551_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNY!MTB"
        threat_id = "2147924551"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 f8 8b 0f 8d 47 04 8b 10 83 c0 04 [0-255] [0-255] [0-255] 66 0f be 04 08 [0-255] c6 44 24 ?? 01 ff (d2|d7)}  //weight: 5, accuracy: Low
        $x_5_2 = {0f be 11 03 55 f8 89 55 f8 8b 45 f8 83 c0 01 50 [0-255] [0-255] 50 ff 95 74 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNAE_2147925224_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNAE!MTB"
        threat_id = "2147925224"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f be 00 85 c0 74 24 8b 45 ?? 03 45 ?? 66 0f be 00 8b 4d ?? 8b 55 ?? 66 89 04 4a 8b 45 02 40 89 45 02 8b 45 01 40 89 45 01 eb}  //weight: 10, accuracy: Low
        $x_1_2 = {ff 55 98 89 45 ?? 8b 45 ?? ?? ?? ?? 8b 45 fc ff 70 ?? 8b ?? fc ff 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNAF_2147925225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNAF!MTB"
        threat_id = "2147925225"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 51 3c 89 55 ?? 8b 45 00 8b 4d ?? 03 48 2c 89 4d}  //weight: 10, accuracy: Low
        $x_1_2 = {66 0f be 0c 02 8b 55 ?? 8b 45 ?? 66 89 0c 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNAG_2147925226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNAG!MTB"
        threat_id = "2147925226"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d0 0f be 0b 03 d9 03 f3 8b 42 3c 8b 6b 04 8b 5b 08 8b 7c 10 2c 8d 44 24}  //weight: 10, accuracy: High
        $x_1_2 = {8d 40 04 83 e9 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_HNAH_2147925243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.HNAH!MTB"
        threat_id = "2147925243"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {03 ef 8b 4e 3c 8b 5f 04 8b 7f 08 03 74 31 2c [0-255] [0-255] c6 40 08 01 50 ff d3}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_D_2147925588_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.D!MTB"
        threat_id = "2147925588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 fc 8b 40 20 8b 4d e4 0f be 04 08 85 c0 74 21 8b 45 fc 8b 40 20 8b 4d e4 66 0f be 04 08 8b 4d e4 8b 55 c4 66 89 04 4a 8b 45 e4 40 89 45 e4 eb ce}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_D_2147925588_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.D!MTB"
        threat_id = "2147925588"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {03 41 3c 89 85 30 fe ff ff 8b 45 dc 8b 8d 30 fe ff ff 8b 95 2c fe ff ff 03 44 d1 78 89 45 84 8b 45 dc 8b 4d 84 03 41 20 89 85 34 fe ff ff 8b 45 dc 8b 4d 84 03 41 1c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_DB_2147925914_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.DB!MTB"
        threat_id = "2147925914"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 8b e8 0f af 7c 24 ?? 0f b6 04 16 03 f8 46 3b f5 72 04 00 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 08 88 4d ?? 8b 55 ?? 0f af 55 ?? 0f b6 45 ?? 03 d0 89 55 ?? eb 06 00 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_3 = {8a 00 88 45 ?? 8b 45 ?? 0f af 45 ?? 0f b6 4d ?? 03 c1 89 45 ?? eb 06 00 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_4 = {0f 1f 40 00 0f af 54 24 ?? 0f b6 04 3e 46 03 d0 3b f1 72}  //weight: 1, accuracy: Low
        $x_1_5 = {90 90 90 0f af d8 0f b6 4d 00 01 cb 45 4e 75 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_DC_2147925915_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.DC!MTB"
        threat_id = "2147925915"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f af c8 0f b6 14 73 03 ca 0f af c8 0f b6 54 73 ?? 46 03 ca 3b f7 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0f af 44 24 ?? 0f b6 0c 2a 03 c1 45 3b ee 72}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 44 24 04 8a 00 8b 0c 24 88 01 8b 04 24 83 c0 01 89 04 24 8b 44 24 04 83 c0 01 89 44 24 04 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_DF_2147928455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.DF!MTB"
        threat_id = "2147928455"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 45 f4 8b 45 f4 8b 48 0c 89 4d f0 8b 55 f0 83 c2 0c 89 55 fc 8b 45 fc 89 45 e8 b9 01 00 00 00 85 c9 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rugmi_PAGN_2147939017_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rugmi.PAGN!MTB"
        threat_id = "2147939017"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rugmi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fivem injector" ascii //weight: 2
        $x_2_2 = "mode con: cols=30 lines=10" ascii //weight: 2
        $x_1_3 = "loader.pdb" ascii //weight: 1
        $x_1_4 = "URLDownloadToFileW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

