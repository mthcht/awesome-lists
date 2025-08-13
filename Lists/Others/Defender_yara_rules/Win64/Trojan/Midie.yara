rule Trojan_Win64_Midie_SIB_2147807755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.SIB!MTB"
        threat_id = "2147807755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "XVI32_Load" ascii //weight: 10
        $x_10_2 = "DllInstall" ascii //weight: 10
        $x_10_3 = "XVI32_Close" ascii //weight: 10
        $x_10_4 = "XVI32_init" ascii //weight: 10
        $x_1_5 = {4c 3b 7c 24 60 7d ?? 4c 8b 7c 24 50 48 8b 6c 24 58 55 48 8b 44 24 ?? 5d 48 01 c5 48 0f be 45 00 49 31 c7 49 81 e7 ff 00 00 00 48 8b 2d 9b 84 05 00 49 c1 e7 ?? 4d 8b 3c 2f 4c 8b 74 24 50 49 c1 fe ?? 49 81 e6 ff ff ff 00 4d 31 f7 4c 89 7c 24 50 4c 8b 7c 24 ?? 49 ff c7 4c 89 7c 24 04 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {48 c7 c0 08 00 00 00 48 3b 44 24 ?? 7c ?? 4c 8b 7c 24 ?? 49 83 e7 01 4d 21 ff 74 ?? 4c 63 7c 24 ?? 4c 8b 74 24 02 49 d1 ?? 49 81 e6 ff ff ff 7f 4d 31 f7 4c 89 7c 24 02 eb ?? 4c 8b 7c 24 02 49 d1 ?? 49 81 e7 ff ff ff 7f 4c 89 7c 24 02 48 ff 44 24 00 71 ?? ff 74 24 02 4c 8b 7c 24 ?? 48 8b 2d ?? ?? ?? ?? 49 c1 e7 ?? 58 49 89 04 2f 48 ff 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Midie_NM_2147904896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NM!MTB"
        threat_id = "2147904896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RWSafe.pdb" ascii //weight: 2
        $x_2_2 = "GPT 1.6" ascii //weight: 2
        $x_1_3 = "Baat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_NM_2147904896_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NM!MTB"
        threat_id = "2147904896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {40 b7 01 40 88 7c 24 20 8a cb e8 bc fd ff ff e8 9b 0b 00 00 48 8b d8 48 83 38 00}  //weight: 3, accuracy: High
        $x_2_2 = {48 8b c8 e8 0a fd ff ff 84 c0 74 16 48 8b 1b 48 8b cb e8 b7 00 00 00 45 33 c0 41 8d 50 02 33 c9 ff d3 e8 73 0b 00 00 48 8b d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_NM_2147904896_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NM!MTB"
        threat_id = "2147904896"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 7c 24 ?? 00 49 0f 44 d6 4c 8d 44 24 ?? 4c 8d 7c 24 ?? 4c 89 f9 e8 21 f3 ff ff 4c 8d a4 24}  //weight: 2, accuracy: Low
        $x_1_2 = {48 89 ce 0f b6 81 ?? 00 00 00 88 91 ?? 00 00 00 48 8d 0d 67 01 00 00 48 63 04 81 48 01 c8 ff e0 0f b6 c2 ff c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GXZ_2147908904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GXZ!MTB"
        threat_id = "2147908904"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 02 41 88 00 88 0a 0f b6 54 24 31 44 0f b6 44 24 30 0f b6 4c 14 32 42 02 4c 04 32 0f b6 c1 0f b6 4c 04 32 42 32 4c 17 f7 41 88 4a ff 49 83 eb 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GP_2147914443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GP!MTB"
        threat_id = "2147914443"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dbdjUKLXxZzyf" ascii //weight: 1
        $x_1_2 = "KYgWGvLdWnJMcT" ascii //weight: 1
        $x_1_3 = "xrEAfFrCHbBCE0" ascii //weight: 1
        $x_1_4 = "EaVMlTKHmPPIYKX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_ASJ_2147922485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.ASJ!MTB"
        threat_id = "2147922485"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 8b d0 4c 8d 05 ?? ?? ff ff 49 8b cf 48 8b f8 ff 15 ?? ?? ?? ?? 4c 89 6c 24 30 4c 8b cf 44 89 6c 24 28 45 33 c0 33 d2 48 89 5c 24 20 49 8b cf ff 15 ?? ?? ?? ?? 41 b9 18 00 00 00 4c 89 6c 24 20 4c 8d 44 24 50 48 8b d3 49 8b cf ff 15 ?? ?? ?? ?? b9 64 00 00 00 ff 15}  //weight: 4, accuracy: Low
        $x_1_2 = {49 8d 04 30 49 2b d0 0f 1f 40 00 0f 1f 84 00 00 00 00 00 44 30 38 48 8d 40 01 48 83 ea 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_AMI_2147925996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.AMI!MTB"
        threat_id = "2147925996"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Westminster Performance Suite for optimized system analytics and efficiency" wide //weight: 4
        $x_1_2 = "London Bridge Technologies" wide //weight: 1
        $x_2_3 = "Manchester.dll" wide //weight: 2
        $x_3_4 = "70.59.2345.6789" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_AMD_2147926002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.AMD!MTB"
        threat_id = "2147926002"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Kensington Data Shield for comprehensive data security and protection" wide //weight: 4
        $x_3_2 = "Piccadilly Digital Labs" wide //weight: 3
        $x_1_3 = "71.60.3456.7890" wide //weight: 1
        $x_2_4 = "Stratford.dll" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GNS_2147927639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GNS!MTB"
        threat_id = "2147927639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 c1 86 36 32 1a 95 2a a4 4d}  //weight: 5, accuracy: High
        $x_5_2 = {8c 11 42 36 ee 97 a4 bc ?? ?? ?? ?? cc 31 d1 32 2e 59 00 76 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GNS_2147927639_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GNS!MTB"
        threat_id = "2147927639"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2f ef 00 72 ?? 0a d7 30 76 ?? a4 e2 ?? 30 76 ?? dc 72 ?? 30 76 ?? ac 0a 0f 30 76 ?? bc}  //weight: 10, accuracy: Low
        $x_1_2 = "baE8.NU6L" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GNK_2147927659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GNK!MTB"
        threat_id = "2147927659"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 63 c0 48 c1 f2 b2 42 80 b4 44 ?? ?? ?? ?? ?? 42 ff 4c 04 ?? 48 13 e8 5e 4e 8b 94 83 ?? ?? ?? ?? ff ce 36 66 43 8b 34 8a 48 8d 8a ?? ?? ?? ?? 0f 8d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GTC_2147931139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GTC!MTB"
        threat_id = "2147931139"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {12 0e 6d 30 1b 97 fb 00 1c e0 58 95}  //weight: 5, accuracy: High
        $x_5_2 = {41 32 f8 56 40 08 b4 54 1e 00 fe ff 40 d2 c7 66 0b de 40 1a f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_NS_2147937841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.NS!MTB"
        threat_id = "2147937841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4d 29 fe 4c 39 f7 4d 89 f0 4c 0f 42 c7 48 89 d9 31 d2 e8 a4 fe ff ff 42 8d 0c fd 00 00 00 00 48 d3 e0 48 0b 46 ?? 48 89 46 ?? 49 39 fe}  //weight: 2, accuracy: Low
        $x_1_2 = {48 89 f1 e8 2e ff ff ff 48 8b 46 ?? 48 31 06 48 83 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GZK_2147941295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GZK!MTB"
        threat_id = "2147941295"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b4 1f 4d bf 85 e6 08 f6 9c fa 43 1b 08 1e 32 f9 bf}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GZZ_2147941354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GZZ!MTB"
        threat_id = "2147941354"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f1 33 cd 31 aa ?? ?? ?? ?? 5a 89 95 ?? ?? ?? ?? 34 04 1e 58 03 15 ?? ?? ?? ?? c9 b7 49 b4 b4 41 e1 f4}  //weight: 10, accuracy: Low
        $x_5_2 = {ec 50 1e 32 62 a7 a4 63 80}  //weight: 5, accuracy: High
        $x_5_3 = {18 31 10 42 ?? 54 02 20 35 ?? ?? ?? ?? 1a cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Midie_SPR_2147945181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.SPR!MTB"
        threat_id = "2147945181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 ff 45 33 c9 48 89 7c 24 30 45 33 c0 c7 44 24 28 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 44 24 20 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 48 8b e8 48 83 f8 ff 75}  //weight: 3, accuracy: Low
        $x_3_2 = {c7 44 24 28 ?? ?? ?? ?? 48 83 64 24 20 00 48 8d 15 ?? ?? ?? ?? 33 c9 45 33 c9 ff 15 ?? ?? ?? ?? 48 83 f8 20 0f 9f c0 48 83 c4 38}  //weight: 3, accuracy: Low
        $x_1_3 = "posdfcc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_AHB_2147946815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.AHB!MTB"
        threat_id = "2147946815"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 03 c8 48 89 4c 24 30 89 44 24 38 0f 28 44 24 30 66 0f 7f 44 24 30 48 8d 85 d0 01 00 00 48 89 44 24 20 4c 8d 8d d8 01 00 00 4c 8d 85 e0 01 00 00 48 8d 95 e8}  //weight: 5, accuracy: High
        $x_5_2 = {44 8b c0 b8 4f ec c4 4e 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 41 8d 50 41 48 8d 4d c0 e8}  //weight: 5, accuracy: High
        $x_5_3 = "MP3SimWnd" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_AHC_2147947011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.AHC!MTB"
        threat_id = "2147947011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {0f 10 45 b0 f3 0f 7f 45 d8 8a 45 c0 88 45 e8 8a 45 c1 88 45 e9 48 8b 45 c8 48 89 45 f0 48 8d 05 ?? ?? ?? ?? 48 89 45 d0 eb 08 48 c7 45 d0 00}  //weight: 30, accuracy: Low
        $x_20_2 = {44 8b c0 b8 ?? ?? ?? ?? 41 f7 e8 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 1a 44 2b c1 41 8d 50 41 48 8d 4d c0 e8}  //weight: 20, accuracy: Low
        $x_5_3 = "MP3SimWnd" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_MDD_2147947499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.MDD!MTB"
        threat_id = "2147947499"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 32 c9 41 32 ca 41 88 4c 24 01 49 8d 47 fe 83 e0 07 0f b6 8c 30 ?? ?? ?? ?? c0 e9 04 c0 e2 04 0a ca 41 32 8c 37 ?? ?? ?? ?? 32 cb 41 32 c8 41 88 4c 24 02 49 83 c7 05 49 83 c5 05 4d 8d 64 24 05 49 83 fd 1a 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Midie_GVA_2147949149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Midie.GVA!MTB"
        threat_id = "2147949149"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8d 45 d8 48 83 7d f0 0f 48 0f 47 45 d8 0f b6 14 08 80 f2 3d 48 8b c6 48 83 7e 18 0f 76 03 48 8b 06 88 14 08 48 ff c1 48 3b 4d e8 72 d2}  //weight: 2, accuracy: High
        $x_1_2 = "//tapped.win/" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\CHARM\\Auth" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

