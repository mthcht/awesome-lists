rule Trojan_Win32_Zloader_SK_2147753168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SK!MTB"
        threat_id = "2147753168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "antiemule-loader-bot32.dll" ascii //weight: 10
        $x_10_2 = "DllRegisterServer" ascii //weight: 10
        $x_2_3 = "EndPage" ascii //weight: 2
        $x_2_4 = "StartPage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_DHB_2147754282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.DHB!MTB"
        threat_id = "2147754282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 89 4d f0 89 c3 f6 d3 80 e3 ?? 6a 00 6a 00 6a ?? 50 e8 ?? ?? ?? ?? 8b 4d f0 83 c4 10 08 d8 30 c8 c1 c1 ?? 34 ?? 88 07 47 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = "djluflczrgefphtiwegc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zloader_AB_2147756432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.AB!MTB"
        threat_id = "2147756432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 3b d6 8b 0c 85 80 9e 0a 10 0f 95 c0 02 c0 32 44 39 2d 24 02 30 44 39 2d 8d 04 12}  //weight: 1, accuracy: High
        $x_1_2 = {5c 53 65 61 74 5c 70 61 67 65 5c 70 61 70 65 72 5c 42 75 73 79 5c [0-2] 5c 64 6f 77 6e 5c 57 69 6e 67 5c 57 6f 75 6c 64 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_3 = ":\\Windows\\iexplore.exe" ascii //weight: 1
        $x_1_4 = {20 05 93 19 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = "IsAsyncMoniker" ascii //weight: 1
        $x_1_6 = "C:\\TEMP\\" ascii //weight: 1
        $x_1_7 = "CorExitProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_RA_2147756571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.RA!MTB"
        threat_id = "2147756571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c:\\clean\\there\\clothe\\winter\\Fraction\\race\\Card\\Worldcloud.pdb" ascii //weight: 1
        $x_1_2 = "main.dll" ascii //weight: 1
        $x_1_3 = "Drystrange1" ascii //weight: 1
        $x_1_4 = "Lightsheet@12" ascii //weight: 1
        $x_1_5 = "c:\\talk\\Turn\\separate\\Time\\Spot\\Station\\Togethernotice.pdb" ascii //weight: 1
        $x_1_6 = {8b d0 6b d2 43 8b f9 6b ff 43 2b f2 8b d6 2b d7 8d 7c 02 5c 66 01 3d}  //weight: 1, accuracy: High
        $x_3_7 = {81 c2 84 23 01 01 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 [0-5] 8b 0d 00 89 88 38 ed ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zloader_AC_2147766904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.AC!MTB"
        threat_id = "2147766904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {36 43 c0 63 ff 48 d0 41 d0 0c 8b 80 e9 c0 ff 09 21 24 74 28 ff be [0-4] 58 d2 48 8b 82 f8 f1 8b 00 70}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04}  //weight: 1, accuracy: High
        $x_1_4 = ":\\Windows\\iexplore.exe" ascii //weight: 1
        $x_1_5 = "\\Quiet\\Fun\\Insect\\Carry.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Zloader_AD_2147766910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.AD!MTB"
        threat_id = "2147766910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 08 8b 4c 24 10 0b c8 8b 4c 24 0c 75 ?? 8b 44 24 04 f7 e1 c2 ?? ?? 53 f7 e1 8b d8 8b 44 24 08 f7 64 24 14 03 d8 8b 44 24 08 f7 e1 03 d3 5b c2}  //weight: 1, accuracy: Low
        $x_1_3 = ":\\Windows\\iexplore.exe" ascii //weight: 1
        $x_1_4 = {5c 4c 65 61 73 74 5c 4f 72 69 67 69 6e 61 6c 5c [0-10] 5c 44 69 73 63 75 73 73 5c 4c 61 72 67 65 5c ?? ?? 5c 62 75 74 5c 46 69 74 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_AE_2147766911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.AE!MTB"
        threat_id = "2147766911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ff 33 c2 83 c1 04}  //weight: 1, accuracy: High
        $x_1_2 = {02 c0 02 c3 02 c1 2c ?? 81 c6 ?? ?? ?? ?? 88 44 24 13 89 35 ?? ?? ?? ?? 89 b4 2f ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 c0 83 c7 ?? 8d 5c 30 01 89 1d ?? ?? ?? ?? 81 ff ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
        $x_1_3 = ":\\Windows\\iexplore.exe" ascii //weight: 1
        $x_1_4 = {5c 53 6c 61 76 65 5c 45 6c 73 65 5c [0-8] 5c 54 69 6d 65 5c [0-16] 5c 77 68 65 65 6c 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_5 = "Attempt to use MSIL code" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_AF_2147766912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.AF!MTB"
        threat_id = "2147766912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 8b d1 03 c6 3b fe 76 08 3b f8 0f 82 ?? ?? ?? ?? 83 f9 ?? 0f 82 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 73 13 0f ba 25 ?? ?? ?? ?? 01 0f 82 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f ba 25 ?? ?? ?? ?? 01 73 09 f3 a4}  //weight: 1, accuracy: Low
        $x_1_2 = ":\\Windows\\iexplore.exe" ascii //weight: 1
        $x_1_3 = {5c 68 69 6c 6c 5c 44 61 6e 63 65 5c [0-4] 5c 63 6f 6d 70 61 6e 79 5c 42 65 61 75 74 79 5c 6b 65 65 70 5c 53 63 61 6c 65 5c [0-4] 5c 45 78 70 65 72 69 65 6e 63 65 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_MB_2147767281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.MB!MTB"
        threat_id = "2147767281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 f8 8b c2 c1 e8 ?? 03 f2 89 45 fc 8b 45 f4 01 45 fc 8b 5d f8 8b c2 c1 e0 ?? 03 45 f0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 fc c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c6 2b c8 8b f1 c1 e6 ?? 03 75 e8 8b c1 c1 e8 ?? 03 45 ec 03 d9 33 f3 33 f0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 fc 2b d6 8b 45 e4 29 45 f8 4f 75 99}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_C_2147767460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.C!ibt"
        threat_id = "2147767460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 61 74 68 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 57 61 6c 6b 6b 6e 65 77 00}  //weight: 1, accuracy: High
        $x_1_2 = "SameAfraid\\animalStone\\ourWife\\LiquidJust\\path.pdb" ascii //weight: 1
        $x_1_3 = "InternetReadFile" ascii //weight: 1
        $x_1_4 = "InternetWriteFile" ascii //weight: 1
        $x_1_5 = "HttpSendRequestExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_C_2147767460_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.C!ibt"
        threat_id = "2147767460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 89 c1 81 f1 f2 00 00 00 89 ca 0f af d0 31 d1 0f af ca 29 d1 81 f1 ae 02 00 00 8d 91 44 ff ff ff 89 d6 0f af f1 09 f2 0f be d2 01 f2 89 d6 29 ce 21 ce 35 77 d8 dd 9d 01 f1 0f af ca 0f af ce 0f af c9 69 c9 d0 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 5d 0c b9 c1 de 31 35 89 d8 89 de f7 e1 c1 ea 07 69 c2 68 02 00 00 29 c6 8b 0c b5 ?? ?? ?? ?? 85 c9 74 2f 31 c0 90 90 [0-16] 39 d9 0f 84 96 00 00 00 81 fe 66 02 00 00 8d 76 01 0f 4f f0 8b 0c b5 ?? ?? ?? ?? 85 c9 75 e1}  //weight: 1, accuracy: Low
        $x_1_3 = {53 57 56 81 ec ?? ?? 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? be ff ff ff ff e8 ?? ?? ?? ?? 84 c0 0f 84 ?? ?? 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_LB_2147768365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.LB!MTB"
        threat_id = "2147768365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 33 c0 5f 5d c3}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 57 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 11 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2d ?? ?? 00 00 a3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_BM_2147768967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.BM!MSR"
        threat_id = "2147768967"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Circleopposite" ascii //weight: 1
        $x_1_2 = "CreateFile2" ascii //weight: 1
        $x_1_3 = "c:\\FlowerSpring\\JumpEven\\Throughobserve\\willEase\\Eye.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_FF_2147769575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.FF!MTB"
        threat_id = "2147769575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 df c1 e1 04 03 c8 c1 e1 02 2b f9 03 d7 89 15 ?? ?? ?? ?? 8b 44 24 14 2b d5 83 ea 08 81 c3 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 54 24 10 89 1d ?? ?? ?? ?? 83 c2 04 89 18 8b 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_GA_2147772400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.GA!MTB"
        threat_id = "2147772400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 0c 32 88 0c 38 8b 55 ?? 83 c2 ?? 89 55 [0-15] 5f 5e 8b e5 5d c3 32 00 03 45 ?? 8b}  //weight: 5, accuracy: Low
        $x_5_2 = {03 01 8b 55 ?? 89 02 8b 45 ?? 8b 08 83 e9 ?? 8b 55 ?? 89 0a 8b e5 5d c3}  //weight: 5, accuracy: Low
        $x_10_3 = {8b c2 c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 11 32 00 04 01 01 01 01 31 32 30 33}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zloader_GB_2147772566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.GB!MTB"
        threat_id = "2147772566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0c 32 88 0c 38 8b 55 f8 83 c2 01 89 55 f8 eb ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 5f 5e 8b e5 5d c3 32 00 03 45 fc 8b 55 f4}  //weight: 10, accuracy: Low
        $x_10_2 = {03 01 8b 55 08 89 02 8b 45 08 8b 08 83 e9 01 8b 55 08 89 0a 8b e5 5d c3 28 00 8b 55 ?? 8d 44 02 ?? 8b 4d 08}  //weight: 10, accuracy: Low
        $x_10_3 = {89 11 5d c3 41 00 81 c2 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b ca a3 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15}  //weight: 10, accuracy: Low
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Zloader_GF_2147778273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.GF!MTB"
        threat_id = "2147778273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a ca 2a cb 8a c2 b3 ?? f6 eb 81 c6 ?? ?? ?? ?? 89 35 ?? ?? ?? ?? 89 b4 2f ?? ?? ?? ?? 2a 05 ?? ?? ?? ?? 80 c1 ?? 83 c7 ?? 02 c8 81 ff ?? ?? ?? ?? 0f 82}  //weight: 10, accuracy: Low
        $x_10_2 = {29 1e f6 e9 02 c3 f6 e9 02 c3 83 ee ?? 81 fe ?? ?? ?? ?? 7f ?? 8b 35 ?? ?? ?? ?? a2 ?? ?? ?? ?? 85 ed 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_SIB_2147780526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIB!MTB"
        threat_id = "2147780526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b de 2b 5c 24 ?? 83 c3 ?? 8b 00 89 44 24 ?? 8b 44 24 ?? 05 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 03 c1 83 3d ?? ?? ?? ?? ?? 89 44 24 ?? 74 ?? 8b c7 2b c1 2b 44 24 ?? 03 f0 89 35 ?? ?? ?? ?? eb ?? 8b c8 2b ce 83 c1 03 83 25 ?? ?? ?? ?? ?? 8b 44 24 ?? 8d 34 11 8b 4c 24 ?? 05 ?? ?? ?? ?? 83 c1 ?? a3 ?? ?? ?? ?? 03 f1 8b 4c 24 ?? 83 44 24 ?? 04 89 01 8b ce 2b cb 33 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {41 83 f9 19 7c ?? 8b 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 40 68 ?? ?? ?? ?? 52 6a ff a3 ?? ?? ?? ?? 89 55 ?? ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 74 ?? 8d 81 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 74 ?? 47 83 ff ?? 7c ?? 83 3d ?? ?? ?? ?? ?? a3 f0 88 09 01 75 ?? 0f b6 05 ?? ?? ?? ?? 66 83 c0 ?? 6a ?? 0f b7 c0 5e 2b f0 a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 3d ?? ?? ?? ?? 75 ?? 8d 46 ?? 0f b7 c0 89 45 ?? eb ?? 6a ?? 58 2b c6 01 05 ?? ?? ?? ?? c6 05 ?? ?? ?? ?? ?? 8b 7d ?? 81 c3 ?? ?? ?? ?? 03 da ff d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Zloader_SIBF_2147780528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIBF!MTB"
        threat_id = "2147780528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 8b 74 24 ?? 83 44 24 ?? ?? 8b 06 05 ?? ?? ?? ?? 89 06}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d8 8a 81 ?? ?? ?? ?? 8d 49 01 4e [0-48] 85 f6 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d 08 89 4d ?? 8b 15 ?? ?? ?? ?? 83 c2 ?? 2b 55 ?? 33 c0 89 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8b 4d ?? 51 68 ?? ?? ?? ?? 8b 55 00 52 ff 15 ?? ?? ?? ?? 00 30 ff 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_SIBG_2147793879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIBG!MTB"
        threat_id = "2147793879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 11 88 55 ?? [0-160] 0f b6 4d 00 2b 8d ?? ?? ?? ?? 88 4d 00 [0-240] 8a 45 00 8a 8d 03 d2 c0 88 45 00 [0-112] 8b 85 ?? ?? ?? ?? 8a 4d 00 88 08 [0-192] 8b 85 ?? ?? ?? ?? 83 c0 ?? 89 85 0d [0-112] 8b 85 0a 83 c0 ?? 89 85 0a [0-128] 8b 8d 03 c1 c1 ?? 89 8d 03 [0-224] 69 95 03 ?? ?? ?? ?? 89 95 03 [0-160] 8b 85 ?? ?? ?? ?? 05 a7 22 00 00 89 85 1d [0-192] 8b 95 1d 3b 95 a8 fe ff ff 0f 8d ?? ?? ?? ?? [0-160] 8b 8d 0d 8a 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_ZX_2147795289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.ZX"
        threat_id = "2147795289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "201"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {55 89 e5 56 8b 75 08 85 f6 74 [0-16] 6a 00 e8 ?? ?? ?? ?? 83 c4 08 56 6a 00 ff 35 ?? ?? ?? ?? ff d0 5e 5d c3}  //weight: 100, accuracy: Low
        $x_100_3 = {55 89 e5 53 57 56 8b 7d 08 85 ff 74 [0-30] 6a 00 e8 ?? ?? ?? ?? 83 c4 08 8b 1d [0-22] 50 53 ff ?? eb 02 31 c0 5e 5f 5b 5d c3}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_ADT_2147798216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.ADT!MTB"
        threat_id = "2147798216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {fe 45 ff 0f b6 75 ff 8a 14 06 00 55 fe 0f b6 4d fe 8a 1c 01 88 1c 06 88 14 01 0f b6 34 06 8b 4d 08 0f b6 d2 03 f2 81 e6 ff 00 00 00 8a 14 06 30 14 39 47 3b 7d 0c 72 c8}  //weight: 20, accuracy: High
        $x_1_2 = "HTTP/1.1" ascii //weight: 1
        $x_1_3 = "EBWAkVSELJeIYPQIE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_CF_2147807564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.CF!MTB"
        threat_id = "2147807564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Project1.dll" ascii //weight: 1
        $x_1_2 = "whoami.exe" ascii //weight: 1
        $x_1_3 = "yyhhjf" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "jgfgfccdshgjhghj" ascii //weight: 1
        $x_1_7 = "ggdrerererdfghfhgfhg" ascii //weight: 1
        $x_1_8 = "ffcdeeeg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_GGT_2147814052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.GGT!MTB"
        threat_id = "2147814052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c1 8b f1 c1 f8 ?? 83 e6 ?? 8d 1c 85 ?? ?? ?? ?? c1 e6 ?? 8b 03 8a 44 30 ?? a8 01 0f 84 ?? ?? ?? ?? 33 ff 39 7d 10 89 7d f8 89 7d f0 75 07}  //weight: 10, accuracy: Low
        $x_1_2 = "7kwifhre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_SIBB_2147817489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIBB!MTB"
        threat_id = "2147817489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {21 f0 89 45 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 89 fe f7 d6 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 83 e7 ?? 21 f0 57 50 e8 ?? ?? ?? ?? 83 c4 08 33 45 00 35 ?? ?? ?? ?? 89 45 00 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {88 c7 f6 d7 0f b6 c7 50 56 e8 ?? ?? ?? ?? 83 c4 08 88 45 ?? 8b 45 ?? 88 c3 f6 d3 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 0f b6 4d ?? 22 7d 02 20 d8 0f b6 c0 08 4d 01 0f b6 cf 51 50 e8 ?? ?? ?? ?? 83 c4 08 89 c3 ff 75 02 56 e8 ?? ?? ?? ?? 83 c4 08 32 5d 01 8b 45 0c 88 1c 38 8d 7f 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_SIBH_2147817834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIBH!MTB"
        threat_id = "2147817834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 db 31 ff 89 55 ?? 89 ce e8 ?? ?? ?? ?? 89 75 ?? 89 c1 0f b6 36 d3 e7 01 fe e8 ?? ?? ?? ?? f7 d0 50 56 e8 ?? ?? ?? ?? 83 c4 08 21 f0 74 ?? c1 e8 ?? 89 c7 89 45 ?? b8 ?? ?? ?? ?? f7 d7 21 f7 50 56 e8 ?? ?? ?? ?? 83 c4 08 81 ce ?? ?? ?? ?? 81 e7 ?? ?? ?? ?? 81 f6 ?? ?? ?? ?? 23 75 07 09 fe 81 c3 ?? ?? ?? ?? 31 c0 40 50 53 e8 ?? ?? ?? ?? 83 c4 08 8b 4d 02 8b 55 00 89 c3 89 f7 81 c3 ?? ?? ?? ?? 41 39 d3 0f 85 ?? ?? ?? ?? 89 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_SIBH2_2147817973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.SIBH2!MTB"
        threat_id = "2147817973"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c7 39 f0 8b 45 ?? 30 1c 38 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 89 da 89 c1 c1 eb ?? d3 e2 89 d8 89 d6 f7 d0 89 55 ?? f7 d6 89 45 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 f7 d0 89 45 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 21 f0 8b 75 05 23 75 09 09 c6 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 89 d9 23 45 06 23 4d 09 6a 00 51 50 e8 ?? ?? ?? ?? 83 c4 0c 31 f0 89 c6 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 c4 04 0b 45 09 21 d8 23 45 05 6a 00 50 56 8b 75 ?? e8 ?? ?? ?? ?? 83 c4 0c 89 c3 f7 d7 57 6a 00 e8 ?? ?? ?? ?? 83 c4 08 89 c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_CG_2147824869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.CG!MTB"
        threat_id = "2147824869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 0c 03 8b 54 03 04 33 4d 08 33 55 0c 09 ca 75}  //weight: 1, accuracy: High
        $x_1_2 = {f7 e1 0f af f9 01 da 01 d7 8b 55 d4 29 c2 19 fe 81 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_MBHS_2147852861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.MBHS!MTB"
        threat_id = "2147852861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GrctvybDrctvy" ascii //weight: 1
        $x_1_2 = "YctvybEcrtvy" ascii //weight: 1
        $x_1_3 = "frgthy.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_MBHS_2147852861_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.MBHS!MTB"
        threat_id = "2147852861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 38 36 2e 64 6c 6c 00 5f 61 40 34}  //weight: 1, accuracy: High
        $x_1_2 = "KshBnwklqd|eHnfmgQcpqakoq" ascii //weight: 1
        $x_1_3 = "FlehccrlBklIjhukhnoyg[me" ascii //weight: 1
        $x_1_4 = "KrmuhahnUfa|mnlFgmZwmmEfwot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_MKD_2147924863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.MKD!MTB"
        threat_id = "2147924863"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 c8 a3 ?? ?? ?? ?? 8d ?? d1 1e 00 00 66 89 15 ?? ?? ?? ?? 80 ea 5e 02 d0 0f b6 d2 0f af d1 80 ea 27 88 15 ?? ?? ?? ?? 8b 44 24 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zloader_B_2147937650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zloader.B"
        threat_id = "2147937650"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 12 27 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ba 29 27 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {ba 11 27 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {ba 13 27 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {ba 16 27 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {ba e0 2e 00 00}  //weight: 1, accuracy: High
        $x_10_7 = {48 63 44 24 ?? 48 8d 0d ?? ?? ?? ?? 8a 04 01 0f b6 ?? 48 63 44 24 ?? 48 8d}  //weight: 10, accuracy: Low
        $x_10_8 = {48 89 c2 e8 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? 32 1d}  //weight: 10, accuracy: Low
        $x_10_9 = {ba 10 00 00 00 e8 ?? ?? ?? ?? 0f b6 ?? ?? ?? ?? ?? 32 1d}  //weight: 10, accuracy: Low
        $x_10_10 = {31 ff 4c 8d ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 0f}  //weight: 10, accuracy: Low
        $x_10_11 = {31 ff 4c 8d ?? ?? ?? ?? ?? 4c 8d ?? ?? ?? ?? ?? 31 f6 0f}  //weight: 10, accuracy: Low
        $x_10_12 = {31 db 4c 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 66}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

