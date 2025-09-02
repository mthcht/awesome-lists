rule Trojan_Win64_Lazy_MA_2147838780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MA!MTB"
        threat_id = "2147838780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 80 00 00 00 4d 8b cb eb 02 25 ed 4c 3b db eb 03 3d 0e c3 4c 0f 47 cb eb 03 68 cd 6a 4d 2b d9 eb 02 c0 5b e9 9b 00 00 00 eb 02}  //weight: 10, accuracy: High
        $x_10_2 = {4d 5a b1 4a 92 35 da 32 ad b4 4c d2 d9 6e c6 3b e6 5b 19 27 36 d2 a1 85 ae b5 1d 64 f5 36 b9 4d e3 3a 14 3f 1b 6b ad 6a 5f 9c 8c 49 8b e2 0e ee}  //weight: 10, accuracy: High
        $x_2_3 = "SHGetDiskFreeSpaceA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MA_2147838780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MA!MTB"
        threat_id = "2147838780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 3d 03 00 00 5b eb 01 45 41 5f eb 01 69 41 5e eb 01 22 41 5d eb 02 19 5a 41 5c eb 03 a0 a0 fd 5e eb 03 0d 23 a5 5f eb 02 65 72 fe 05 3b 04 00 00 eb 03}  //weight: 10, accuracy: High
        $x_10_2 = {4d 5a ef 08 d9 94 7f b3 d9 3f 5f 6b 4a c6 e4 9f 35 8d 93 55 01 79 cd 41 e5 00 6e 53 a5 81 2d c3 67 60 90 8c 0a ab 9e d5 45 70 69 b0 ab bf 5f 3a}  //weight: 10, accuracy: High
        $x_2_3 = "PathMakeUniqueName" ascii //weight: 2
        $x_2_4 = "RegOpenKeyExW" ascii //weight: 2
        $x_2_5 = "WaitMessage" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MB_2147840367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MB!MTB"
        threat_id = "2147840367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5b eb 01 23 41 5f eb 01 25 41 5e eb 02 15 d7 41 5d eb 03 1d 24 cb 41 5c eb 02 be 72 5e eb 03 05 58 f3 5f eb 01 43 fe 05 3b 04 00 00 eb 03 bf f9 11 e9 b3 01 00 00 eb 03 25 87 c2 4d 8b}  //weight: 5, accuracy: High
        $x_5_2 = {4d 5a ef 08 d9 94 7f b3 d9 3f 5f 6b 4a c6 e4 9f 35 8d 93 55 01 79 cd 41 e5 00 6e 53 a5 81 2d c3 67 60 90 8c 0a ab 9e d5 45 70 69 b0 ab bf 5f 3a}  //weight: 5, accuracy: High
        $x_2_3 = "RegisterEventSourceA" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SPRP_2147843102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SPRP!MTB"
        threat_id = "2147843102"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {48 83 ec 20 44 8b f9 4c 8d 35 2e f0 fd ff 48 83 cf ff 4d 8b e1 49 8b e8 4c 8b ea 4f 8b 94 fe 50 da 08 00 90 4c 8b 1d 31 70 02 00 4d 33 d3 41 8b cb 83 e1 3f 49 d3 ca 4c 3b d7 0f 84}  //weight: 4, accuracy: High
        $x_3_2 = {49 8d 4e 30 45 33 c0 ba a0 0f 00 00 e8 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 4c 8d 05 ?? ?? ?? ?? 48 8b d5 48 c1 fa 06 4c 89 34 03 48 8b c5 83 e0 3f 48 8d 0c c0 49 8b 04 d0 48 8b 4c c8 28 48 83 c1 02 48 83 f9 02 77 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_CAZ_2147843716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.CAZ!MTB"
        threat_id = "2147843716"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 44 24 18 48 63 4c 24 14 0f be 14 08 48 8b 44 24 28 44 8b 44 24 14 48 89 44 24 08 44 89 c0 89 54 24 04 99 41 b8 ?? ?? ?? ?? 41 f7 f8 48 63 ca 8b 54 24 04 4c 8b 4c 24 08 41 33 14 89 41 88 d2 48 8b 4c 24 18 4c 63 5c 24 14 46 88 14 19 8b 44 24 14 83 c0 ?? 89 44 24 14 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_EM_2147847283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.EM!MTB"
        threat_id = "2147847283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {47 1d c1 01 48 83 ec 10 48 31 14 24 48 31 d0 83 44 24 08 28}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_EM_2147847283_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.EM!MTB"
        threat_id = "2147847283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 0f b6 01 80 c0 0e 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 0d 83 c0 01 41 3b c0 75 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_EM_2147847283_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.EM!MTB"
        threat_id = "2147847283"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Opoafioaeoaigduighadu" ascii //weight: 1
        $x_1_2 = "Ras9ifuoaoifgajdgdi" ascii //weight: 1
        $x_1_3 = "timeGetTime" ascii //weight: 1
        $x_1_4 = "iovsoigioseiogisdj" ascii //weight: 1
        $x_1_5 = "Caoafoawfoiawjgidaj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_BY_2147847376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.BY!MTB"
        threat_id = "2147847376"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADSisgfioseijgesg" ascii //weight: 1
        $x_1_2 = "IOhjoisadjgfisdjgesig" ascii //weight: 1
        $x_1_3 = "KOiosaediogseiojgsd" ascii //weight: 1
        $x_1_4 = "Moipdeasiogsaedijgsd" ascii //weight: 1
        $x_1_5 = "Cioajsefoieafijae" ascii //weight: 1
        $x_1_6 = "HNafiajfdiaewifjaeji" ascii //weight: 1
        $x_1_7 = "Ijisajfgiesjfijasedfd" ascii //weight: 1
        $x_1_8 = "Noiaifoajifsaijdfds" ascii //weight: 1
        $x_2_9 = "WaitForSingleObject" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Lazy_BV_2147848229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.BV!MTB"
        threat_id = "2147848229"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 20 ff c0 89 44 24 20 8b 44 24 48 39 44 24 20 7d 20 48 63 44 24 20 48 8b 4c 24 40 0f be 04 01 83 f0 31 48 63 4c 24 20 48 8b 54 24 28 88 04 0a eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RDD_2147848274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RDD!MTB"
        threat_id = "2147848274"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Eriosagfoiasdgasdioh" ascii //weight: 1
        $x_1_2 = "Vaiofaeioufaeughuad" ascii //weight: 1
        $x_1_3 = "timeGetTime" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ABYV_2147848401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ABYV!MTB"
        threat_id = "2147848401"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fjiocoivjsfiiqwi" ascii //weight: 2
        $x_2_2 = "Roiaifaejf89ajdigsdcj" ascii //weight: 2
        $x_2_3 = "timeGetTime" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ABAS_2147850012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ABAS!MTB"
        threat_id = "2147850012"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {f3 0f 7f 45 97 48 89 4d 2f c7 45 a7 c0 cf 86 c9 c7 45 ab c4 c1 c0 cd c7 45 af c0 c2 d5 00 c6 45 b3 01 0f 1f 40 00 66 66 0f 1f 84 00 00 00 00 00 8d 41 97 30 44 0d 97 48 ff c1 48 83 f9 1b 72 f0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMAB_2147853391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMAB!MTB"
        threat_id = "2147853391"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\System32\\opencv_world470.dll" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\System32\\ds5w_x64.dll" ascii //weight: 1
        $x_1_3 = "cdn.axion.systems/diablo/cf4463f8-6db9-4a8b-9925-16a99a1bdec2.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GMQ_2147892540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GMQ!MTB"
        threat_id = "2147892540"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 8b f8 48 89 5d 20 48 89 75 28 48 b8 a9 8e ed 20 d1 e2 39 fe 48 89 45 10 48 89 75 18 66 0f 6f 45 10 66 0f ef 45 20 66 0f 7f 45 10 45 33 f6 4c 89 75 b0 48 c7 45 b8 0f 00 00 00 44 88 75 a0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GMP_2147892746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GMP!MTB"
        threat_id = "2147892746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 4c 24 68 48 b8 4d f0 90 8a 5b 81 b8 04 48 89 44 24 40 48 89 4c 24 48 66 0f 6f 44 24 40 66 0f ef 44 24 60 66 0f 7f 44 24 40 48 8d 44 24 40 4c 8b c3 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ARA_2147892878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ARA!MTB"
        threat_id = "2147892878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 85 20 01 00 00 48 8b 4d 00 48 8b 49 ?? 0f b6 0c 41 e8 ?? ?? ?? ?? 8b 8d 20 01 00 00 88 44 0d 10 8b 85 20 01 00 00 ff c0 89 85 20 01 00 00 eb b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ARA_2147892878_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ARA!MTB"
        threat_id = "2147892878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 c3 80 e3 ?? 80 cb ?? 24 ?? 30 d8 34 ?? 88 05}  //weight: 2, accuracy: Low
        $x_2_2 = {89 c2 80 e2 ?? 80 ca ?? 24 ?? 30 d0 34 ?? 88 05}  //weight: 2, accuracy: Low
        $x_3_3 = "test123123123123" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Lazy_ARA_2147892878_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ARA!MTB"
        threat_id = "2147892878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\PPLKiller.pdb" ascii //weight: 2
        $x_2_2 = "\\Temp\\RTCore64.sys" ascii //weight: 2
        $x_2_3 = "disablePPL" ascii //weight: 2
        $x_2_4 = "disableLSAProtection" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win64_Lazy_GNT_2147895097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GNT!MTB"
        threat_id = "2147895097"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 56 6c 48 8b 4d 28 66 0f 7f 45 40 48 89 45 38 4c 89 75 50 ff 15 ?? ?? ?? ?? 48 8d 4d 10 48 89 45 58 ff 15 ?? ?? ?? ?? 48 89 74 24 58 4c 8d 05 ?? ?? ?? ?? 48 89 5c 24 50 41 b9 ?? ?? ?? ?? 48 89 74 24 48 49 8b d6 48 89 74 24 40 33 c9 89 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NLS_2147895470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NLS!MTB"
        threat_id = "2147895470"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {eb 05 48 ff c9 75 be 48 83 ec 28 48 8d be ?? ?? ?? ?? 8b 07 09 c0 74 4a 8b 5f 04 48 8d 8c 30 ?? ?? ?? ?? 48 01 f3 48 83 c7 08 ff 96 0c d2 00 00 48 95 8a 07 48 ff c7 08 c0 74 d7}  //weight: 5, accuracy: Low
        $x_1_2 = "WowOpO.TXT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AX_2147896932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AX!MTB"
        threat_id = "2147896932"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 33 c9 44 0f b7 84 24 10 02 00 00 48 8b 94 24 08 02 00 00 48 8b 8c 24 c8 00 00 00 ff 15 ?? ?? ?? ?? 48 89 84 24 d0 00 00 00 48 83 bc 24 d0 00 00 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = "payload.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ALZ_2147897081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ALZ!MTB"
        threat_id = "2147897081"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 28 48 8d 0d f5 e2 00 00 31 d2 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {48 8d 0d c6 e2 00 00 31 d2 ff 15 be df 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NLA_2147897388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NLA!MTB"
        threat_id = "2147897388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8d 0d 75 31 1e 00 48 8b 01 48 05 ?? ?? ?? ?? 48 89 41 10 48 89 41 ?? e8 7f 43 00 00 48 8d 3d ?? ?? ?? ?? e8 f3 41 00 00 48 8b 1d 24 66 23 00}  //weight: 5, accuracy: Low
        $x_1_2 = "NZRB.x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NLA_2147897388_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NLA!MTB"
        threat_id = "2147897388"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 8d 50 02 33 c9 48 8b 03 ff 15 ?? ?? ?? ?? e8 13 07 00 00 48 8b d8 48 83 38 00 74 14}  //weight: 5, accuracy: Low
        $x_5_2 = {48 8d 4c 24 20 e8 1e e6 ff ff 48 8d 15 5f 9a 04 00 48 8d 4c 24 ?? e8 dd 1e 00 00 cc 33 c0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NL_2147899138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NL!MTB"
        threat_id = "2147899138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 85 ff 48 0f 44 f8 33 c0 48 83 ff e0 77 18 48 8b 0d ?? ?? ?? ?? 8d 50 08 4c 8b c7}  //weight: 2, accuracy: Low
        $x_2_2 = {75 b7 48 8b 1d ?? ?? ?? ?? 48 8b cb e8 c8 17 ff ff 48 83 25 9c 9e 0e 00 00 48 83 27 ?? c7 05 8a c6 0e 00 01 00 00 00 33 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NL_2147899138_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NL!MTB"
        threat_id = "2147899138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 c3 10 48 85 db 74 35 8b 4d 60 44 8b cf 44 89 74 24 28 4c 8b c6 ba 01 00 00 00 48 89 5c 24 20 ff 15 20 c1 01 00 33 ff 85 c0 75 39 48 8d 4b f0 81 39 dd}  //weight: 2, accuracy: High
        $x_1_2 = {33 c0 48 8b 4d 00 48 33 cd e8 bb 05 00 00 48 8b 5d 30 48 8b 75 38 48 8b 7d 40 4c 8b 6d 48 48 8d 65 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NL_2147899138_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NL!MTB"
        threat_id = "2147899138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ConsoleApplication2.pdb" ascii //weight: 1
        $x_1_2 = "download/football.txt" ascii //weight: 1
        $x_1_3 = "mysuperstackoverflow" ascii //weight: 1
        $x_1_4 = "156.245.19.127" ascii //weight: 1
        $x_1_5 = "InternetReadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NL_2147899138_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NL!MTB"
        threat_id = "2147899138"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Killing self" ascii //weight: 1
        $x_1_2 = "Restarting self" ascii //weight: 1
        $x_1_3 = "CMD session closed" ascii //weight: 1
        $x_1_4 = "C:\\Users\\localadmin\\Downloads\\Lilith-master\\Lilith-master\\x64\\Release\\Lilith.pdb" ascii //weight: 1
        $x_1_5 = "CMD session opened" ascii //weight: 1
        $x_1_6 = "Xe#vLLD PDB" ascii //weight: 1
        $x_1_7 = "lilithRELEASE.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RA_2147900176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RA!MTB"
        threat_id = "2147900176"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "bardg\\Documents\\diablo\\client\\bin\\x64\\Release\\client.pdb" ascii //weight: 5
        $x_1_2 = "a={|vwjdd(fmkm{{izq(egl" ascii //weight: 1
        $x_1_3 = "ajTSYRJNanDNI.JGOLBA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RB_2147900681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RB!MTB"
        threat_id = "2147900681"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GOfKoBH.(*X_Exr0VpkD).pxroc1" ascii //weight: 1
        $x_1_2 = {1b 48 8b 05 50 b4 57 00 49 89 43 08 48 89 1d 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RC_2147900682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RC!MTB"
        threat_id = "2147900682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e2 99 ea f4 6e c4 16 cf f3 6b e8 b5 97 f8 0e 21}  //weight: 1, accuracy: High
        $x_1_2 = "IooHIsa1BYJ.(*AyxWYUb).IsLoopback" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RC_2147900682_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RC!MTB"
        threat_id = "2147900682"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 ba 00 10 00 00 00 00 00 00 49 b8 ?? ?? 00 00 00 00 00 00 65 48 8b 04 25 60 00 00 00 48 8b 40 10 48 01 c2 49 01 c0 4c 8b ca 48 31 0a 48 83 c2 08 49 3b d0 72 f4 41 ff e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_DAS_2147901192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.DAS!MTB"
        threat_id = "2147901192"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {80 74 24 27 ?? 34 ?? c6 44 24 20 30 88 44 24 28 48 8d 44 24 20 49 ff c0 42 80 3c 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NY_2147902078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NY!MTB"
        threat_id = "2147902078"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c9 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 0d 40 00 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 00 e0 0e 00}  //weight: 5, accuracy: Low
        $x_1_2 = "StickyNotes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ZBA_2147902338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ZBA!MTB"
        threat_id = "2147902338"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 ff c0 49 63 c8 42 0f b6 04 09 42 88 04 0e 48 8b 44 24 ?? 88 14 01 4c 8b 4c 24 ?? 42 0f b6 0c 0e 48 03 ca 0f b6 c1 42 0f b6 0c 08 41 30 0c 1b 49 ff c3 49 81 fb e7 d6 07 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMMC_2147905230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMMC!MTB"
        threat_id = "2147905230"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stop Trying To Reverse You No Life Faggot!" ascii //weight: 2
        $x_2_2 = "You are running this program already" ascii //weight: 2
        $x_2_3 = "type=checkblacklist" ascii //weight: 2
        $x_2_4 = "xxxx?xxxx????xxx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AV_2147905831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AV!MTB"
        threat_id = "2147905831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 01 fe c8 88 01 48 ff c1 48 ff ca 75 f1}  //weight: 1, accuracy: High
        $x_1_2 = "SDHEHREJRIET7IJYRIK7Y7I6UKKTHKJHTGKG" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AE_2147906062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AE!MTB"
        threat_id = "2147906062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 8d 04 2c 48 8b 50 08 4c 8b 18 4c 31 ca 4d 31 d3 4c 09 da 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {4a 00 50 01 4a 00 e8 54 4d 00 28 f8 18 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_EE_2147906109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.EE!MTB"
        threat_id = "2147906109"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-workspace.pdb" ascii //weight: 1
        $x_1_2 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
        $x_1_3 = "certutil -hashfile " ascii //weight: 1
        $x_1_4 = "&& timeout /t 5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZY_2147906185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZY!MTB"
        threat_id = "2147906185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 03 c6 4c 89 64 24 ?? 48 89 45 ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? 48 8d 54 24 ?? ff 15 ?? ?? ?? ?? 48 8b 4c 24 ?? ff 15 ?? ?? ?? ?? 49 8b cd e8}  //weight: 5, accuracy: Low
        $x_5_2 = {44 8b 03 8b 53 f8 4d 03 c5 44 8b ?? fc 49 03 d6 48 8b 4c 24 ?? 4c 89 64 24 ?? ff 15 ?? ?? ?? ?? 0f b7 46 ?? 48 8d 5b ?? ff c7 3b f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZZ_2147906216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZZ!MTB"
        threat_id = "2147906216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {41 5f 41 5e 41 5d 41 5c 5f 5e 5d c3 30 40 02 00 91 40 02 00 91 40 02 00 45 40 02 00 45 40 02 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZZ_2147906216_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZZ!MTB"
        threat_id = "2147906216"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 74 24 21 39 80 74 24 22 3a 80 74 24 23 3b 80 74 24 24 3c 80 74 24 25 3d 80 74 24 26 3e 80 74 24 27 3f 66 89 4c 24 28 80 f1 40 80 74 24 29 41 34 42 c6 44 24 20 58 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_CN_2147906367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.CN!MTB"
        threat_id = "2147906367"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 4e 80 35 ?? ?? ?? 00 35 80 35 ?? ?? ?? 00 36 80 35 ?? ?? ?? 00 37 80 35 ?? ?? ?? 00 38 80 35 ?? ?? ?? 00 39 80 35 ?? ?? ?? 00 3a 80 35 ?? ?? ?? 00 3b 80 35 ?? ?? ?? 00 3c 80 35 ?? ?? ?? 00 3d 80 35 ?? ?? ?? 00 3e 34 3f 88 05}  //weight: 5, accuracy: Low
        $x_5_2 = {74 4e 80 35 ?? ?? ?? 00 31 80 35 ?? ?? ?? 00 32 80 35 ?? ?? ?? 00 33 80 35 ?? ?? ?? 00 34 80 35 ?? ?? ?? 00 35 80 35 ?? ?? ?? 00 36 80 35 ?? ?? ?? 00 37 80 35 ?? ?? ?? 00 38 80 35}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Lazy_RK_2147906788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RK!MTB"
        threat_id = "2147906788"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 49 89 43 b8 49 89 4b c0 48 8d 05 ?? ?? ?? ?? 49 89 4b d0 4d 8d 4b b8 49 89 4b d8 48 8b da 49 89 4b e0 44 8d 41 01 49 89 43 c8 89 4c 24 50 49 89 4b f0 48 8b cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RK_2147906788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RK!MTB"
        threat_id = "2147906788"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PenaJ\\Downloads\\Osiris\\output\\build\\osiris.pdb" ascii //weight: 1
        $x_1_2 = "start cmd /C \"color b && title Error && echo" ascii //weight: 1
        $x_1_3 = "certutil -hashfile " ascii //weight: 1
        $x_1_4 = "&& timeout /t 5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_KAF_2147907243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.KAF!MTB"
        threat_id = "2147907243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 00 0f b7 8c 24 ?? ?? ?? ?? 33 c1 0f b7 8c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ACC_2147907647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ACC!MTB"
        threat_id = "2147907647"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b d0 33 0f b6 c1 ff c1 2a c2 04 36 41 30 40 ff 83 f9 1d 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMMH_2147907937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMMH!MTB"
        threat_id = "2147907937"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 d3 ea 45 02 c0 80 e2 01 44 0a c2 41 0f b7 d2 66 d3 ea 45 02 c0 0f b7 4d 6f 80 e2 01 44 0a c2 44 88 07 48 ff c7 49 83 e9 01 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 43 0e 48 83 eb 10 66 31 45 ?? 45 3b f7 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SZ_2147908624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SZ!MTB"
        threat_id = "2147908624"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Loading Blocker: " ascii //weight: 1
        $x_1_2 = "Close Modern Warfare Before You Load The Driver" ascii //weight: 1
        $x_1_3 = "Loader.pdb" ascii //weight: 1
        $x_1_4 = "taskkill /FI \"IMAGENAME eq dnSpy.exe" ascii //weight: 1
        $x_1_5 = "taskkill /FI \"IMAGENAME eq HTTPDebuggerUI.exe" ascii //weight: 1
        $x_1_6 = "taskkill /FI \"IMAGENAME eq ida.exe" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_8 = "Blocker Injector1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RO_2147909169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RO!MTB"
        threat_id = "2147909169"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {44 31 f5 41 5e 55 81 34 24 91 87 ff 5d 59 81 f1 91 87 ff 5d 5d 44 01 f1 41 5e 48 81 ec 08 00 00 00 41 56 8f 04 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RS_2147910167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RS!MTB"
        threat_id = "2147910167"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c4 41 f7 e0 41 8b c0 2b c2 d1 e8 03 c2 c1 e8 05 0f be c0 6b c8 ?? 41 8a c0 2a c1 41 02 c7 41 30 01 44 03 c7 4c 03 cf 41 83 f8 ?? 7c d1}  //weight: 1, accuracy: Low
        $x_1_2 = "khxdled\\santo\\build\\santo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RT_2147910168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RT!MTB"
        threat_id = "2147910168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c4 41 f7 e0 c1 ea ?? 0f be c2 6b c8 ?? 41 8a c0 2a c1 41 02 c7 41 30 01 44 03 c7 4c 03 cf 41 83 f8 11 7c da}  //weight: 1, accuracy: Low
        $x_1_2 = "khxdled\\santo\\build\\santo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RU_2147911217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RU!MTB"
        threat_id = "2147911217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 0f af f8 49 8b c2 48 f7 e7 48 c1 ea 07 48 69 c2 ?? ?? ?? ?? 48 2b f8 41 8a c8 80 e1 07 c0 e1 03 48 0f be 95 ?? ?? ?? ?? 48 d3 fa 40 32 fa 49 8b c2 49 f7 e1 48 c1 ea 07 48 69 c2 ?? ?? ?? ?? 49 8b c9 48 2b c8 40 32 f9 42 30 bc 05 ?? ?? ?? ?? 4d 03 c3 4c 03 cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RW_2147911806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RW!MTB"
        threat_id = "2147911806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 00 41 b8 81 00 00 00 89 c2 4c 89 c1 41 89 c0 41 80 e0 0f c0 ea 04 45 8d 48 30 45 8d 58 37 41 80 f8 0a 45 0f b6 c1 45 0f b6 cb 45 0f 42 c8 44 88 4c 0c 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RW_2147911806_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RW!MTB"
        threat_id = "2147911806"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 04 b7 48 05 14 01 00 00 48 89 84 24 f0 00 00 00 8b 40 fc 89 84 24 ac 00 00 00 48 6b c6 18 48 8d 14 07 48 83 c2 20 48 89 94 24 f8 00 00 00 48 8b 42 f8 48 8d 8c 24 d0 00 00 00 48 89 41 10}  //weight: 1, accuracy: High
        $x_1_2 = "Lazy instance has previously been poisonedOnce" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_HNC_2147912001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.HNC!MTB"
        threat_id = "2147912001"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 61 64 67 61 65 6c 61 64 69 61 64 64 61 83 a5 a2 a3 a6 55 6d 55 64 67 61 65 6c 61 66 63}  //weight: 1, accuracy: High
        $x_1_2 = {96 62 64 56 54 88 99 a7 a8 7d 78 71 56 56 63 72 41 3e b0 84 00 00 5a 85 00 00 66 64 69 73 6b 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ZZ_2147912273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ZZ!MTB"
        threat_id = "2147912273"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 0c 11 66 33 cb 66 89 0a 48 8d 52 02 49 83 e8 01 75}  //weight: 1, accuracy: High
        $x_1_2 = "hdfzpysvpzimorhk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMAA_2147912717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMAA!MTB"
        threat_id = "2147912717"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0b 49 8d 14 18 48 83 fa 64 73 ?? 0f b6 c1 80 e9 ?? 34 ?? 0f b6 c9 f6 c2 ?? 0f b6 c0 0f 45 c8 49 8b c1 48 8b d3 88 0c 03 48 ff c3 49 8d 04 18 49 3b c2 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMAD_2147912887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMAD!MTB"
        threat_id = "2147912887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 09 33 c8 8b c1 e9 [0-30] 88 01 8b 44 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMAD_2147912887_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMAD!MTB"
        threat_id = "2147912887"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 0f b6 08 43 8d 14 10 0f b6 c1 4d 8d 40 ?? 34 ?? 80 e9 ?? f6 c2 ?? 0f b6 c0 0f b6 c9 0f 45 c8 4b 8d 04 02 43 88 4c 18 ?? 49 3b c1 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AI_2147913601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AI!MTB"
        threat_id = "2147913601"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 2b 95 94 e8 07 39 bf 8e bc 44 5a 9d 8d 01 1d 82 5d 41 97 b0 95 b8 50 4e 91 d6 79 5a 95 25 f2 54 9e 08 f9 74 41}  //weight: 2, accuracy: High
        $x_2_2 = {56 bf 7e c6 1d 0f f3 38 02 00 00 80 71 79 82 d1 6f 46 9d 05 79 f1 25 a1 b6 68 11 3e 4e 6e 8d 22}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GPD_2147915116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GPD!MTB"
        threat_id = "2147915116"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 fc 01 0f b7 c8 66 2b ca 66 31 4c 45 d0 48 ff c0 48 83 f8 15 72 ec c6 45 fc 00 48 8d 45 d0 49 c7 c0 ff ff ff ff 49 ff c0 66 42 83 3c 40 00 75 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZM_2147915879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZM!MTB"
        threat_id = "2147915879"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 d2 c7 45 f0 38 02 00 00 8d 4a 02 ff 15 ?? ?? ?? ?? 48 8b c8 48 8d 55 f0 48 8b d8 ff 15 ?? ?? ?? ?? 83 f8 01 ?? ?? 48 8d 55 f0 48 8b cb ff 15 ?? ?? ?? ?? 83 f8 01 75}  //weight: 5, accuracy: Low
        $x_1_2 = {9b 4e 4b 73 66 cf 4e 72 9b 4e 4a 73 e7 cf 4e 72 9b 4e 4d 73 ed cf 4e 72 eb cf 4e 72 e9 cf 4e 72 ed 4e 4b 73 c3 cf 4e 72 ed 4e 4a 73 fb cf 4e 72}  //weight: 1, accuracy: High
        $x_1_3 = {43 56 45 2d 32 30 32 34 2d 33 30 30 38 38 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 70 6f 63 2e 70 64 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AZL_2147916156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AZL!MTB"
        threat_id = "2147916156"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e9 1e 33 c8 69 c9 65 89 07 6c 03 ca 89 4c 95 94 8b c1 48 ff c2 49 3b d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_WCD_2147916494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.WCD!MTB"
        threat_id = "2147916494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Go build ID: \"a2XE2MdOg2bFzkApzkl9/" ascii //weight: 5
        $x_5_2 = "Go build ID: \"4B8-iyNma34aKyyPriEp/" ascii //weight: 5
        $x_1_3 = "DeleteSelf" ascii //weight: 1
        $x_1_4 = "InjectProcessRemote" ascii //weight: 1
        $x_1_5 = "DllInjectSelf" ascii //weight: 1
        $x_1_6 = "Steal_token" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Lazy_NK_2147916633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NK!MTB"
        threat_id = "2147916633"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-48] 5c 00 73 00 72 00 63 00 5c 00 78 00 36 00 34 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 74 00 75 00 6c 00 70 00 69 00 63 00 61 00 6c 00 2e 00 70 00 64 00 62 00}  //weight: 3, accuracy: Low
        $x_3_2 = {43 3a 5c 55 73 65 72 73 5c [0-48] 5c 73 72 63 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 75 6c 70 69 63 61 6c 2e 70 64 62}  //weight: 3, accuracy: Low
        $x_2_3 = "Fontello project" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Lazy_WC_2147917645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.WC!MTB"
        threat_id = "2147917645"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "navegador/logger.Configure" ascii //weight: 1
        $x_1_3 = "main.Execute" ascii //weight: 1
        $x_1_4 = "navegador/cmd/navegador" ascii //weight: 1
        $x_1_5 = "navegador/logger.(*Logger).SetVerbose" ascii //weight: 1
        $x_1_6 = "YsImfSBoP9QPYL0xyKJPq0gcaJdG3rInoqxTWbfQu9M=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GPB_2147917860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GPB!MTB"
        threat_id = "2147917860"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Bivaji Coms\\BivaApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GBN_2147919382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GBN!MTB"
        threat_id = "2147919382"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {66 f7 df 41 32 f3 41 80 ea 9f 4e 8d 5c 1c 30 4d 8b 54 43 f8}  //weight: 5, accuracy: High
        $x_5_2 = {48 b8 d3 6d 18 e2 b2 55 66 d6 48 89 44 24 40 48 89 4c 24 48 66 0f 6f 44 24 40 66 0f ef 44 24 60 66 0f 7f 44 24 40 48 8d 44 24 40 4c 8b c3 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_TZ_2147919801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.TZ!MTB"
        threat_id = "2147919801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID:" ascii //weight: 2
        $x_2_2 = "ThunderKitty-Grabber" ascii //weight: 2
        $x_2_3 = "tokengrabber.SetTelegramCredentials" ascii //weight: 2
        $x_2_4 = "tokengrabber.init" ascii //weight: 2
        $x_2_5 = "tokengrabber.SendDMViaAPI" ascii //weight: 2
        $x_1_6 = "tokengrabber.sendMessage" ascii //weight: 1
        $x_1_7 = "defender.Disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_CZ_2147919987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.CZ!MTB"
        threat_id = "2147919987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "utils/browsers.History" ascii //weight: 1
        $x_2_2 = "ThunderKitty-Grabber/utils/browsers.Login" ascii //weight: 2
        $x_2_3 = "ThunderKitty-Grabber/utils/tokengrabber.init" ascii //weight: 2
        $x_1_4 = "browsers.dataBlob" ascii //weight: 1
        $x_1_5 = "defender.Disable" ascii //weight: 1
        $x_1_6 = "browsers.CreditCard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GXB_2147920185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GXB!MTB"
        threat_id = "2147920185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f 6e c8 66 0f 73 f9 0e 66 0f eb cb 66 0f db ce 66 0f 6f d6 66 0f df d0 66 0f eb d1 66 0f 6f c2 66 0f fc 05 ?? ?? ?? ?? 66 0f 6f c8 66 0f da 0d ?? ?? ?? ?? 66 0f 74 c8 66 0f db 0d ?? ?? ?? ?? 66 0f eb ca f3 0f 7f 0c 2f 48 8d 45 10 48 83 c5 20 4c 39 e5 48 89 c5 0f 86}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_DA_2147920317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.DA!MTB"
        threat_id = "2147920317"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 8b 07 49 8b c6 48 f7 e1 48 c1 ea 03 48 6b c2 0f 48 2b c8 0f b6 44 0c 20 43 32 04 0a 43 88 04 02 41 ff c3 49 ff c2 49 63 cb 48 3b 4b 10}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 0f 49 8b c6 49 f7 e1 48 c1 ea 02 48 8d 04 52 48 03 c0 4c 2b c8 42 0f b6 44 0d b7 43 32 04 02 41 88 04 0a 41 ff c3 49 ff c2 4d 63 cb 4c 3b 4b 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Lazy_IZ_2147920730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.IZ!MTB"
        threat_id = "2147920730"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go build ID:" ascii //weight: 2
        $x_2_2 = "eO9FjRExQ9G9I3RTzDAEYhuS5KFy5RYudrnCvKSr8Z0=" ascii //weight: 2
        $x_1_3 = "ILa9j1onAAMadBsyyUJv5cack8Y1WT26yLj/V+ulKp8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_RZ_2147921606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.RZ!MTB"
        threat_id = "2147921606"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Go buildinf:" ascii //weight: 2
        $x_2_2 = "/thesunwave/pososyamba_bot" ascii //weight: 2
        $x_1_3 = "mTUQ2QPcCF65D8a5eeKxIAqOPcrxsxO6CzHR4s0" ascii //weight: 1
        $x_1_4 = "zPAT6CGy6wXeQ7NtTnaTerfKOsV6V6F8agHXFiazDkg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GMN_2147921670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GMN!MTB"
        threat_id = "2147921670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 89 08 66 89 5c 24 68 48 89 5c 24 6e 48 89 5c 24 76 33 c0 66 89 44 24 6b 88 44 24 6d 66 89 44 24 6e 88 44 24 70 66 89 44 24 71 88 44 24 73 66 89 44 24 74 88 44 24 76 66 89 44 24 77 88 44 24 79 66 89 44 24 7a 88 44 24 7c 89 5c 24 34 89 5c 24 64 0f 28 44 24 20 66 0f 7f 44 24 20 4c 8d 85 b0 01 00 00 48 8d 54 24 20 48 8d 4c 24 30}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ROW_2147921725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ROW!MTB"
        threat_id = "2147921725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e0 c1 ea 04 0f be c2 6b c8 32 41 8a c0 2a c1 04 32 41 30 01 41 ff c0 49 ff c1 41 83 f8 02 7c d9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GM_2147922335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GM!MTB"
        threat_id = "2147922335"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ChromeFuckNewCookies" ascii //weight: 2
        $x_2_2 = "/c timeout /t 10 & del /f /q" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MBXY_2147922343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MBXY!MTB"
        threat_id = "2147922343"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c8 c1 e9 1e 33 c8 69 c1 65 89 07 6c 03 c2 89 84 94 84 0c 00 00 48 ff c2 48 81 fa 70 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMZ_2147922650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMZ!MTB"
        threat_id = "2147922650"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 04 24 48 8b 4c 24 10 8a 54 24 0f 32 14 01 88 14 01 48 83 c0 01 48 89 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZT_2147922878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZT!MTB"
        threat_id = "2147922878"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 8b c9 66 90 8d 41 8b 30 04 0a 48 ff c1 48 83 f9 0c 72 f1 c6 42 0d 00 4c 89 4d a8 48 8d 42 0c 48 3b d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AL_2147924227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AL!MTB"
        threat_id = "2147924227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 c2 69 d0 93 01 00 01 0f b6 41 ff e9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MBXX_2147925166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MBXX!MTB"
        threat_id = "2147925166"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Desktop\\solo\\examples\\example_win32_directx11\\Release\\calculator.p" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NM_2147925657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NM!MTB"
        threat_id = "2147925657"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 48 89 c3 48 ff c0 48 2d 00 10 3e 00 48 2d 24 2f 0c 10 48 05 1b 2f 0c 10}  //weight: 1, accuracy: High
        $x_2_2 = {80 3b cc 75 ?? c6 03 00 bb 00 10 00 00 68 d0 18 0e 31 68 18 e3 2b 4f 53 50 e8 ?? ?? ?? ?? 48 83 c0 14 48 89 44 24 10 5b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SOK_2147925845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SOK!MTB"
        threat_id = "2147925845"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 eb 03 d3 c1 fa 05 8b c2 c1 e8 ?? 03 d0 0f be c2 6b c8 33 0f b6 c3 ff c3 2a c1 04 37 41 30 40 ff 83 fb 17 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_THK_2147925871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.THK!MTB"
        threat_id = "2147925871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c0 e1 02 49 8b d1 48 d3 ea 66 41 23 d6 42 ?? ?? 44 44 50 66 33 d0 41 0f b7 c0 66 41 2b c2 66 33 d0 66 ?? ?? 54 44 50 49 ff c0 49 83 f8 22 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ZZK_2147925955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ZZK!MTB"
        threat_id = "2147925955"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 50 7a 30 14 08 48 ff c0 48 83 f8 0a 72 f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GTZ_2147926142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GTZ!MTB"
        threat_id = "2147926142"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {55 48 89 e5 48 83 ec ?? 41 81 f1 ?? ?? ?? ?? 48 83 ec ?? 8b f0 41 81 f2 ?? ?? ?? ?? 33 c0 48 83 c0}  //weight: 10, accuracy: Low
        $x_10_2 = {55 48 89 e5 48 83 ec ?? 33 c0 41 81 f0 ?? ?? ?? ?? 41 81 f1 ?? ?? ?? ?? 8b c8 41 81 f2 ?? ?? ?? ?? 48 83 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Lazy_GNS_2147927754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GNS!MTB"
        threat_id = "2147927754"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 30 03 49 89 dc 00 5b ?? 01 64 24 ?? 41 5c 0c ?? 85 38}  //weight: 5, accuracy: Low
        $x_5_2 = {44 67 31 20 51 10 10 86 0e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_YAF_2147927862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.YAF!MTB"
        threat_id = "2147927862"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 0f b6 17 8b cb 48 33 d1 c1 eb 08 0f b6 ca 49 ff c7 33 5c 8c 40 48 85 ed}  //weight: 5, accuracy: High
        $x_5_2 = "Software\\Yuwei Qusi\\Oovi Appc" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_YAG_2147927871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.YAG!MTB"
        threat_id = "2147927871"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {48 8d 3f 32 c3 48 8d 3f 48 8d 3f 48 8d 3f 2a c3 48 8d 3f 48 8d 3f 48 8d 3f 48 8d 3f 32 c3 48 8d 3f 2a c3 48 8d 3f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMCP_2147927902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMCP!MTB"
        threat_id = "2147927902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 33 c9 ff 15 [0-30] 33 d2 33 c9 ff 15 [0-30] 45 33 c0 48 8d 15 ?? ?? ?? ?? 33 c9 ff 15 [0-30] 33 d2 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_TYC_2147928518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.TYC!MTB"
        threat_id = "2147928518"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f7 e1 c1 ea 04 0f be c2 6b d0 34 0f b6 c1 ff c1 2a c2 04 ?? 41 30 40 ff 83 f9 0c 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NP_2147928692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NP!MTB"
        threat_id = "2147928692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /c {}" ascii //weight: 2
        $x_1_2 = "C:\\Windows\\System32\\" ascii //weight: 1
        $x_1_3 = "X\\d{6}\\.dat$" ascii //weight: 1
        $x_1_4 = "{}Windows\\System32\\backup_f64.exe" ascii //weight: 1
        $x_1_5 = "start \"\" \"{}\"" ascii //weight: 1
        $x_1_6 = "{}Windows\\System32\\czero_log" ascii //weight: 1
        $x_1_7 = "schtasks /create /tn \"{}\" /sc ONLOGON /tr \"{}\" /rl HIGHEST /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ALL_2147929272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ALL!MTB"
        threat_id = "2147929272"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f ba f0 0f 49 8d 8f 28 ca 4c 02 48 8d 15 bd 81 03 00 41 89 87 8c 22 db 01}  //weight: 3, accuracy: High
        $x_2_2 = {45 33 c0 48 89 44 24 28 48 8d 53 04 4c 8d 4d ?? c7 44 24 20 00 01 00 00 48 8d 0d 4a 98 03 00}  //weight: 2, accuracy: Low
        $x_1_3 = "SAKURATECH\\Project\\B290_OneDigiMMIC\\MSVC\\mr12e\\mr12e\\mr12e\\x64\\Release\\mr12e.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMCW_2147929314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMCW!MTB"
        threat_id = "2147929314"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 c0 40 00 00 10 00 00 00 4e 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 a0 ae 00 00 00 d0 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AMCW_2147929314_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AMCW!MTB"
        threat_id = "2147929314"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 55 48 8b ec 48 83 ec 50 c7 45 d0 ?? ?? ?? ?? 33 c0 c7 45 d4 ?? ?? ?? ?? ba ?? ?? ?? ?? c7 45 d8 ?? ?? ?? ?? c7 45 dc [0-53] c6 45 fc 01 8d 0c 02 66 31 4c 45 d0 48 ff c0 48 83 f8 15 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AOP_2147930767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AOP!MTB"
        threat_id = "2147930767"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 d1 30 c1 31 c0 28 c8 88 44 24 ?? 8b 4c 24 08 48 8b 54 24 18 44 8a 44 24 ?? 8a 44 24 06 44 30 c0 4c 63 c1 42 88 04 02 83 c1 01 83 f9 13 89 4c 24 ?? 88 44 24 2f 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GNN_2147932689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GNN!MTB"
        threat_id = "2147932689"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {43 8d 0c 00 44 8b c9 41 81 f1 b7 0d c1 04 45 85 c0 44 0f 49 c9 43 8d 14 09 8b ca 81 f1 b7 0d c1 04 45 85 c9 0f 49 ca ff c3 89 4f fc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ALY_2147932693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ALY!MTB"
        threat_id = "2147932693"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 44 24 40 33 db 89 05 0f a3 75 00 8b 44 24 24 89 05 09 a3 75 00 8b 44 24 48 89 05 03 a3 75 00 89 5c 24 60 88 1d fe a2 75 00 e8}  //weight: 2, accuracy: High
        $x_1_2 = {48 89 74 24 40 b8 20 00 00 00 8b 74 24 30 c1 ee 05 8b ce 48 f7 e1 48 c7 c1 ff ff ff ff 48 89 7c 24 20 48 8d 15 2b 65 6b 00 48 0f 42 c1 48 8b c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_HGP_2147932820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.HGP!MTB"
        threat_id = "2147932820"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f 10 4c d7 08 4c 89 44 24 38 41 b9 20 00 00 00 4c 89 44 24 30 49 8b cc 66 0f 7e c8 f2 0f 11 44 24 60 f3 0f 7e 44 d7 10 ba 04 00 35 83 0f b7 c0 89 44 24 50 66 48 0f 7e c8 44 89 44 24 28 48 c1 e8 30 44 89 44 24 54}  //weight: 2, accuracy: High
        $x_1_2 = "System\\CurrentControlSet\\Services\\Amaterasu" ascii //weight: 1
        $x_1_3 = "Registry\\Machine\\System\\CurrentControlSet\\Services\\Amaterasu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GNE_2147933061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GNE!MTB"
        threat_id = "2147933061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {61 f3 56 1d ?? ?? ?? ?? 1b f3 56 1d ?? ?? ?? ?? e2 f0 56 1d ?? ?? ?? ?? 2b f3 56 1d}  //weight: 10, accuracy: Low
        $x_1_2 = "UwUdisRAT.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHLA_2147933460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHLA!MTB"
        threat_id = "2147933460"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 8b c2 4a 8d 0c 2a 83 e0 7f 48 ff c2 0f b6 84 18 80 00 00 00 32 04 0f 88 01 48 3b d5 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GD_2147934060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GD!MTB"
        threat_id = "2147934060"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4c 8b 84 24 ?? ?? ?? ?? 8a 11 4d 8b 00 41 32 54 00 08 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GTK_2147934731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GTK!MTB"
        threat_id = "2147934731"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b6 5e ff 73 69 02 63 31 88 3f a5 2c e4 53 32 1f 80 15 ?? ?? ?? ?? 30 cd 46}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GTP_2147934844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GTP!MTB"
        threat_id = "2147934844"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 f6 db 41 0f 95 c3 4f 8d 9c 1b ?? ?? ?? ?? c1 6c 24 ?? 4c 48 c7 44 24 ?? 80 5b 76 e7 4c 8b 5c 24 ?? 48 81 74 24 ?? 34 72 b2 a5 80 74 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_HHM_2147935725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.HHM!MTB"
        threat_id = "2147935725"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 f7 e8 41 03 d0 c1 fa 05 8b c2 c1 e8 1f 03 d0 b8 01 00 00 00 2a c2 0f be c0 6b c8 39 41 02 c8 41 ff c0 41 30 49 ff 41 83 f8 11 7c ca}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_PIN_2147935942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.PIN!MTB"
        threat_id = "2147935942"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {49 8b c9 48 2b c8 40 32 f9 49 8b c7 49 f7 e2 48 c1 ea 07 48 69 c2 ff 00 00 00 49 8b ca 48 2b ?? 40 32 f9 41 32 f8 42 30 7c 05 c8 49 ff c0 4d 03 cd 49 83 c2 06 4d 3b ce 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_A_2147936261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.A!MTB"
        threat_id = "2147936261"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 81 f3 77 9e b4 57 48 01 d8 03 f7 48 81 ec 28 00 00 00 89 b5 94 fa ff ff 29 b5 54 f9 ff ff 33 fe 81 c7 13 c3 00 00 66 81 ef 35 eb 89 b5 b8 f9 ff ff 81 c6 38 9c 00 00 c7 85 1c fa ff ff 5f 07 00 00 81 ee 95 12 00 00 81 ef f4 24 00 00 81 f7 99 c8 00 00 e9 4e e6 ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GVA_2147936311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GVA!MTB"
        threat_id = "2147936311"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b 45 e0 c7 05 ?? ?? ?? ?? 88 15 00 00 48 8b 4d f8 8a 14 01 4c 8b 45 e8 41 88 14 00 48 05 01 00 00 00 4c 8b 4d f0 4c 39 c8 48 89 45 e0}  //weight: 1, accuracy: Low
        $x_1_2 = "RerueelfhnrsrWrl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_TVZ_2147937226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.TVZ!MTB"
        threat_id = "2147937226"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 f7 12 da 4b 41 f7 e8 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 ?? 41 0f b6 c0 2a c1 04 34 41 30 02 41 ff c0 4d 8d 52 01 41 83 f8 13 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_VVZ_2147937235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.VVZ!MTB"
        threat_id = "2147937235"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b8 1f 85 eb 51 4d 8d 40 01 f7 e1 c1 ea 04 0f be c2 6b d0 ?? 0f b6 c1 ff c1 2a c2 04 37 41 30 40 ff 83 f9 04 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GC_2147938146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GC!MTB"
        threat_id = "2147938146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "good.5dfruitjkgreat" ascii //weight: 1
        $x_1_2 = "Cwon.ttheir2Kabundantly.land" ascii //weight: 1
        $x_1_3 = "o:\\dir_for_builds\\bldObj" ascii //weight: 1
        $x_1_4 = "giveneveryn" ascii //weight: 1
        $x_1_5 = "ktreelman,Rm" ascii //weight: 1
        $x_1_6 = "sayingr7Zshe.dfruitfuldzfemalegreater" ascii //weight: 1
        $x_1_7 = "6maleyou.re,multiply,Thegreenreplenishfitselfw" ascii //weight: 1
        $x_1_8 = "vg05b3wE.Dll" ascii //weight: 1
        $x_1_9 = "sELF.eXe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GVB_2147938151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GVB!MTB"
        threat_id = "2147938151"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 03 c8 48 8b c1 0f b6 00 83 f0 36 48 8b 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 48 8b 84 24 ?? ?? ?? ?? 48 8b 8c 24 ?? ?? ?? ?? 48 03 c8 48 8b c1 0f b6 00 83 c0 12 48 8b 8c 24 ?? ?? ?? ?? 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 48 8b 84 24 ?? ?? ?? ?? 48 ff c0 48 89 84 24 ?? ?? ?? ?? 48 81 bc 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AB_2147939489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AB!MTB"
        threat_id = "2147939489"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c0 a8 e2 76 09 00 46 04 15 1f e4 10 b4 dd 01 82 3a 52 eb 20 14 ef d8 be 2c 0e 8d 42 5c 0f a0 dc fa 80 c9 4f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AC_2147939494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AC!MTB"
        threat_id = "2147939494"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f2 00 80 e2 01 45 88 c2 41 80 f2 01 41 80 e2 00 44 08 d2 41 88 c2 41 80 f2 ff 41 88 d3 41 80 f3 ff 44 88 c3 80 f3 01 45 08 da 80 cb 01 41 80 f2 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_PGY_2147939521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.PGY!MTB"
        threat_id = "2147939521"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 6d 61 6e 61 67 65 64 28 74 31 00 00 70 0b 00 00 76 31 00 00 64 0b 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60}  //weight: 1, accuracy: High
        $x_4_2 = {68 79 64 72 61 74 65 64 10 9a 13 00 00 f0 3c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 c0}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_PGL_2147939900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.PGL!MTB"
        threat_id = "2147939900"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 83 7d a0 07 48 8d 4d 88 4c 89 74 24 30 ba ?? ?? ?? ?? 48 0f 47 4d 88 45 33 c9 45 33 c0 c7 44 24 28 ?? ?? ?? ?? c7 44 24 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_PLV_2147941797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.PLV!MTB"
        threat_id = "2147941797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 d2 f7 f1 3d ab 10 f6 8f 0f 83 ?? ?? ?? ?? 48 8b 4d a8 8b 05 ?? ?? ?? ?? 31 d2 f7 35 7e 22 16 00 ba c0 cd 97 78 81 f2 43 ee 1d c9 09 d0 2d 17 c5 ec 6f 05 35 a7 e7 86 ba ed ca 60 fd 81 f2 fa 0f 8c 92 01 d0 25 31 15 d6 b4 48 83 f9 00 0f 94 c1 88 4d a7 3d 0e aa b9 ec 0f 83}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_FY_2147941865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.FY!MTB"
        threat_id = "2147941865"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6f c7 48 8d 4c 24 30 0f 57 c6 33 d2 66 0f 7f 44 24 30 ff ?? ?? ?? ?? ?? 48 89 05 e7 27 23 00 48 85 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MBZ_2147942168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MBZ!MTB"
        threat_id = "2147942168"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "schtasks.exe /create /tn \"SystemHelperTask\" /tr \"%s\" /sc onlogon /rl HIGHEST /f" ascii //weight: 2
        $x_1_2 = "powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SFD_2147942779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SFD!MTB"
        threat_id = "2147942779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 0f b6 04 08 32 02 41 88 04 08 41 ff c2 49 ff c0 49 63 c2 48 3b 43 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AZLY_2147942839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AZLY!MTB"
        threat_id = "2147942839"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {66 89 44 24 6b 88 44 24 6d 66 89 44 24 6e 88 44 24 70 66 89 44 24 71 88 44 24 73 66 89 44 24 74 88 44 24 76 66 89 44 24 77 88 44 24 79 66 89 44 24 7a 88 44 24 7c 89 7c 24 64 0f 10 03 0f 29 45 d0 89 7c 24 34 c6 44 24 68 01 48 8d 55 50 48 8d 4c 24 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_PAD_2147943902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.PAD!MTB"
        threat_id = "2147943902"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 8b 4d b8 0f b6 14 81 88 55 a0 0f b6 45 a1 44 0f b6 0c 81 44 88 4d a1 0f b6 45 a2 0f b6 34 81 40 88 75 a2}  //weight: 3, accuracy: High
        $x_2_2 = "DisableRealtimeMonitoring" ascii //weight: 2
        $x_2_3 = "DisableBehaviorMonitoring" ascii //weight: 2
        $x_2_4 = "DisableAntiSpyware" ascii //weight: 2
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_BOE_2147944026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.BOE!MTB"
        threat_id = "2147944026"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c0 e9 03 c0 e0 05 08 c8 34 a0 41 88 04 24 49 8b 76 18 48 8b 05 ?? ?? ?? ?? 4c 01 f8 ff d0 48 98 48 8d 0d a8 17 24 00 48 3b 34 c1 0f 86}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_ETL_2147944784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.ETL!MTB"
        threat_id = "2147944784"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 84 0d a0 00 00 00 8d 41 88 30 84 0d a1 00 00 00 8d 41 89 30 84 0d a2 00 00 00 8d 41 8a 30 84 0d a3 00 00 00 8d 41 8b 30 84 0d a4 00 00 00 8d 41 8c 30 84 0d a5 00 00 00 8d 41 8d 30 84 0d a6 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_MX_2147944946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.MX!MTB"
        threat_id = "2147944946"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "start /min cmd.exe /c powershell -WindowStyle Hidden" ascii //weight: 1
        $x_5_2 = "zetolacs-cloud.top" ascii //weight: 5
        $x_5_3 = "textpubshiers.top" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AQ_2147944995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AQ!MTB"
        threat_id = "2147944995"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 44 24 40 0f be 00 44 31 e8 44 69 e0 95 e9 d1 5b 44 33 64 24 54 b8 00 ad 85 3a 3d 58 15 53 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AR_2147944997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AR!MTB"
        threat_id = "2147944997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jYR3AXLUy0BX30OQNfgSukljV5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AR_2147944997_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AR!MTB"
        threat_id = "2147944997"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {34 40 88 44 24 23 0f b6 05 46 5a 04 00 34 41 88 44 24 24 0f b6 05 3a 5a 04 00 34 42 88 44 24 25 0f b6 05 2e 5a 04 00 34 43 88 44 24 26 0f b6 05 22 5a 04 00 34 44 88 44 24 27 33 c0 66 66 66 0f 1f 84 00 00 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = {8d 48 3d 30 4c 04 20 48 ff c0 48 83 f8 08 72 f0 c6 44 24 29 00 48 8d 44 24 20 49 c7 c0 ff ff ff ff 49 ff c0 42 80 3c 00 00 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AS_2147945006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AS!MTB"
        threat_id = "2147945006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c4 48 89 84 24 00 18 00 00 45 33 e4 44 89 a4 24 c0 00 00 00 c6 84 24 d0 00 00 00 ?? b0 ?? b1 ?? b2 ?? 41 b0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZP_2147945542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZP!MTB"
        threat_id = "2147945542"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 74 24 21 35 80 74 24 22 36 80 74 24 23 37 80 74 24 24 38 80 74 24 25 39 80 74 24 26 3a 80 74 24 27 3b 66 89 4c 24 28 80 f1 3c 80 74 24 29 3d 34 3e c6 44 24 20 6c 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {80 74 24 21 36 80 74 24 22 37 80 74 24 23 38 80 74 24 24 39 80 74 24 25 3a 80 74 24 26 3b 80 74 24 27 3c 66 89 4c 24 28 80 f1 3d 80 74 24 29 3e 34 3f c6 44 24 20 6c 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
        $x_10_3 = {80 74 24 21 39 80 74 24 22 3a 80 74 24 23 3b 80 74 24 24 3c 80 74 24 25 3d 80 74 24 26 3e 80 74 24 27 3f 66 89 4c 24 28 80 f1 40 80 74 24 29 41 34 42 c6 44 24 20 6c 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_Lazy_LMD_2147945555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.LMD!MTB"
        threat_id = "2147945555"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {48 8d 3d 0f 97 04 00 67 8d 04 09 48 8d 3c c7 48 8b 77 08 48 8b 46 08 48 89 47 08 48 89 38 48 39 c7 75 1b b8 fe ff ff ff d3 c0 4c 8d ?? ?? ?? ?? ?? 41 21 04 90 75}  //weight: 15, accuracy: Low
        $x_10_2 = {48 8b 45 30 c6 00 20 48 83 c0 01 48 89 45 30 c6 00 78 48 83 c0 01 48 89 45 30 c6 00 20 48 83 c0 01 48 89 45 30 8b c6 48 c1 e0 09 48 8d ?? ?? ?? ?? ?? ?? 8b cf 48 03 c9 8b 0c c8 48 8b 55 30}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GZF_2147945905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GZF!MTB"
        threat_id = "2147945905"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 74 24 21 36 80 74 24 22 37 80 74 24 23 38 80 74 24 24 39 80 74 24 25 3a 80 74 24 26 3b 80 74 24 27 3c 66 89 4c 24 28 80 f1 3d 80 74 24 29 3e 34 3f c6 44 24 20 31 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 42 80 3c 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SX_2147945952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SX!MTB"
        threat_id = "2147945952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8b 45 10 48 8b 48 48 8b 45 fc 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 01 c8 48 8b 00 48 8b 55 18 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 24 48 8b 45 10 48 8b 48 48 8b 45 fc 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 01 c8 48 8b 40 08 eb 19}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 85 2c 04 00 00 48 98 0f b6 44 05 a0 0f b6 c8 8b 85 2c 04 00 00 01 c0 48 63 d0 48 8b 85 10 04 00 00 48 01 d0 41 89 c8 48 8d 15 ?? ?? ?? ?? 48 89 c1 e8 ?? ?? ?? ?? 83 85 2c 04 00 00 01 83 bd 2c 04 00 00 0f 7e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_SXB_2147945953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.SXB!MTB"
        threat_id = "2147945953"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 8b 85 00 07 00 00 48 8b 48 48 8b 85 c4 06 00 00 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 ?? 48 01 c8 48 8b 00 48 8b 95 c0 05 00 00 48 89 c1 e8 ?? ?? ?? ?? 85 c0 75 31 48 8b 85 00 07 00 00 48 8b 48 48 8b 85 c4 06 00 00 48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 ?? 48 01 c8 48 8b 40 08 48 89 85 c8 06 00 00 eb 1d 83 85 c4 06 00 00 01 48 8b 85 00 07 00 00 8b 40 50 39 85 c4 06 00 00}  //weight: 20, accuracy: Low
        $x_15_2 = {89 c2 89 d1 b8 ?? ?? ?? ?? 48 0f af c1 48 c1 e8 20 c1 e8 0d 69 c8 ?? ?? ?? ?? 89 d0 29 c8 01 d8 89 85 18 05 00 00 8b 85 18 05 00 00 89 c1}  //weight: 15, accuracy: Low
        $x_10_3 = {48 63 d0 48 89 d0 48 01 c0 48 01 d0 48 c1 e0 03 48 83 e8 18 48 01 c1 48 8b 85 f0 04 00 00 48 8b 95 f8 04 00 00 48 89 01 48 89 51 08 48 8b 85 00 05 00 00 48 89 41 10 48 8b 95 ?? 05 00 00 48 8d 85 c0 00 00 00 49 89 d1 4c 8d 05 ?? ?? ?? ?? ba 00 01 00 00 48 89 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AM_2147945974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AM!MTB"
        threat_id = "2147945974"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 f7 d2 89 d5 09 cd f7 d5 83 e2 ?? 25 ?? 00 00 00 09 d0 31 c8 83 f0 ?? 21 c8 89 e9 21 c1 31 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AP_2147945990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AP!MTB"
        threat_id = "2147945990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 95 c0 0f 94 c1 83 3d 86 0b 04 00 09 0f 9f c2 30 d1 89 d3 20 c3 30 c2 08 da 89 c8 30 d0 bd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHC_2147946023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHC!MTB"
        threat_id = "2147946023"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 ff c0 48 31 c2 48 8d 05 ?? ?? ?? 00 48 c7 00 00 00 00 00 48 01 38 48 8d 05 ?? ?? ?? 00 48 c7 00 00 00 00 00 4c 01 38 48 89 d0 48 8d 05 ?? ?? ?? 00 48 89 28 48 01 c2 48 31 c0}  //weight: 3, accuracy: Low
        $x_2_2 = {48 31 c2 48 31 c2 48 8d 05 ?? ?? 02 00 48 c7 00 00 00 00 00 48 01 18 48 29 c2 48 83 f2 09 48 8d 05 ?? ?? 02 00 4c 89 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHD_2147947242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHD!MTB"
        threat_id = "2147947242"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {89 08 8b 4d 03 89 48 04 0f b6 4d 07 88 48 08 0f b6 4d 08 88 48 09 48 8d 78 10 48 89 7d ef 48 89 77 38 48 8b 4d 47 48 85 c9 74 ?? 48 8b 01 48 8b d7 ff 10}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 40 01 80 3c 03 00 75 ?? 4c 8d 48 01 48 c7 44 24 20 00 00 00 00 4c 8b c3 49 8b d6 48 8b cf ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_KKA_2147947319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.KKA!MTB"
        threat_id = "2147947319"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {89 41 04 b8 00 08 00 00 41 2b c0 c1 e8 05 66 41 03 c0 66 41 89 02 33 c0 eb ?? 44 2b c8 2b d0 41 8b c0 44 89 49 04 c1 e8 05 66 44 2b c0 89 11 66 45 89 02}  //weight: 8, accuracy: Low
        $x_7_2 = {48 8b fa 41 c1 e2 08 44 0b d0 0f b6 41 02 41 c1 e2 08 44 0b d0 0f b6 41 01 41 c1 e2 08 b9 00 10 00 00 44 0b d0 48 8b 44 24 28 44 89 10 44 3b d1}  //weight: 7, accuracy: High
        $x_5_3 = {41 8b c8 48 8d 7d 00 66 f3 ab 41 0f b7 c2 48 8d 7d a0 41 8b c9 66 f3 ab 41 0f b7 c2 48 8d 7d b8 41 8b c9 66 f3 ab 41 8b c8 41 0f b7 c2 48 8d bd 80 01 00 00 66 f3 ab}  //weight: 5, accuracy: High
        $x_10_4 = "crackmy.app/" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_KKC_2147947320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.KKC!MTB"
        threat_id = "2147947320"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {48 f7 d9 48 89 54 24 70 4c 8b e2 44 8a 24 01 44 88 20 49 03 c3 44 89 a5 68 0f 00 00 83 c7 ff 75}  //weight: 20, accuracy: High
        $x_10_2 = {48 8b fa 41 c1 e2 08 44 0b d0 0f b6 41 02 41 c1 e2 08 44 0b d0 0f b6 41 01 41 c1 e2 08 b9 00 10 00 00 44 0b d0 48 8b 44 24 28}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_KAB_2147947588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.KAB!MTB"
        threat_id = "2147947588"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {49 8b 42 08 41 ff c1 48 d3 e8 41 03 c8 41 32 04 12 88 44 14 38 48 ff c2 83 f9 40 72}  //weight: 10, accuracy: High
        $x_8_2 = {4e 8d 0c 01 48 2b d1 49 ff c9 42 8a 04 0a 41 88 01 49 83 e8 01 75}  //weight: 8, accuracy: High
        $x_7_3 = {43 0f be 0c 02 49 ff c0 83 c1 20 48 63 d1 48 0f af d0 49 33 d1 48 33 c2 4d 3b c1 7c}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_KAB_2147947588_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.KAB!MTB"
        threat_id = "2147947588"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 45 fc 00 00 00 00 8b 45 f8 48 98 48 8d 15 ?? ?? 00 00 0f b6 14 10 8b 45 f8 48 98 0f b6 44 05 d0 38 c2 74}  //weight: 10, accuracy: Low
        $x_8_2 = {8b 45 2c 48 8d 15 ?? ?? 00 00 44 0f b6 04 10 0f b6 0d ?? ?? 00 00 8b 55 2c 48 8b 45 20 48 01 d0 44 89 c2 31 ca 88 10 83 45 2c 01 eb}  //weight: 8, accuracy: Low
        $x_7_3 = "VirtualAlloc failed for shellcode" ascii //weight: 7
        $x_5_4 = "Shellcode executed successfully." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHI_2147947691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHI!MTB"
        threat_id = "2147947691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 0f ef 85 d0 00 00 00 4c 89 bd e0 00 00 00 48 89 9d e8 00 00 00 66 0f ef 8d e0 00 00 00 66 0f 7f 8d 40 03 00 00 66 0f 7f 85 30 03 00 00 ff d0}  //weight: 10, accuracy: High
        $x_5_2 = {49 33 c8 48 bf ?? ?? ?? ?? ?? ?? ?? ?? 48 8b c7 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 03 c0 48 2b c8 48 63 c1 48 8b cb 4c 89 84 c5 50 02 00 00 48 8b 84 c5 50 02 00 00 ff d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHI_2147947691_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHI!MTB"
        threat_id = "2147947691"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 89 74 24 50 48 89 44 24 40 48 c7 44 24 58 00 00 00 00 48 c7 44 24 48 01 00 00 00 c7 44 24 38 28 00 00 00 c7 44 24 30 96 00 00 00 c7 44 24 28 fa 00 00 00 c7 44 24 20 dc 00 00 00}  //weight: 5, accuracy: High
        $x_3_2 = {4d 8d 48 1f 49 83 e1 e0 4d 8b d9 49 c1 eb 05 47 8b 9c 9a b0 5f 06 00 4d 03 da 41}  //weight: 3, accuracy: High
        $x_2_3 = "Cheating Engine" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GVD_2147947741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GVD!MTB"
        threat_id = "2147947741"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 ?? 8c 24 [0-5] 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01}  //weight: 2, accuracy: Low
        $x_1_2 = {48 03 d1 48 8b ca 0f b6 09 03 c8 8b c1 48 ?? 8c 24 [0-5] 48 8b 94 24 ?? ?? ?? ?? 48 03 d1 48 8b ca 88 01 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NIA_2147949563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NIA!MTB"
        threat_id = "2147949563"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DllExport" ascii //weight: 2
        $x_2_2 = {48 c1 ca 21 0f b7 c1 66 41 33 42 10 66 41 89 43 10 48 8d 04 09 48 c1 c8 20 48 03 d0 48 c1 ca 1f 66 41 33 52 12 33 c0}  //weight: 2, accuracy: High
        $x_1_3 = {4c 03 c2 49 8b c8 49 c1 e0 21 48 c1 e9 1f 49 0b c8 0f b7 c1 66 41 33 02 66 41 89 03 48 8d 04 09 48 c1 c8 20 49 0f af d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHG_2147949816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHG!MTB"
        threat_id = "2147949816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {fb 80 33 00 60 01 00 00 00 80 32 00 58 f7 00 00 ?? ?? ?? 00 98 3d}  //weight: 20, accuracy: Low
        $x_10_2 = {0b 02 0e 1d 00 fe 03 00 00 42 2f 00 00 00 ?? ?? ?? ?? ?? 00 00 10}  //weight: 10, accuracy: Low
        $x_5_3 = {20 20 20 20 20 20 20 20 f4 fd 03 00 00 10 00 00 00 f0 01 00 00 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_AHG_2147949816_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.AHG!MTB"
        threat_id = "2147949816"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {48 c7 85 c0 3f 00 00 00 00 00 00 48 c7 85 c8 3f 00 00 00 00 00 00 48 c7 85 d0 3f 00 00 00 00 00 00 48 c7 85 d8 3f 00 00 00 00 00 00 48 8d 85 a0 3f 00 00 ba 40}  //weight: 10, accuracy: High
        $x_10_2 = {48 c7 85 c0 1f 00 00 00 00 00 00 48 c7 85 c8 1f 00 00 00 00 00 00 48 c7 85 d0 1f 00 00 00 00 00 00 48 c7 85 d8 1f 00 00 00 00 00 00 48 8d 85 a0 1f 00 00 ba 40}  //weight: 10, accuracy: High
        $x_3_3 = "@AmelieDataleak" ascii //weight: 3
        $x_2_4 = "AAHLkI4cdw2BdNdKDchnijtsIE537wvRhLI" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_Lazy_LMK_2147950173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.LMK!MTB"
        threat_id = "2147950173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {8a 4f fe 44 8a 47 ff 8a c1 44 8a 1f 8a d1 c0 e8 07 02 d2 0f b6 c0 6b c0 1b 40 8a 77 01 88 4c 24 70 40 02 f6 41 8a c8 44 88 44 24 78 02 c9 44 88 5c 24 68 32 d0 89 44 24 0c 8a c2}  //weight: 20, accuracy: High
        $x_10_2 = {32 42 01 32 44 24 78 32 44 24 68 88 42 fe 8a c1 40 32 c6 40 32 ce 41 32 c7 41 32 cf 32 04 24 32 44 24 02 32 44 24 01 32 44 24 78 32 44 24 68 32 0c 24 02 c0 32 4c 24 02 41 32 c1 32 4c 24 01 41 32 c2 40 32 c7 40 32 c5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_NS_2147950417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.NS!MTB"
        threat_id = "2147950417"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 46 08 88 07 49 63 46 04 41 3b 06 7e 07 49 8d 3c 07 c6 07 cc}  //weight: 2, accuracy: High
        $x_1_2 = {8d 83 00 10 00 00 4c 63 e0 49 8b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Lazy_GTB_2147950746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Lazy.GTB!MTB"
        threat_id = "2147950746"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 04 08 88 45 ff 48 8b 45 00 48 89 45 b8 48 8b 4d 30 48 89 4d c0 48 39 c8 ?? ?? 48 8b 4d 00 48 8b 45 38 0f b6 55 0f 44 0f b6 45 ff 44 31 c2 44 0f b6 45 2f 44 31 c2 88 14 08 8a 45 0f 88 45 2f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

