rule Trojan_Win32_Cridex_DSK_2147750143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DSK!MTB"
        threat_id = "2147750143"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 ec 9f f5 01 89 84 1a ?? ?? ff ff 83 c3 04 8b d6 89 3d ?? ?? ?? ?? 8d 6c 2a 0f 89 5c 24 10 06 00 8b 15}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 cb 03 c1 8b 4d fc 25 ff 00 00 00 8a 80 ?? ?? ?? ?? 5e 33 cd 5b 07 00 0f b6 80}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 44 24 20 8a 4c 14 24 30 08 40 ff 4c 24 1c 89 44 24 20 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_BS_2147750529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.BS!MTB"
        threat_id = "2147750529"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 68 50 11 00 00 ff 15 ?? ?? ?? ?? 03 f0 8b 55 ?? 03 55 ?? 8b 45 ?? 8b 4d ?? 8a 0c 31 88 0c 10 8b 55 ?? 83 c2 01 89 55 ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_PVD_2147750605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.PVD!MTB"
        threat_id = "2147750605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 d6 03 c2 25 ff 00 00 00 8b f0 8a 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 41 81 f9 00 01 00 00 89 35 06 00 88 1d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 55 e0 03 55 f4 0f b6 02 33 c1 8b 4d e0 03 4d f4 88 01 eb}  //weight: 2, accuracy: High
        $x_2_3 = {8b 45 ec 03 45 fc 0f b6 08 03 4d f4 8b 55 ec 03 55 fc 88 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_VSD_2147751449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.VSD!MTB"
        threat_id = "2147751449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 6c 24 10 05 e8 1a 73 01 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 84 2a 05 00 a1}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 44 24 40 0d ?? ?? ?? ?? 89 44 24 40 8b 44 24 28 32 0c 10 8b 54 24 2c 88 0c 1a}  //weight: 2, accuracy: Low
        $x_2_3 = {8b cf b8 04 00 00 00 03 c1 83 e8 04 a3 12 00 8b 3d ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 33 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_KPS_2147752161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.KPS!MTB"
        threat_id = "2147752161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 16 8a cb 8a d0 f6 d1 f6 d2 0a ca 0a d8 22 cb 88 0c 2e 46 3b 74 24 2c 0f 82}  //weight: 2, accuracy: High
        $x_2_2 = {03 ca 81 e1 ff 00 00 00 0f b6 14 8d ?? ?? ?? ?? a3 ?? ?? ?? ?? 30 14 33 83 ee 01 79 07 00 8b 0c 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_MR_2147753252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.MR!MTB"
        threat_id = "2147753252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vprivacywere71NBiggerofandpreventive" wide //weight: 1
        $x_1_2 = "MFcanpOn1R" wide //weight: 1
        $x_1_3 = "cpeanutaItoOn" wide //weight: 1
        $x_1_4 = "Hstrategyof" wide //weight: 1
        $x_1_5 = "GEtheCNETthatpwChrome" wide //weight: 1
        $x_1_6 = "buildshaveandbRwistheRlocal" wide //weight: 1
        $x_1_7 = "forbeR1g3" wide //weight: 1
        $x_1_8 = "iLwebsitesJUandThearchitecturelover" wide //weight: 1
        $x_1_9 = "fofChromePageNonoTyrannosaurusRadio" wide //weight: 1
        $x_1_10 = "myscoobyLvialibrariesMfappearance" wide //weight: 1
        $x_1_11 = "JllJallto" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

rule Trojan_Win32_Cridex_RR_2147753373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.RR!MTB"
        threat_id = "2147753373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c6 03 c2 8d 04 40 81 c3 ?? ?? ?? ?? 2b c6 89 9c 2f ?? ?? ?? ?? 05 ?? ?? ?? ?? 39 0d ?? ?? ?? ?? 72 ?? 29 35 ?? ?? ?? ?? 8b c8 2b ce 83 c1 ?? 8b f0 2b 35 ?? ?? ?? ?? 83 c5 ?? 83 c6 ?? 0f b7 f6 89 6c 24 ?? 81 fd ?? ?? ?? ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_PVS_2147753996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.PVS!MTB"
        threat_id = "2147753996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 10 13 ea 8b f1 89 2d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 54 24 14 81 c1 50 0f 27 02 89 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_OR_2147754176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.OR!MTB"
        threat_id = "2147754176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 1c 83 44 24 14 04 05 ?? ?? ?? ?? 89 44 24 1c 89 02 ba 16 11 00 00 2b d6 a3 c8 c6 5e 00 8b 74 24 1c 03 d2 2b d1 8a c2 2a 44 24 0f 02 d8 83 6c 24 28 01 89 5c 24 10 0f 85 36}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_PVK_2147754414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.PVK!MTB"
        threat_id = "2147754414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ba 72 61 0b 00 8b ff c7 05 ?? ?? ?? ?? 00 00 00 00 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 74 24 20 8d 34 09 2b f0 8b ca 81 c6 71 f2 fe ff 03 f2 33 d2 89 74 24 34 85 c9 0f 94 c2 89 54 24 3c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 51 03 05 2c f9 04 01 03 d6 89 45 00 6b ca 52 83 c5 04 2b cf 03 f1 83 6c 24}  //weight: 1, accuracy: High
        $x_1_2 = {83 44 24 10 04 81 c3 90 4b 08 01 69 c1 3e 5c 01 00 89 1e 8b f2 2b f0 2b 74 24 14 8d 4e 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c2 08 79 03 01 a1 ?? ?? ?? ?? 89 13 83 c3 04 2b c1 83 6c 24 10 01 75 b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 20 69 d2 34 50 01 00 05 40 26 00 01 89 44 24 20 89 01 8b 4c 24 18 a3 ?? ?? ?? ?? 03 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 f8 d1 5f 01 00 0f b6 05 ?? ?? ?? ?? 8d 0c 51 81 c1 a4 c1 fe ff 03 ce 89 0d ?? ?? ?? ?? 3b c7 77 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 14 8b c2 2b c3 81 c6 f0 25 08 01 83 e8 30 89 35 ?? ?? ?? ?? 89 31 8d 1c 45 09 00 00 00 39 7c 24 2c 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 2b c3 83 e8 04 2b 44 24 28 83 44 24 18 04 83 c0 da 8b 3d ?? ?? ?? ?? 03 c6 83 6c 24 1c 01 89 44 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 c3 2c 8f 04 01 89 1a 0f b7 2d ?? ?? ?? ?? 8b d0 2b d7 0f b7 3d ?? ?? ?? ?? 2b fd 81 ea 12 9d 00 00 a3 ?? ?? ?? ?? 81 ff 67 01 00 00 75 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 b6 0c 0c 00 b8 b6 0c 0c 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? a1 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 8b ff 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02 5f 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AR_2147754688_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AR!MTB"
        threat_id = "2147754688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 81 c1 08 e8 02 01 89 0a 8b 15 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 ca}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 24 2c 81 c2 78 41 0c 01 8b 74 24 1c 83 c6 3b 89 54 24 18 03 f0 89 15 ?? ?? ?? ?? 89 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_VD_2147754808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.VD!MTB"
        threat_id = "2147754808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 89 10 e9 [0-13] b8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 80 34 01 ?? 41 81 f9 ?? ?? ?? ?? 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_PVE_2147755014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.PVE!MTB"
        threat_id = "2147755014"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 03 30 8b 4d 08 89 31 8b 55 08 8b 02 2d 92 27 01 00 8b 4d 08 89 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_CY_2147755796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.CY!MTB"
        threat_id = "2147755796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 1e 56 e8 ?? ?? ?? ?? 8b f0 83 c4 04 85 ?? ?? ?? ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 5f 5e 5b 33 cc [0-16] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_FO_2147755832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.FO!MTB"
        threat_id = "2147755832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 14 81 c1 ?? ?? ?? ?? 89 4c 24 10 89 0d ?? ?? ?? ?? 89 0f b9 ?? ?? ?? ?? 2b c8 0f af ca 81 c1 ?? ?? ?? ?? 03 ce 83 7c 24 18 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_MO_2147755890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.MO!MTB"
        threat_id = "2147755890"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 8b 4d f0 2b c8 8b 45 ?? 1b c2 66 89 4d ec 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 e8 a1 ?? ?? ?? ?? 89 42}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_LD_2147756300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.LD!MTB"
        threat_id = "2147756300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fb 2b f9 8d 44 38 ?? 2b f1 8d 5c 33 ?? 81 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8b 6c 24 10 89 75 ?? 8b f0 2b f1 83 c6 ?? 0f b7 f6 6a ?? 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEA_2147756363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEA!MTB"
        threat_id = "2147756363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ef 2b e8 8d 44 2a a5 81 fa ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 8d 44 0a fa 8b 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 9c 32 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 8d 0c c3 03 c8 83 c6 04 89 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_G_2147756476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.G!MTB"
        threat_id = "2147756476"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ThoughtOff\\pairsubject\\presentEquate\\scalePutsoon.pdb" ascii //weight: 1
        $x_1_2 = {0f af c2 0f b6 c0 69 d0 cb 00 00 00 0f b7 c7 0f b6 ca 2b c8 88 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_FU_2147756545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.FU!MTB"
        threat_id = "2147756545"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ee 83 c5 ?? 4b 0f af dd 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 01 a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? 0f b7 db 89 6c 24 10 89 5c 24 20 89 44 24 18 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_FR_2147756568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.FR!MTB"
        threat_id = "2147756568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f0 89 44 24 1c 8b 44 24 24 83 ee 4d 05 ?? ?? ?? ?? 8b fe 89 01 33 c9 89 44 24 24 a3 50 1b 06 10 0f b6 05 ?? ?? ?? ?? 2b 44 24 0c 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEC_2147756629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEC!MTB"
        threat_id = "2147756629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 69 c0 ?? ?? ?? ?? 8d 14 55 ?? ?? ?? ?? 8b cb 81 c6 ?? ?? ?? ?? 89 75 00 83 c5 ?? 89 6c 24 ?? 2b c8 0f b7 c1 8b c8 69 c9 89 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_UF_2147756697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.UF!MTB"
        threat_id = "2147756697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 44 08 b0 ?? ?? 8d 9c 59 ?? ?? ?? ?? bd ?? ?? ?? ?? 2b e9 2b ee 83 c1 01 03 c5 0f af c8 81 c2 ?? ?? ?? ?? 89 17 83 c7 04 83 6c 24 10 01 8d 8c ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DED_2147756736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DED!MTB"
        threat_id = "2147756736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c8 8d 7f 04 8b c1 2b 44 24 14 05 ?? ?? ?? ?? 03 c6 03 d0 8b c3 2b c5 83 c0 b1 03 f0 8b 47 fc 8d 6a 51 05 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 47 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEE_2147756971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEE!MTB"
        threat_id = "2147756971"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 2b c2 89 1d ?? ?? ?? ?? 03 dd 83 15 ?? ?? ?? ?? 00 8d 44 00 ae 8b ea 2b e9 81 c6 ?? ?? ?? ?? 8d 44 28 02 8b 6c 24 10 89 35 ?? ?? ?? ?? 89 75 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEI_2147757565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEI!MTB"
        threat_id = "2147757565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 55 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d 01 6b c9 36 8b 15 01 2b d1 89 15 00 8b 45 f4 6b c0 06 2b 05 01 a3 00 0f b7 0d ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 33 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEM_2147758595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEM!MTB"
        threat_id = "2147758595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ea 04 2b 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 69 05 ?? ?? ?? ?? db 24 00 00 0f b7 4d fc 2b c1 66 89 45 fc 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 45 f8 8b 0d ?? ?? ?? ?? 89 88 ?? ?? ?? ?? 69 15 ?? ?? ?? ?? db 24 00 00 0f b7 45 fc 2b d0}  //weight: 1, accuracy: Low
        $x_1_2 = {03 d0 83 fa 26 b9 01 00 00 00 c1 e1 02 8b 35 ?? ?? ?? ?? 83 ee 26 0f b7 45 fc 99 2b f0 0f b6 81 ?? ?? ?? ?? 99 03 c6 ba 01 00 00 00 c1 e2 02 88 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_DEQ_2147758743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEQ!MTB"
        threat_id = "2147758743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 01 00 00 00 c1 e1 02 0f b6 91 ?? ?? ?? ?? b8 01 00 00 00 c1 e0 03 0f b6 88 ?? ?? ?? ?? 2b d1 81 fa ?? ?? ?? ?? 8b 4d e8 83 e9 03 8b 75 ec 83 de 00 0f b7 45 fc 99 2b c8 1b f2 ba 01 00 00 00 6b c2 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEY_2147760487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEY!MTB"
        threat_id = "2147760487"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 e9 20 0f b6 c9 00 0d ?? ?? ?? ?? 8d 0c 40 81 c6 ?? ?? ?? ?? 2b ca 8b 54 24 14 89 35 ?? ?? ?? ?? 89 b4 2a ?? ?? ?? ?? 0f b6 3d ?? ?? ?? ?? 0f b7 c9 8d b4 40 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 0f b7 d1 03 c7 2b f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DEW_2147760513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEW!MTB"
        threat_id = "2147760513"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zFowUNsWxM" ascii //weight: 1
        $x_1_2 = "OSeCxPIQiT" ascii //weight: 1
        $x_1_3 = "MZWYmbVuzB" ascii //weight: 1
        $x_1_4 = "MBSFGIGCXKTEZRFBMG0" ascii //weight: 1
        $x_1_5 = "08rtg0imuwrh9y3uj450yij3t" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Cridex_DEX_2147760514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DEX!MTB"
        threat_id = "2147760514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "erktb89uk35b8u359k8yj458hj83u" ascii //weight: 1
        $x_1_2 = "FWIIFYSgnG" ascii //weight: 1
        $x_1_3 = "FstYsJWQeD" ascii //weight: 1
        $x_1_4 = "YBAyvWsKIL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Cridex_DAE_2147760881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAE!MTB"
        threat_id = "2147760881"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5c 24 10 0f b7 eb 81 c7 ?? ?? ?? ?? 8b c6 2b c5 89 3a 83 c2 04 83 e8 53 83 6c 24 18 01 89 54 24 14 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DAF_2147760882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAF!MTB"
        threat_id = "2147760882"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d1 2b d3 81 c2 00 00 0f b7 da 0f b7 d3 2b 15 ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 89 28 83 c0 04 83 6c 24 14 01 8d 7c 17 e9 89 44 24 10}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d1 2b d3 81 c2 90 1e 00 00 0f b7 da 0f b7 d3 2b 15 c0 c0 02 10 81 c5 28 2d 03 01 89 28 83 c0 04 83 6c 24 14 01 8d 7c 17 e9 89 44 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_DAG_2147760883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAG!MTB"
        threat_id = "2147760883"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 ff 2b c1 03 d8 8b 44 24 10 83 44 24 10 04 81 c5 40 1c 0f 01 ff 4c 24 14 89 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GC_2147760927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GC!MTB"
        threat_id = "2147760927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 5f 7a 73 00 a1 ?? ?? ?? ?? 31 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 05 [0-48] 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DAM_2147761690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAM!MTB"
        threat_id = "2147761690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 38 ae 08 00 b8 38 ae 08 00 a1 ?? ?? ?? ?? eb 00 8b f8 33 f9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 3d 01 a1 ?? ?? ?? ?? 8b 0d 01 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = "3524523458i234985u283452h834h582y43h582h3495" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_DAO_2147761928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAO!MTB"
        threat_id = "2147761928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 38 ae 08 00 b8 38 ae 08 00 a1 ?? ?? ?? ?? eb 00 8b d8 33 d9 c7 05 ?? ?? ?? ?? 00 00 00 00 01 1d 01 a1 ?? ?? ?? ?? 8b 0d 01 89 08}  //weight: 1, accuracy: Low
        $x_1_2 = "569gu5m9uyh39u85hy8tu3h4589uth39458u9h389u4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Cridex_DAP_2147761929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DAP!MTB"
        threat_id = "2147761929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 01 0a 8a c7 b4 72 83 ea 02 f6 ec 8a f8 02 f9 81 fa ?? ?? ?? ?? 7f e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_DBA_2147762721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.DBA!MTB"
        threat_id = "2147762721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba b4 12 00 00 ba bc 01 00 00 a1 ?? ?? ?? ?? a3 00 eb 00 eb 00 31 0d 00 c7 05 ?? ?? ?? ?? 00 00 00 00 a1 00 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GGL_2147806116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GGL!MTB"
        threat_id = "2147806116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 18 89 45 ec 8b 75 0c 83 ee 7c 33 35 ?? ?? ?? ?? 83 c6 22 2b 75 0c 83 c6 56 89 75 08}  //weight: 10, accuracy: Low
        $x_10_2 = {8b f8 2b 7d 18 33 3d ?? ?? ?? ?? 2b fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GGLM_2147806117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GGLM!MTB"
        threat_id = "2147806117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "vdisablinggoneTfHjZ" ascii //weight: 3
        $x_3_2 = "GZYwebvitesvoad4" ascii //weight: 3
        $x_3_3 = "MnCtheseDeqaceiensG1" ascii //weight: 3
        $x_3_4 = "Betatreeking3seecesesoeving.123forXemetif" ascii //weight: 3
        $x_3_5 = "Cheemeeherinitiatedy777777byE" ascii //weight: 3
        $x_3_6 = "ioinloie8RRieTdTieTrevTmTnes" ascii //weight: 3
        $x_3_7 = "reeKir74rZDvrrrirn" ascii //weight: 3
        $x_3_8 = "7inrnPaedoraasMaelowse" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_RM_2147809033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.RM!MTB"
        threat_id = "2147809033"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3doChromesdays.197types" ascii //weight: 1
        $x_1_2 = "Chromesolving.123whichm" ascii //weight: 1
        $x_1_3 = "Youonfeaturesconnectionbrowsers.62gonlyTheJZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_QLM_2147809084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.QLM!MTB"
        threat_id = "2147809084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b d1 c1 fa 05 c1 ea 1a 03 d1 c1 ea 06 81 e1 3f 00 00 80 7d 07 83 e9 01 83 c9 c0 41 33 c0 85 c9}  //weight: 10, accuracy: High
        $x_10_2 = {56 53 55 8b e9 8b 5c 24 10 33 d2 89 55 00 89 55 04 89 55 08 89 55 0c 85 db 74 08 8b 74 24 14 85 f6 75 08 8b c5 5d 5b 5e c2 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GFT_2147812602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GFT!MTB"
        threat_id = "2147812602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 7d 10 8b e5 33 c8 8d 4e 14 64 89 0d ?? ?? ?? ?? 33 c8 8b 65 e8 0f 84 ?? ?? ?? ?? 85 c0 89 45 0c 8d 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 8b 5d 20 89 5d 08 8b d3 33 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 89 55 c0 68 ?? ?? ?? ?? 6a 11 6a 64 6a 00 ff 15 ?? ?? ?? ?? 89 05 ?? ?? ?? ?? 81 f8 00 00 00 00 0f 85}  //weight: 10, accuracy: Low
        $x_1_2 = "OpenClipboard" ascii //weight: 1
        $x_1_3 = "SetClipboardData" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GZM_2147813387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GZM!MTB"
        threat_id = "2147813387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 01 ba ff fe fe 7e 03 d0 83 f0 ?? 33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 e8}  //weight: 10, accuracy: Low
        $x_1_2 = "besthotel360.com" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "lCQhAmalCQhAmalCQhAma" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_GZL_2147814057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.GZL!MTB"
        threat_id = "2147814057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 8a 07 32 c2 0f b6 4f ?? 32 ca e9}  //weight: 10, accuracy: Low
        $x_10_2 = {88 07 46 47 49 83 f9 ?? 0f 85 ?? ?? ?? ?? e9 ?? ?? ?? ?? ba ?? ?? ?? ?? 8a 06 32 c2 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_AK_2147838175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.AK!MTB"
        threat_id = "2147838175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 3c 31 0f b6 cb 01 f9 81 e1 ff 00 00 00 8b 7d e0 32 3c 0f 8b 4d e4 88 3c 31 83 c6 01 8b 4d ec 39 ce 8b 4d cc 89 55 dc 89 4d d8 89 75 d4 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_MA_2147841701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.MA!MTB"
        threat_id = "2147841701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 4c 24 6a 30 c9 88 8c 24 c7 00 00 00 8b 94 24 c0 00 00 00 8a 4c 24 6a 00 c9 88 8c 24 c7 00 00 00 81 c2 29 be 0c 36 89 84 24 84 00 00 00 89 94 24 a8 00 00 00 81 bc 24 a8 00 00 00 9f 5c dd 49 0f 83}  //weight: 5, accuracy: High
        $x_5_2 = {0d 83 b2 77 49 e2 dc 24 49 e2 dc 24 49 e2 dc 24 d2 09 12 24 80 e3 dc 24 57 b0 5f 24 3e e2 dc 24 49 e2 dd 24 7c e2 dc 24 de}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_SPQ_2147902458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.SPQ!MTB"
        threat_id = "2147902458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bonebegin" ascii //weight: 1
        $x_1_2 = "Ratherdesign" ascii //weight: 1
        $x_1_3 = "StoneNumeral" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_MBFW_2147906134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.MBFW!MTB"
        threat_id = "2147906134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 72 74 79 77 68 71 61 65 20 76 20 61 77 72 74 77 71 68 72 20 72 73 67 74 66 00 73 64 66 62 67 61 64}  //weight: 1, accuracy: High
        $x_1_2 = {52 00 54 00 55 00 54 00 49 00 4c 00 53 00 2e 00 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_ACX_2147929298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.ACX!MTB"
        threat_id = "2147929298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {03 d9 89 5d f8 8b 45 f8 c1 e8 03 b9 01 00 00 00 2b c8 89 4d dc 8b 55 f8 0f af 55 dc 89 55 f8 c1 e3 03 8b 45 ec 03 45 fc 0f b6 08 03 4d f4 8b 55 ec 03 55 fc 88 0a 8b 45 fc 83 e8 01 89 45 fc 8b 4d fc 83 e9 01 89 4d fc 8b 55 fc}  //weight: 3, accuracy: High
        $x_2_2 = {83 c0 02 89 45 fc 8b 4d e0 03 4d fc 8a 51 01 88 55 eb 8b 45 fc 83 c0 01 89 45 fc 8a 4d eb 88 4d f3 8b 55 ec 03 55 fc 8a 45 f3 88 02 8b 4d 14 03 4d f8 0f b6 11 89 55 f4 8b 5d f8 8b 4d d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_MKV_2147929940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.MKV!MTB"
        threat_id = "2147929940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 ca 88 4d 13 11 0d d3 86 41 00 8b 4d e8 8b 15 ?? ?? 41 00 31 15 0b 87 41 00 0f b6 55 13 33 ce 2b cf 0f af ca 34 c3 2c 4e 88 4d 13 0f b6 4d 13 03 c1 88 45 13 8a 45 13}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Cridex_TTZ_2147931447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Cridex.TTZ!MTB"
        threat_id = "2147931447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Cridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 cd 5a 00 00 35 53 3a 00 00 89 45 ec 8b 55 f0 0f b6 02 8b 55 e8 88 02 ff 45 ?? 66 c7 45 e0 4b 00 66 83 7d e0 4d 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

