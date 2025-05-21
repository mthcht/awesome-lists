rule Trojan_Win32_Obfuscator_AO_2147754912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.AO!MTB"
        threat_id = "2147754912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 85 f7 fe ff ff 8a 84 0d f8 fe ff ff 88 84 35 f8 fe ff ff 88 94 0d f8 fe ff ff 0f b6 84 35 f8 fe ff ff 0f b6 ca 03 c8 0f b6 c1 8a 84 05 f8 fe ff ff 30 04 3b 43 8a 85 f7 fe ff ff 3b 5d 0c 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BZ_2147755280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BZ!MTB"
        threat_id = "2147755280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 e8 f0 [0-13] 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 ba 21 5d 00 00 80 34 01 ?? 41 39 d1 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_GZ_2147755289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.GZ!MTB"
        threat_id = "2147755289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 89 10 e9 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? ba ?? ?? ?? ?? 31 c9 80 34 01 b5 41 39 d1 75 ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XD_2147755337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XD!MTB"
        threat_id = "2147755337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 8b cf c1 e1 04 03 4c 24 28 8b c7 c1 e8 05 03 44 24 30 03 d7 33 ca 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 89 4c 24 0c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XK_2147755372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XK!MTB"
        threat_id = "2147755372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 de 83 c1 ?? f7 de 83 ee ?? 8d 76 fe 8d 76 01 29 fe 31 ff 09 f7 c7 43 ?? ?? ?? ?? ?? 31 33 83 c3 ?? 83 c2 ?? 8d ?? ?? ?? ?? ?? 81 ee ?? ?? ?? ?? ff e6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_KD_2147755375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.KD!MTB"
        threat_id = "2147755375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 31 c9 68 ?? ?? ?? ?? 5a 80 34 01 a3 41 39 d1 75 f7 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_GG_2147755578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.GG!MTB"
        threat_id = "2147755578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 39 8d 04 39 41 3b ce 72 ?? 33 c9 85 f6 74 ?? 30 14 39 8d 04 39 41 3b ce 72 ?? 57 e8 ?? ?? ?? ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_DL_2147755674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.DL!MTB"
        threat_id = "2147755674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 03 44 24 20 8b ce c1 e9 05 03 d6 33 c2 03 cf 81 3d 34 c5 c5 02 ?? ?? ?? ?? c7 05 b8 c3 c5 02 ?? ?? ?? ?? 89 2d b0 c3 c5 02 89 2d b4 c3 c5 02 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BT_2147755692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BT!MTB"
        threat_id = "2147755692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 fc 8d 84 02 ?? ?? ?? ?? 8b 4d 08 03 01 8b 55 08 89 02 8b 45 08 8b 08 81 e9 ?? ?? ?? ?? 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BT_2147755692_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BT!MTB"
        threat_id = "2147755692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 8b 84 ?? ?? ?? ?? ?? 8b 8c ?? ?? ?? ?? ?? 8a 94 ?? ?? ?? ?? ?? 30 14 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BK_2147755711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BK!MTB"
        threat_id = "2147755711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 14 33 c0 8a 44 34 18 81 e1 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 04 8a 54 14 14 32 c2 88 03 43 4d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XA_2147755722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XA!MTB"
        threat_id = "2147755722"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 8b cb c1 e1 04 8b f3 03 4c 24 2c 03 c3 c1 ee 05 33 c8 03 74 24 30 [0-3] 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? [0-16] 89 4c 24 0c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_CP_2147755724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.CP!MTB"
        threat_id = "2147755724"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 a3 a8 ?? ?? ?? a3 ?? ?? ?? ?? 8b c7 c1 e0 04 03 44 24 34 8b f7 c1 ee 05 03 74 24 2c 03 d7 33 c2 81 3d ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 0c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FY_2147755739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FY!MTB"
        threat_id = "2147755739"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 0d d8 30 04 32 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b 53 ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 6a ?? ff 73 ?? 56 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FB_2147755924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FB!MTB"
        threat_id = "2147755924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 0c 32 03 d6 83 f8 ?? ?? ?? 33 c0 eb 01 40 30 1a 8b 4d ?? 8b 55 ?? 46 3b f7 ?? ?? 8b 4d ?? 8b 55 ?? 8a 45 ?? 30 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XX_2147756280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XX!MTB"
        threat_id = "2147756280"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c 30 0c 30 b8 ?? ?? ?? ?? 83 f0 ?? 83 6c 24 ?? ?? 83 7c 24 ?? ?? ?? ?? ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 5f 5e 33 cc e8 ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XY_2147756299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XY!MTB"
        threat_id = "2147756299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 23 13 ?? ?? f7 f9 8b 4c 24 ?? 8b 44 24 ?? 83 c1 ?? 89 4c 24 ?? 8a 54 14 ?? 30 54 08 ?? 3b ee ?? ?? ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 64 89 ?? ?? ?? ?? ?? 59 5f 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PD_2147756319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PD!MTB"
        threat_id = "2147756319"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 74 30 0c 30 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d ?? ?? 83 7d ?? ?? ?? ?? ?? ?? ?? ?? 5e 83 c5 ?? c9 c3 55 8b ec 83 ec ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_YT_2147756336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.YT!MTB"
        threat_id = "2147756336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 7d f0 89 55 e4 8b 45 fc 03 45 0c 0f be 08 8b 55 e4 0f be 44 15 10 33 c8 8b 55 fc 03 55 0c 88 0a eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PW_2147756337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PW!MTB"
        threat_id = "2147756337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 8a 81 ?? ?? ?? ?? 30 04 3a 83 f9 ?? ?? ?? 33 c9 ?? ?? 41 42 3b d3 ?? ?? 8b 85 ?? ?? ?? ?? ff d0 6a ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PP_2147756345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PP!MTB"
        threat_id = "2147756345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d 74 ?? 83 7d 74 ?? ?? ?? ?? ?? ?? ?? 5e 83 c5 ?? c9 c3 55 8b ec 83 ec ?? 56 be ?? ?? ?? ?? 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PJ_2147756369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PJ!MTB"
        threat_id = "2147756369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 74 30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d 74 ?? 83 7d 74 ?? ?? ?? ?? ?? ?? ?? 5e 83 c5 ?? c9 c3 55 8b ec 83 ec ?? 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PZ_2147756405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PZ!MTB"
        threat_id = "2147756405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 55 08 8b 02 03 45 fc 8b 4d 08 89 01 8b e5 5d c3 55 8b ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_LT_2147756418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.LT!MTB"
        threat_id = "2147756418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 0f b6 44 05 00 0f b6 4d f3 03 c1 99 8b cb f7 f9 8b 45 e8 8a 4c 15 00 30 08 40 83 bd ?? ?? ?? ?? ?? 89 45 e8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TT_2147756456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TT!MTB"
        threat_id = "2147756456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 31 b8 ?? ?? ?? ?? 83 f0 ?? 83 6d 74 ?? 83 7d 74 ?? ?? ?? ?? ?? ?? ?? 5e 83 c5 78 c9 c3 55 8b ec 83 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TY_2147756472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TY!MTB"
        threat_id = "2147756472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 6a 01 5e 81 c6 ?? ?? ?? ?? 87 d6 83 f9 00 ?? ?? 83 7d fc 04 ?? ?? c7 45 fc 00 00 00 00 80 34 01 c4 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TZ_2147756490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TZ!MTB"
        threat_id = "2147756490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 40 a3 ?? ?? ?? ?? 8a c3 2a c2 f6 eb 8a c8 0f b6 c1 81 c6 ?? ?? ?? ?? 8d 9c 18 ?? ?? ?? ?? 89 75 00 81 fb ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TR_2147756500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TR!MTB"
        threat_id = "2147756500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 23 45 c8 8b 4d c8 83 c1 01 99 f7 f9 8b 55 a0 2b d0 89 55 a0 8b 45 d8 8b 4d 08 8b 55 c4 89 14 81 e9 58 fe ff ff ?? ?? 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_ET_2147756543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.ET!MTB"
        threat_id = "2147756543"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c1 f0 e8 ?? ?? ?? ?? 0f b6 4d f3 0f b6 03 03 c1 99 8b cf f7 f9 8b 45 e8 8a 4c 15 00 30 08 40 83 bd ?? ?? ?? ?? ?? 89 45 e8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TE_2147756572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TE!MTB"
        threat_id = "2147756572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 18 40 89 44 24 18 8a 54 14 20 30 50 ff 39 ac 24 ?? ?? ?? ?? 0f ?? ?? ?? ?? ?? 8b 44 24 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_QB_2147756611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.QB!MTB"
        threat_id = "2147756611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 68 ?? ?? ?? ?? 6a 00 ff ?? ?? ?? ?? ?? 03 45 fc 8b 55 08 03 02 8b 4d 08 89 01 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PT_2147756626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PT!MTB"
        threat_id = "2147756626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 f7 bd 74 ff ff ff 89 95 68 ff ff ff 8b 45 84 03 85 6c ff ff ff 0f be 08 8b 95 68 ff ff ff 0f be 44 15 8c 33 c8 8b 55 84 03 95 6c ff ff ff 88 0a eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EM_2147756627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EM!MTB"
        threat_id = "2147756627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 f0 83 4d fc ff 8a 4c 15 00 30 08 40 8d 8d c0 fe ff ff 89 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_QW_2147756656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.QW!MTB"
        threat_id = "2147756656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 37 56 e8 ?? ?? ?? ?? 8b f0 83 c4 04 3b f3 0f ?? ?? ?? ?? ?? 5f 5e 5b c9 c3 55 8b ec 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EO_2147756706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EO!MTB"
        threat_id = "2147756706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 4d 17 0f b6 03 03 c1 99 8b cf f7 f9 8b 85 ?? ?? ?? ?? 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08 40 8d 8d ?? ?? ?? ?? 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EO_2147756706_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EO!MTB"
        threat_id = "2147756706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 75 fc 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 0f be 14 30 f7 da 8b 85 ?? ?? ?? ?? 0f be 08 2b ca 8b 95 ?? ?? ?? ?? 88 0a 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_ZP_2147756708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.ZP!MTB"
        threat_id = "2147756708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 81 e9 ?? ?? ?? ?? 89 4d fc c1 45 08 04 8b 55 fc 81 c2 ?? ?? ?? ?? 89 55 fc 8b 45 08 05 ?? ?? ?? ?? 89 45 08 8b 45 08 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_LL_2147756725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.LL!MTB"
        threat_id = "2147756725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 db 53 8d ?? ?? ?? ?? ?? 50 53 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 53 ff 15 ?? ?? ?? ?? 85 f6 ?? ?? e8 ?? ?? ?? ?? 30 04 3e 4e 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_LL_2147756725_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.LL!MTB"
        threat_id = "2147756725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 d1 00 89 4c 24 0c 89 0d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8b 5c 24 24 05 ?? ?? ?? ?? 89 44 24 20 a3 ?? ?? ?? ?? 89 03 bb ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 66 3b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_LR_2147756727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.LR!MTB"
        threat_id = "2147756727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4c 24 0c 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 03 fb 8b 4c 24 28 83 44 24 28 04 89 44 24 2c a3 ?? ?? ?? ?? 89 01 0f b7 c7 89 15 ?? ?? ?? ?? 89 7c 24 20 8d 0c 45 ?? ?? ?? ?? 0f af c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_DB_2147756755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.DB!MTB"
        threat_id = "2147756755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 78 40 89 45 f8 b2 10 8d 73 10 89 4d f4 2b fb 8a 44 37 ff 8d 76 ff 8d 49 ff 88 41 f0 30 06 0f b6 41 40 88 01 80 c2 ff 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_DB_2147756755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.DB!MTB"
        threat_id = "2147756755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b d7 d3 e2 8b 4d f0 8b c7 c1 e8 05 03 55 e4 03 45 e0 03 cf 33 d0 33 d1 8b 0d ?? ?? ?? ?? 29 55 f8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_KI_2147756766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.KI!MTB"
        threat_id = "2147756766"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 31 d2 [0-48] c7 45 fc ?? ?? ?? ?? 80 34 01 ?? 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SV_2147756768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SV!MTB"
        threat_id = "2147756768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 c8 3b 55 94 ?? ?? 8b 45 a0 03 45 c8 0f be 08 81 f1 ?? ?? ?? ?? 8b 55 a0 03 55 c8 88 0a 8b 45 c8 83 c0 01 89 45 c8 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RB_2147756774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RB!MTB"
        threat_id = "2147756774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 44 24 10 2b 7c 24 10 8b 44 24 34 d1 6c 24 24 29 44 24 14 4d ?? ?? ?? ?? ?? ?? 8b 44 24 28 8b 8c 24 ?? ?? ?? ?? 89 38 5f 5e 5d 89 58 04 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_HH_2147756802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.HH!MTB"
        threat_id = "2147756802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 83 e2 1f 0f b6 92 ?? ?? ?? ?? 32 14 03 8b 5c 24 28 88 50 04 8b 54 24 24 03 d0 83 e2 1f 0f b6 92 ?? ?? ?? ?? 32 14 03 83 c0 06 88 50 ff 81 f9 ?? ?? ?? ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FJ_2147756814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FJ!MTB"
        threat_id = "2147756814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 1c 31 44 24 14 2b 5c 24 14 8b 44 24 3c d1 6c 24 2c 29 44 24 18 ff 4c 24 24 0f ?? ?? ?? ?? ?? 8b 44 24 30 8b 8c 24 ?? ?? ?? ?? 5f 5e 89 68 04 5d 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_GF_2147756879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.GF!MTB"
        threat_id = "2147756879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b c5 33 ca c1 e8 05 03 44 24 24 89 44 24 14 89 4c 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FD_2147756893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FD!MTB"
        threat_id = "2147756893"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 4c 24 50 8b c7 c1 e8 05 03 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 4c 24 24 81 fa ?? ?? ?? ?? ?? ?? 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_YY_2147756899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.YY!MTB"
        threat_id = "2147756899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 03 75 fc 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 4d 08 03 31 8b 55 08 89 32 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_YY_2147756899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.YY!MTB"
        threat_id = "2147756899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b c1 8d 88 ?? ?? ?? ?? 83 44 24 10 04 81 c3 ?? ?? ?? ?? 69 c1 ?? ?? ?? ?? 89 1e 8b f2 2b f0 2b 74 24 14 8d 4e 08 2b 0d ?? ?? ?? ?? 83 e9 ?? 83 6c 24 18 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_QQ_2147756964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.QQ!MTB"
        threat_id = "2147756964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 03 4d f0 13 55 f4 89 0d ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ec 8b 15 ?? ?? ?? ?? 89 91 ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EE_2147756970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EE!MTB"
        threat_id = "2147756970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 8c 8a 54 15 ?? 30 10 40 83 bd ?? ?? ?? ?? ?? 89 45 8c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_UR_2147756980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.UR!MTB"
        threat_id = "2147756980"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 03 55 f0 13 45 f4 66 89 55 e8 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 e4 a1 ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 0f b7 4d e8 8b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FT_2147756981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FT!MTB"
        threat_id = "2147756981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 80 f1 e7 8b 5d fc 03 d8 88 0b ?? ?? 8b 4d fc 03 c8 8a 1a 88 19 [0-48] 8b 45 fc 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_LZ_2147757154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.LZ!MTB"
        threat_id = "2147757154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 83 ea ?? a3 ?? ?? ?? ?? 8b 44 24 10 8b 4c 24 24 83 44 24 10 04 81 c1 ?? ?? ?? ?? 89 08 8b c6 2b c2 69 f8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 03 fa}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TB_2147757155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TB!MTB"
        threat_id = "2147757155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 85 ?? ?? ?? ?? 40 83 c4 ?? 89 85 ?? ?? ?? ?? 0f b6 94 15 ?? ?? ?? ?? 30 50 ff 83 7d 14 ?? 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BO_2147757171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BO!MTB"
        threat_id = "2147757171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 c3 8b d8 8d 45 e8 8b d3 e8 ?? ?? ?? ?? 8b 55 e8 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f4 46 4f 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BO_2147757171_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BO!MTB"
        threat_id = "2147757171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d1 8d 4c 32 f7 81 c7 ?? ?? ?? ?? 89 7d 00 0f b6 2d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 8b f5 2b f2 81 fe ?? ?? ?? ?? 75 16 8b d1 2b d0 83 ea ?? 83}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RF_2147757172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RF!MTB"
        threat_id = "2147757172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 44 34 50 81 e1 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 03 83 c4 ?? 8a 54 14 14 32 c2 88 03 43 4d 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RF_2147757172_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RF!MTB"
        threat_id = "2147757172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 14 8d 5e a9 8b 44 24 24 03 d9 05 ?? ?? ?? ?? 8b f3 2b f7 a3 ?? ?? ?? ?? 89 02 83 ee 07 83 c2 04 ff 4c 24 18 89 54 24 14 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RF_2147757172_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RF!MTB"
        threat_id = "2147757172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 fc 33 c0 89 45 ec 83 7d ec 00 ?? ?? 8b 45 ec 83 e0 ?? 85 c0 ?? ?? 8b 45 ec 8a 80 ?? ?? ?? ?? 34 d9 8b 55 fc 03 55 ec 88 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EP_2147757238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EP!MTB"
        threat_id = "2147757238"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 44 [0-48] 99 f7 f9 8a 03 83 c4 ?? 8a 54 14 18 32 c2 88 03 8b 44 24 10 43 48 89 44 24 10 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_FV_2147757266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.FV!MTB"
        threat_id = "2147757266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8a 5d 00 8b 44 24 28 83 c4 18 8a 54 14 14 32 da 88 5d ?? 45 48 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_EN_2147757561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.EN!MTB"
        threat_id = "2147757561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 54 24 10 0f b6 44 14 24 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 18 8b 4c 24 1c 83 c0 01 89 44 24 18 8a 54 14 24 30 54 01 ff 83 7c 24 14 00 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_QL_2147757588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.QL!MTB"
        threat_id = "2147757588"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 89 45 fc 8b 0d ?? ?? ?? ?? 89 4d 08 8b 55 08 8b 02 8b 4d fc 8d 94 01 ?? ?? ?? ?? 8b 45 08 89 10 8b 4d 08 8b 11 81 ea ?? ?? ?? ?? 8b 45 08 89 10 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TX_2147757590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TX!MTB"
        threat_id = "2147757590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 30 8a 18 83 c4 1c 8a 54 14 18 32 da 88 18 40 89 44 24 14 ff 4c 24 10 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_TX_2147757590_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.TX!MTB"
        threat_id = "2147757590"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 80 f1 ?? 8b 5d fc 03 d8 ?? ?? e8 ?? ?? ?? ?? 88 0b eb 10 8b 4d fc 03 c8 73 05 e8 ?? ?? ?? ?? 8a 1a 88 19 40 42 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_CQ_2147757628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.CQ!MTB"
        threat_id = "2147757628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 99 f7 bd 7c ff ff ff 89 95 70 ff ff ff 8b 45 ec 03 45 fc 0f be 00 8b 8d 70 ff ff ff 0f be 4c 0d 88 33 c1 8b 4d ec 03 4d fc 88 01 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PL_2147757636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PL!MTB"
        threat_id = "2147757636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 0c 8b 55 f8 8b 0c 90 8b 5d 14 8b 45 fc 33 0c 83 8b 55 08 8b 45 f8 89 0c 82 8b 55 18 4a 3b 55 fc 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_AD_2147757929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.AD!MTB"
        threat_id = "2147757929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d a4 24 00 00 00 00 8a 4c 05 d8 30 0c 32 83 f8 20 75 04 33 c0 eb 01 40 42 3b d7 72 ea 8b 85 ?? ?? ?? ?? ff d0 6a 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_OF_2147757930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.OF!MTB"
        threat_id = "2147757930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 f4 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 14 89 45 f4 ?? ?? ?? ?? ?? ?? 8b 45 10 5e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RW_2147757953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RW!MTB"
        threat_id = "2147757953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d a4 8b c3 2b fb 8d 5d ac 2b 5d a8 eb 07 ?? ?? ?? ?? ?? ?? ?? 8a 0c 03 8d 40 01 32 4c 07 ff 88 48 ff 4a 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SL_2147758036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SL!MTB"
        threat_id = "2147758036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 c1 e8 05 89 45 f8 8b 45 f8 03 45 c8 89 45 f8 8b 45 fc 33 45 e0 89 45 fc 8b 45 fc 33 45 f8 89 45 fc 83 25 ?? ?? ?? ?? ?? 8b 45 f0 2b 45 fc 89 45 f0 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PH_2147758056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PH!MTB"
        threat_id = "2147758056"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b fa 8b 55 08 8a d8 d0 eb 33 f6 33 c9 89 45 f4 88 5d ff 89 55 f8 89 7d f0 85 ff ?? ?? 8a 04 01 30 04 32 03 d6 83 f9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_XO_2147758057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.XO!MTB"
        threat_id = "2147758057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f6 33 c9 88 5d ff 89 45 f8 89 7d f0 85 ff [0-48] 8d 49 00 8d 14 06 8b 45 f4 8a 04 01 30 02 83 f9 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_OX_2147758062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.OX!MTB"
        threat_id = "2147758062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 18 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 20 32 da 88 1c 01 41 3b ee 89 4c 24 18 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RR_2147758130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RR!MTB"
        threat_id = "2147758130"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 34 20 0f b6 cb 03 c1 99 b9 ?? ?? ?? ?? f7 f9 83 c4 ?? 45 0f b6 54 14 14 30 55 ff 83 bc 24 ?? ?? ?? ?? ?? ?? ?? 8b 44 24 10 5e 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_OP_2147758239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.OP!MTB"
        threat_id = "2147758239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 4e 0f ?? ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 5f 5e 33 cd 5b e8 ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? c9 c3 55 8d 6c 24 88 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? 33 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_BV_2147758265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.BV!MTB"
        threat_id = "2147758265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 51 6a 05 ff 15 ?? ?? ?? ?? 83 c4 ?? 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 79 0c 8b 51 14 2b fa 8b 15 ?? ?? ?? ?? 88 04 17 b8 01 00 00 00 03 c2 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_DD_2147758277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.DD!MTB"
        threat_id = "2147758277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 16 88 18 0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 85 ?? ?? ?? ?? 8a 94 ?? ?? ?? ?? ?? 30 10 40 83 bd ?? ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_MS_2147758327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.MS!MTB"
        threat_id = "2147758327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 04 40 0f b6 4c 24 2f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 30 83 c4 1c 8a 4c 14 24 30 08 40 83 bc 24 ?? ?? ?? ?? ?? 89 44 24 14 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SM_2147758363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SM!MTB"
        threat_id = "2147758363"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 03 4d 08 83 e9 ?? ?? ?? ?? ?? ?? 03 d8 83 c4 ?? 58 c9 ?? ?? ?? c1 c9 ?? c0 c8 ?? c0 c8 ?? 34 ?? aa e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SS_2147758365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SS!MTB"
        threat_id = "2147758365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 34 0f b6 44 04 40 0f b6 4c 24 2f 03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 30 83 c4 1c 8a 4c 14 24 30 08 40 83 bc 24 ?? ?? ?? ?? ?? 89 44 24 14 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SB_2147758391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SB!MTB"
        threat_id = "2147758391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 8d 4c ff ?? ?? 8b 95 ?? ?? ?? ?? 83 ca 19 8b 85 ?? ?? ?? ?? 03 10 8b 8d ?? ?? ?? ?? 2b ca 89 8d ?? ?? ?? ?? 8b 95 ?? ?? ?? ?? 8b 45 9c 8b 8d ?? ?? ?? ?? 89 0c ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_DX_2147758427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.DX!MTB"
        threat_id = "2147758427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 15 [0-48] a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? a1 ?? ?? ?? ?? 89 82 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 84 0a ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_CK_2147758499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.CK!MTB"
        threat_id = "2147758499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 f0 8b 45 ec 0f b6 84 05 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 45 f0 8a 8c 15 ?? ?? ?? ?? 30 08 ff 45 08 8b 45 14 ff 4d 14 85 c0 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_GL_2147758511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.GL!MTB"
        threat_id = "2147758511"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 53 ff 15 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 3b f3 ?? ?? e8 ?? ?? ?? ?? 30 04 3e 4e 79 f5 8b 4d fc 5f 5e 33 cd 5b e8 ?? ?? ?? ?? c9 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PQ_2147758655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PQ!MTB"
        threat_id = "2147758655"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 83 c4 0c 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d 08 89 45 14 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_KP_2147758689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.KP!MTB"
        threat_id = "2147758689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 f8 8b 44 24 18 8b d7 8b 7c 24 20 2b d6 83 44 24 20 04 83 c2 ?? 05 ?? ?? ?? ?? 89 44 24 18 89 07 8d ba ?? ?? ?? ?? a3 ?? ?? ?? ?? 03 f9 ff 4c 24 14 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_PK_2147758775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.PK!MTB"
        threat_id = "2147758775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 59 ?? ?? 57 8d 85 ?? ?? ?? ?? 50 57 ff 15 ?? ?? ?? ?? 8d 45 84 50 57 ff 15 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4d 80 30 04 31 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_KK_2147758784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.KK!MTB"
        threat_id = "2147758784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 3e 89 b5 ?? ?? ?? ?? b8 ?? ?? ?? ?? 83 f0 ?? 83 ad ?? ?? ?? ?? ?? 8b b5 ?? ?? ?? ?? 3b f3 ?? ?? 8b 4d fc 5f 5e 33 cd 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_SA_2147758790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.SA!MTB"
        threat_id = "2147758790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 f7 bd 7c ?? ?? ?? 89 95 ?? ?? ?? ?? 8b 55 f0 03 55 fc 0f be 02 8b 8d ?? ?? ?? ?? 0f be 54 0d 8c 33 c2 8b 4d f0 03 4d fc 88 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_NV_2147758801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.NV!MTB"
        threat_id = "2147758801"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 83 e1 ?? 8b 54 24 1c 8a 1c 02 2a 1c 0d ?? ?? ?? ?? 80 c3 20 66 c7 44 ?? ?? ?? ?? 8b 4c 24 18 88 1c 01 c6 44 24 4b ?? 83 c0 ?? 89 44 24 38 8b 74 24 28 39 f0 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_IB_2147758885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.IB!MTB"
        threat_id = "2147758885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 10 66 89 1d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? ?? ?? 8d b8 ?? ?? ?? ?? 8d 41 be 81 c2 ?? ?? ?? ?? 03 c6 89 55 00 8b c8 83 c6 19 2b cf 83 c5 04 03 f1 83 6c 24 14 01 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RQ_2147759074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RQ!MTB"
        threat_id = "2147759074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 da 89 1d ?? ?? ?? ?? 83 d0 ?? 89 44 24 24 a3 ?? ?? ?? ?? 8b 44 24 1c 8d 34 56 81 c1 ?? ?? ?? ?? 83 c6 ?? 03 f7 89 08 83 c0 ?? ff 4c 24 14 89 44 24 1c 8b 44 24 24 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_MR_2147782834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.MR!MTB"
        threat_id = "2147782834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 02 83 05 [0-5] 83 [0-6] a1 [0-4] 3b [0-5] a1 [0-4] 8b [0-5] 01 10 a1 [0-4] 03 [0-5] 03 [0-5] 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_MU_2147783734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.MU!MTB"
        threat_id = "2147783734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 33 0d ?? ?? ?? ?? 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 8b [0-2] 89 [0-2] 8b [0-5] 89 [0-2] 8b [0-2] f7 da 8b [0-2] 8b 08 2b ca 8b 55 08 89 0a 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Obfuscator_RM_2147784755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RM!MTB"
        threat_id = "2147784755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 89 0d ?? ?? ?? ?? 8b c2 33 05 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b d0 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RM_2147784755_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RM!MTB"
        threat_id = "2147784755"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b df 3b fe 73 ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 8b 54 24 ?? 8a c3 2a 44 24 ?? 83 c4 04 32 03 51 32 44 24 ?? 52 88 03 ff 15 ?? ?? ?? ?? 03 5c 24 ?? 3b de 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RT_2147786815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RT!MTB"
        threat_id = "2147786815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 33 05 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 00 00 00 00 8b d0 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 8b e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RT_2147786815_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RT!MTB"
        threat_id = "2147786815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 c0 bb 03 00 a3 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 3b ca 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RT_2147786815_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RT!MTB"
        threat_id = "2147786815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 08 81 f1 80 00 00 00 88 ?? ?? 8b ?? ?? 03 ?? ?? 89 55 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 4d ?? 0f b6 11 0f b6 45 ?? 33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 25 80 00 00 00 33 d0 8b 4d ?? 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_RT_2147786815_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.RT!MTB"
        threat_id = "2147786815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rcp-be-sanitizer" ascii //weight: 1
        $x_1_2 = "--login.sessionKey" ascii //weight: 1
        $x_1_3 = "rso-auth.username" ascii //weight: 1
        $x_1_4 = "rso-auth.password" ascii //weight: 1
        $x_1_5 = "new_game_patcher" ascii //weight: 1
        $x_1_6 = "allow_insecure_content" ascii //weight: 1
        $x_1_7 = "T:\\cid\\p4\\Releases_11_24\\LeagueClientCode_X86_Public\\15682\\tmp\\x86-Public-LCU\\RiotClient\\bin\\LeagueClient.pdb" ascii //weight: 1
        $x_1_8 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_9 = "ShellExecuteW" ascii //weight: 1
        $x_1_10 = "GetKeyboardLayout" ascii //weight: 1
        $x_1_11 = "pwlqfu.biz" ascii //weight: 1
        $x_1_12 = "QQBrowser/9.0.2524.400" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Obfuscator_NIT_2147941840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Obfuscator.NIT!MTB"
        threat_id = "2147941840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Obfuscator"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 00 6a 00 ff 15 14 81 40 00 c7 45 d4 00 00 00 00 6a 00 6a 00 ff 15 18 81 40 00 85 c0 0f 85 e9 00 00 00 c7 45 d0 00 00 00 00 c7 45 cc 00 00 00 00 eb 09 8b 4d cc 83 c1 01 89 4d cc 81 7d cc fb 0c 00 00 7d 0b 8b 55 d0 83 c2 01 89 55 d0 eb e3 6a 00 ff 15 34 80 40 00 83 f8 4b}  //weight: 2, accuracy: High
        $x_1_2 = {8b 4d fc 03 4d e8 8a 11 02 55 80 8b 45 fc 03 45 e8 88 10 8b 8d 74 ff ff ff 83 c1 01 89 8d 74 ff ff ff 8b 55 e0 81 e2 ff 00 00 00 39 95 74 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

