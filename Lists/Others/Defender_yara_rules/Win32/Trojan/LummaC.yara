rule Trojan_Win32_LummaC_B_2147891669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.B!MTB"
        threat_id = "2147891669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 3c 02 89 d9 80 e1 18 d3 e7 89 c1 83 e1 fc 31 7c 0c 14 40 83 c3 08 39 c6 75 e4}  //weight: 1, accuracy: High
        $x_1_2 = "cmd.exe /c timeout /nobreak /t 3 & fsutil file setZeroData offset=0 length=%lu \"%s\" & erase \"%s\" & exit" ascii //weight: 1
        $x_1_3 = "gstatic-node.io" ascii //weight: 1
        $x_1_4 = "TeslaBrowser" ascii //weight: 1
        $x_1_5 = "*.eml" ascii //weight: 1
        $x_1_6 = "powershell -exec bypass \"%s\"" ascii //weight: 1
        $x_1_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_A_2147893962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.A!MTB"
        threat_id = "2147893962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4c 24 04 b8 d1 05 00 00 01 44 24 04 8b 54 24 04 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 c4 1c 08 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 10 8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GAA_2147906160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GAA!MTB"
        threat_id = "2147906160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 10 30 0c 06 83 ff ?? ?? ?? 6a 00 6a 00 6a 00 ff d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GMK_2147907896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GMK!MTB"
        threat_id = "2147907896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f6 17 80 07 ?? b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
        $x_10_2 = {f6 17 80 07 ?? b8 ?? ?? ?? ?? bb ?? ?? ?? ?? b8 ?? ?? ?? ?? 80 2f ?? f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_ASGE_2147908308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGE!MTB"
        threat_id = "2147908308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c2 8b 55 f4 33 d0 89 55 f4 e8}  //weight: 2, accuracy: High
        $x_2_2 = {81 01 e1 34 ef c6 c3 29 11 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGF_2147908632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGF!MTB"
        threat_id = "2147908632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 44 2c ?? 03 c6 0f b6 c0 8a 44 04 ?? 30 04 39 8b 4c 24 ?? 85 c9 74}  //weight: 4, accuracy: Low
        $x_1_2 = "divuhxIUo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGH_2147910142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGH!MTB"
        threat_id = "2147910142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 44 3c ?? 03 c6 59 59 8b 4c 24 ?? 0f b6 c0 8a 44 04 ?? 30 04 29 45 3b ac 24}  //weight: 4, accuracy: Low
        $x_1_2 = "daixiAis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAE_2147910594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAE!MTB"
        threat_id = "2147910594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 14 30 83 ff 0f 75 ?? 8b 8d ?? ?? ?? ?? 6a 00 6a 00 [0-15] 50 51 68}  //weight: 1, accuracy: Low
        $x_1_2 = {30 0c 33 83 ff 0f 75 ?? 8b 95 [0-15] 6a 00 6a 00 [0-15] 50 51 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_KAA_2147910698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.KAA!MTB"
        threat_id = "2147910698"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 75 88 8a 84 05 ?? ?? ?? ?? 30 04 0b 43 3b 9d ?? ?? ?? ?? 89 5d ?? 8b 5d ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGI_2147910711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGI!MTB"
        threat_id = "2147910711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 d0 0f b6 10 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 31 d0 88 45 ?? 8b 55 f0 8b 45 0c 01 c2 0f b6 45 ?? 88 02 83 45 f0 01 8b 45 f0 3b 45 10 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGJ_2147910942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGJ!MTB"
        threat_id = "2147910942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 8b 44 24 ?? 8d 4c 24 ?? 8a 44 04 ?? 30 07 e8 ?? ?? ?? 00 8b 5c 24 ?? 47 8b 54 24 ?? 6a 0f 5d 81 ff}  //weight: 2, accuracy: Low
        $x_2_2 = {0f b6 44 1c ?? 03 c6 33 ed 0f b6 c0 59 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAA_2147912540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAA!MTB"
        threat_id = "2147912540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 6d fc 46 8b 45 08 8a 4d fc 03 c2 30 08 42 3b d7 7c ?? 5e 83 ff 2d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GXL_2147913228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GXL!MTB"
        threat_id = "2147913228"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8d 45 c4 50 e8 ?? ?? ?? ?? 8a 45 c4 30 04 37 59 83 fb 0f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGK_2147913926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGK!MTB"
        threat_id = "2147913926"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 e3 04 03 9d ?? ?? ff ff 33 d9 81 3d ?? ?? ?? 00 03 0b 00 00 75 13 6a 00 ff 15 ?? ?? ?? 00 33 c0 50 50 50 ff 15 ?? ?? ?? 00 8b 45 6c 33 c3 2b f0}  //weight: 4, accuracy: Low
        $x_1_2 = {2b f8 83 3d ?? ?? ?? 00 0c 89 45 6c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MZT_2147913948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MZT!MTB"
        threat_id = "2147913948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 44 34 ?? 03 c2 0f b6 c0 0f b6 44 04 ?? 30 83 ?? ?? ?? ?? 43 81 fb ?? ?? ?? ?? 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNU_2147914108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNU!MTB"
        threat_id = "2147914108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {03 55 e0 0f b6 02 33 45 dc 8b 4d 14 03 4d e0 88 01 8d 4d e4}  //weight: 10, accuracy: High
        $x_1_2 = "IUAhsiuchniuohAIU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAT_2147914796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAT!MTB"
        threat_id = "2147914796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 74 24 30 8b 0c 87 0f b6 04 06 6a 03 30 81}  //weight: 1, accuracy: High
        $x_1_2 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAB_2147914927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAB!MTB"
        threat_id = "2147914927"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 24 30 8b 0c b3 0f b6 04 37 6a 03 30 81 ?? ?? ?? ?? b9}  //weight: 1, accuracy: Low
        $x_1_2 = {45 89 6c 24 14 81 fd ?? ?? ?? ?? 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAJ_2147915158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAJ!MTB"
        threat_id = "2147915158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b d8 8b 45 ?? 31 18 6a 00 e8 [0-20] 83 45 ec 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_RDB_2147915331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.RDB!MTB"
        threat_id = "2147915331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 6c 24 28 8b 5c 24 34 8b 54 24 40 59 8b 4c b5 00 8a 04 33 6a 03 30 04 11 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MAC_2147915505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MAC!MTB"
        threat_id = "2147915505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 03 8b 4c 85 ?? 8a 04 18 30 04 11 b9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGV_2147916172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGV!MTB"
        threat_id = "2147916172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 01 8b 4c 24 ?? 30 04 0a 8d 4c}  //weight: 4, accuracy: Low
        $x_1_2 = "JAHNsiu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJF_2147917324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJF!MTB"
        threat_id = "2147917324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {21 d0 01 f0 89 c2 31 ca f7 d0 21 c8 01 c0 29 d0}  //weight: 5, accuracy: High
        $x_5_2 = {21 ca 01 c8 01 d2 29 d0 05 ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 04 ?? 8b 0c 24 88 44 0c 08 ff 04 24 8b 04 24 83 f8}  //weight: 5, accuracy: Low
        $x_5_3 = {21 d0 01 c0 89 ca f7 d2 21 c2 f7 d0 21 c8 29 d0 89 44 24}  //weight: 5, accuracy: High
        $x_5_4 = {21 c8 09 ca 29 c2 89 54 24 ?? 8b 44 24 ?? 04 1d 8b 0c 24 88 44 0c ?? ff 04 24 8b 04 24 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_CZ_2147917460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CZ!MTB"
        threat_id = "2147917460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 98 8b 44 24 ?? 8a 04 01 8d 4c 24 ?? 30 82}  //weight: 1, accuracy: Low
        $x_1_2 = {46 89 74 24 ?? 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASGW_2147917802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASGW!MTB"
        threat_id = "2147917802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 04 01 8d 4c 24 ?? 30 82 [0-4] e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 8d 4c 24 ?? e8 ?? ?? ?? ?? 46 89 74 24 ?? 81 fe ?? ?? ?? 00 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALC_2147917813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALC!MTB"
        threat_id = "2147917813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d7 81 e7 00 b7 67 da 89 d3 81 f3 00 b7 67 5a 21 f2 8d 3c 7b 01 f7 01 d2 29 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALC_2147917813_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALC!MTB"
        threat_id = "2147917813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b ca c1 f9 06 83 e2 3f 6b d2 38 8b 0c 8d 50 6a 4b 00 88 44 11 29 8b 0b 8b c1 c1 f8 06 83 e1 3f 6b d1 38 8b 0c 85 50 6a 4b 00 8b 45 14 c1 e8 10 32 44 11 2d 24 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJK_2147919210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJK!MTB"
        threat_id = "2147919210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d4 45 d0 4b c7 44 24 ?? ee 49 e4 4f c7 44 24 ?? e2 4d 9e 33 c7 44 24 ?? 96 31 9c 37 c7 44 24 ?? 9a 35 34 3b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASN_2147919709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASN!MTB"
        threat_id = "2147919709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {f6 17 90 89 d8 bb 99 00 00 00 90 31 c3 80 07 79 80 2f 35 90 89 d8 bb 99 00 00 00 90 31 c3 f6 2f 47 e2}  //weight: 4, accuracy: High
        $x_4_2 = {8b 0a 8b 3e f6 17 53 5b 90 89 c3 83 f3 39 80 07 47 80 2f 25 53 5b 90 89 c3 83 f3 39 f6 2f 47 e2}  //weight: 4, accuracy: High
        $x_1_3 = {20 ca 30 c8 08 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_CCJP_2147920161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJP!MTB"
        threat_id = "2147920161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 ec 8b 4d ec 0f b6 0c 0f 05 ?? ?? ?? ?? 31 c8 89 45 e8 8b 45 e8 04 6e 8b 4d ec 88 04 0f ff 45 ec 8b 45 ec 83 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMAH_2147920215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMAH!MTB"
        threat_id = "2147920215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 00 8b 4d ?? 83 c1 ?? 0f be c9 33 c1 8b 4d [0-4] 03 4d ?? 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJG_2147920706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJG!MTB"
        threat_id = "2147920706"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 08 03 45 fc 0f b6 08 8b 15 ?? ?? ?? ?? 81 c2 96 00 00 00 33 ca 8b 45 08 03 45 fc 88 08 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJL_2147920707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJL!MTB"
        threat_id = "2147920707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 0c 1a 8d 43 ?? 30 01 43 83 fb 14 72 f2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJM_2147920708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJM!MTB"
        threat_id = "2147920708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 ce 21 d6 01 f6 29 f2 01 ca 89 54 24}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJN_2147920709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJN!MTB"
        threat_id = "2147920709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {29 cf 81 c1 ?? ?? ?? ?? 31 cf 21 d7 31 cf 89 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJO_2147920710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJO!MTB"
        threat_id = "2147920710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 0c 24 8b 14 24 0f b6 54 14 ?? 81 c1 ?? ?? ?? ?? 31 d1 89 8c 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 80 c1 ?? 8b 14 24 88 4c 14 ?? ff 04 24 8b 0c 24 83 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJQ_2147920712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJQ!MTB"
        threat_id = "2147920712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {f6 17 58 50 89 c0 35 ?? ?? ?? ?? 90 80 07 64 80 2f 88 58 50 89 c0 35 ?? ?? ?? ?? 90 f6 2f 47 e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJQ_2147920712_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJQ!MTB"
        threat_id = "2147920712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 de 89 f3 21 fb 01 db 01 fe 89 f7 29 df 83 e6 ?? 83 f7}  //weight: 2, accuracy: Low
        $x_1_2 = {53 57 56 81 ec ?? ?? ?? ?? a1 ?? ?? ?? ?? b9 ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 01 c8 40 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_RZ_2147920731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.RZ!MTB"
        threat_id = "2147920731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 c8 c1 e0 02 29 c4 89 e7 8b 73 08 fc f3 a5 ff 13}  //weight: 2, accuracy: High
        $x_1_2 = "main.PZzdIVAnmb.func1" ascii //weight: 1
        $x_1_3 = "main.WIKjjgAgOA.func1" ascii //weight: 1
        $x_1_4 = "main.vpbBpKpstg.deferwrap2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJE_2147922438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJE!MTB"
        threat_id = "2147922438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "64"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "aflkmfhebedbjioipglgcbcmnbpgliof" wide //weight: 5
        $x_5_2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" wide //weight: 5
        $x_5_3 = "fhilaheimglignddkjgofkcbgekhenbh" wide //weight: 5
        $x_5_4 = "ffnbelfdoeiohenkjibnmadjiehjhajb" wide //weight: 5
        $x_5_5 = "nkbihfbeogaeaoehlefnkodbefgpgknn" wide //weight: 5
        $x_5_6 = "dmkamcknogkgcdfhhbddcghachkejeap" wide //weight: 5
        $x_5_7 = "ookjlbkiijinhpmnjffcofjonbfbgaoc" wide //weight: 5
        $x_5_8 = "omaabbefbmiijedngplfjmnooppbclkk" wide //weight: 5
        $x_5_9 = "lgmpcpglpngdoalbgeoldeajfclnhafa" wide //weight: 5
        $x_1_10 = "Electrum" wide //weight: 1
        $x_1_11 = "Exodus\\" wide //weight: 1
        $x_1_12 = "discord\\" wide //weight: 1
        $x_1_13 = "wallet" wide //weight: 1
        $x_5_14 = "RAV Endpoint Protection" wide //weight: 5
        $x_5_15 = "Process Hacker 2" wide //weight: 5
        $x_5_16 = "signons.sqlite" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMN_2147923342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMN!MTB"
        threat_id = "2147923342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c2 0f b6 c0 89 44 24 [0-40] e8 ?? ?? ?? ?? 8b 44 24 ?? 8b 4c 24 ?? 8a 44 04 ?? 30 04 19 43 3b 5d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AQ_2147924240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AQ!MTB"
        threat_id = "2147924240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 44 24 18 8b 4c 24 1c 8a 44 04 38 30 04 19 85 f6 74 09 6a 01 8b ce e8}  //weight: 4, accuracy: High
        $x_1_2 = {0f b6 44 2c 38 03 c2 89 74 24 10 0f b6 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASQ_2147924497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASQ!MTB"
        threat_id = "2147924497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 23 00 83 63 04 00 e8 ?? ?? ?? ?? 8b 4c 24 44 83 c4 0c 8b 44 24 3c 8a 4c 0c 40 30 0c 38 83 7b 04 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCIO_2147924561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCIO!MTB"
        threat_id = "2147924561"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 80 c1 ?? 32 4c 04 1c 80 c1 ?? 88 4c 04 1c 40 83 f8 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASS_2147924614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASS!MTB"
        threat_id = "2147924614"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 23 00 83 63 ?? 00 e8 [0-4] 8b 44 24 ?? 83 c4 0c 8a 4c 2c ?? 30 0c 38 83 7b 04 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCIP_2147924764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCIP!MTB"
        threat_id = "2147924764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 61 37 35 c7 44 24 ?? 65 39 65 35 c7 44 24 ?? 31 37 66 63 c7 44 24 ?? 65 32 64 33 c7 44 ?? 24 61 62 66 33 c7 44 24 ?? 37 34 64 36 c7 44 24 ?? 66 63 32 32 c7 44 24 ?? 64 30 65 33}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCIQ_2147925097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCIQ!MTB"
        threat_id = "2147925097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 31 66 61 c7 44 24 ?? 39 38 35 61 c7 44 24 ?? 33 65 62 31 c7 44 24 ?? 34 36 33 35 c7 44 24 ?? 64 35 33 37 c7 44 24 ?? 37 64 64 31 c7 44 24 ?? 36 62 64 37 c7 44 24 ?? 33 35 32 36}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_WDD_2147925221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.WDD!MTB"
        threat_id = "2147925221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 c8 04 28 32 04 0a 04 38 88 04 0a 41 83 f9 07 75 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_HNAA_2147925579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.HNAA!MTB"
        threat_id = "2147925579"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 12 51 50 6a 00 ff 72 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {31 f2 89 54 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
        $x_1_3 = {31 c8 89 45 e4 8b 45 e4}  //weight: 1, accuracy: High
        $x_10_4 = {f3 a5 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc}  //weight: 10, accuracy: High
        $x_11_5 = {8b 14 24 8b 34 24 0f b6 74 34 04 81 c2 ?? ?? ?? ?? 31 f2 89 54 24 0c 8b 54 24 0c 80 c2 ?? 8b 34 24 88 54}  //weight: 11, accuracy: Low
        $x_11_6 = {c7 44 24 34 29 23 17 1d c7 44 24 38 15 1f 13 19 c7 44 24 3c 11 1b 1f 15 c7 44 24 40 1d 17 b2 11 c7 44 24 44 10 11 0e 0f c7 44 24 48 0c 0d 0a 0b c7 44 24 4c f6 09 fe 07 c7 44 24 50 09 08 0f 0e}  //weight: 11, accuracy: High
        $x_11_7 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 00 00 00 [0-16] 68 74 74 70 73 3a 2f 2f [0-16] 2e ?? ?? ?? 2f [0-21] 2e 65 78 65 00 00 [0-255] [0-240] 68 74 74 70 73 3a 2f 2f [0-21] 2e [0-4] 2f 61 70 69 00}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_11_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_SKK_2147925757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.SKK!MTB"
        threat_id = "2147925757"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d8 24 fc 00 c8 32 02 34 42 04 b6 88 02 42 83 c3 02 fe c1 83 fb 08 75 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AVCA_2147925831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AVCA!MTB"
        threat_id = "2147925831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c6 83 e6 ?? 89 d3 81 f3 ?? 00 00 00 01 f3 32 1c 14 fe cb 88 1c 14 42 83 c0 02 83 fa 05 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_KKZ_2147926121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.KKZ!MTB"
        threat_id = "2147926121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d0 83 e0 16 89 f3 81 f3 ?? ?? ?? ?? 29 c3 fe c3 32 19 80 c3 37 88 19 41 4e 83 c2 fe 83 fe f0 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALM_2147926152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALM!MTB"
        threat_id = "2147926152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 83 e1 02 81 f1 ce ?? ?? ?? 89 c2 83 e2 01 09 d1 80 c1 78 32 0c 04 80 f1 8e 80 c1 70 88 0c 04 83 f0 01 8d 04 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALM_2147926152_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALM!MTB"
        threat_id = "2147926152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 ce f7 d6 89 c8 c1 e8 02 83 e6 02 0f af f0 c0 e0 02 0c 02 88 cc d0 ec 80 e4 01 f6 e4 00 c0 88 dc 80 e4 fc 28 e0 04 94 0f b6 f8 8d 04 b1 01 f8 04 02 32 04 0c 04 12 88 04 0c 41 83 c3 02 83 f9 08}  //weight: 2, accuracy: High
        $x_1_2 = {89 c1 80 c1 5d 32 0c 02 80 c1 2f 88 0c 02 40 83 f8 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_YKZ_2147926168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.YKZ!MTB"
        threat_id = "2147926168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f af d0 01 fa 89 f7 d1 e7 83 e7 06 81 c7 ?? ?? ?? ?? 89 f0 29 f8 01 d0 30 c8 04 f1 88 44 35 e0 89 f0 83 c0 02 b9 ?? ?? ?? ?? 29 f1 83 e1 01 83 e0 0e 29 c8 89 c6 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_HZ_2147926247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.HZ!MTB"
        threat_id = "2147926247"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 04 37 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8a 4c 24 ?? 88 0c 37 83 fb ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_WIS_2147926346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.WIS!MTB"
        threat_id = "2147926346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 f2 83 e2 3b 81 e6 c4 00 00 00 09 d6 89 c2 83 e2 3b 81 ca ?? ?? ?? ?? 83 e0 c4 31 f0 31 d0 34 bb 04 78 88 44 3c ?? 47 83 c1 02 83 ff 22 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AST_2147926502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AST!MTB"
        threat_id = "2147926502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 d0 0f b6 10 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 31 d0 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? 01 8b 45 ?? 3b 45 ?? 0f 8f}  //weight: 4, accuracy: Low
        $x_1_2 = {01 ca 0f b6 00 88 02 8b 55 0c 8b 45 08 01 c2 0f b6 45 ff 88 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASU_2147926651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASU!MTB"
        threat_id = "2147926651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 14 0a 88 d4 f6 d4 20 c4 f6 d0 20 d0 08 e0 88 04 0e}  //weight: 4, accuracy: High
        $x_1_2 = {08 c4 30 d1 80 f4 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EZ_2147926907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EZ!MTB"
        threat_id = "2147926907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 45 eb 24 01 0f b6 c0 8b 4d f4 31 e9 89 45 bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EZ_2147926907_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EZ!MTB"
        threat_id = "2147926907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 60 05 00 00 10 00 00 00 62 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 05 00 00 02 00 00 00 72 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EZ_2147926907_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EZ!MTB"
        threat_id = "2147926907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 06 00 00 10 00 00 00 de 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 88 03 00 00 00 90 06 00 00 04 00 00 00 ee 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ASA_2147926981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ASA!MTB"
        threat_id = "2147926981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 d6 81 e6 ef 00 00 00 89 cb 83 e3 10 09 f3 0f b6 74 0f e2 83 f3 10 21 d3 31 d3 f7 d3 21 f3 31 d3 b0 69 28 d8 88 44 0f e2 41 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTT_2147927100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTT!MTB"
        threat_id = "2147927100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 d6 09 ca f7 d2 09 f2 89 d6 81 f6 ?? ?? ?? ?? 83 e2 ?? 01 d2 29 f2 88 10 40 49}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTT_2147927100_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTT!MTB"
        threat_id = "2147927100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 f1 89 c7 83 f7 ?? 81 e7 ?? ?? ?? ?? 21 f0 09 ca 09 c7 31 fa 89 55 ?? 8b 45 ?? 8b 4d ?? 31 e9 89 45}  //weight: 10, accuracy: Low
        $x_1_2 = "Process Hollowing.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTN_2147927314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTN!MTB"
        threat_id = "2147927314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 4d c3 8b 5d ?? 30 ca 8b 55 ?? 0f 45 c7 89 5d ?? 89 55 ?? 8b 55 ?? 89 55 ?? 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTN_2147927314_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTN!MTB"
        threat_id = "2147927314"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 fc 02 00 00 00 a0 05 00 00 02 00 00 00 a0 05 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EA_2147927497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EA!MTB"
        threat_id = "2147927497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 8d 84 00 00 00 8b d3 c1 ea 08 88 14 08 ff 85 84 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EA_2147927497_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EA!MTB"
        threat_id = "2147927497"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 88 b8 00 00 00 8b 85 84 00 00 00 8b d3 c1 ea 08 88 14 01 ff 85 84 00 00 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTS_2147927571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTS!MTB"
        threat_id = "2147927571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 04 83 c0 ?? 89 04 24 ?? 83 2c 24 ?? 8a 04 24 30 04 32 42 3b d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTS_2147927571_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTS!MTB"
        threat_id = "2147927571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca f7 d2 83 e2 ?? 81 e1 ?? ?? ?? ?? 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNM_2147927680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNM!MTB"
        threat_id = "2147927680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {f7 df 01 f8 40 0f b6 9c 04 ?? ?? ?? ?? 00 da 0f b6 f2 8a bc 34 ?? ?? ?? ?? 88 bc 04 ?? ?? ?? ?? 88 9c 34 ?? ?? ?? ?? 02 9c 04 ?? ?? ?? ?? 0f b6 f3 0f b6 9c 34 ?? ?? ?? ?? 30 99 ?? ?? ?? ?? 41}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNM_2147927680_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNM!MTB"
        threat_id = "2147927680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 d9 8a b4 1c ?? ?? ?? ?? 88 b4 04 ?? ?? ?? ?? 88 94 1c ?? ?? ?? ?? 0f b6 94 04 ?? ?? ?? ?? 00 d1 02 0c 04 0f b6 d9 8a b4 1c ?? ?? ?? ?? 88 b4 04 ?? ?? ?? ?? 88 94 1c ?? ?? ?? ?? 83 c0 ?? 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_HNAB_2147927905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.HNAB!MTB"
        threat_id = "2147927905"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 14 3b 85 d2 74 19 89 ce c1 e6 05 01 ce 01 d6 47 89 f1 39 fd 75 e8}  //weight: 2, accuracy: High
        $x_1_2 = {8b 40 18 c3 31 c0 c3 cc 8b 4c 24 04 31 c0 85 c9 74 0f 8b 54 24 08 39 51 18 76 06 8b 41 0c 8b 04 90 c3}  //weight: 1, accuracy: High
        $x_3_3 = {0f ad fe 89 fa d3 ea f6 c1 20 ?? ?? 89 d6 31 d2 31 d7 31 c6 81 cf 01 01 01 01 81 ce 01 01 01 01 57 56}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_AMFA_2147927922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMFA!MTB"
        threat_id = "2147927922"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 f9 00 c1 89 cf 0f b6 c9 0f b6 94 0c ?? ?? 00 00 88 94 2c ?? ?? 00 00 88 84 0c ?? ?? 00 00 02 84 2c ?? ?? 00 00 0f b6 c0 0f b6 84 04 ?? ?? 00 00 8b 8c 24 ?? ?? 00 00 30 04 19 43 39 9c 24 ?? ?? 00 00 74}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMCS_2147928101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMCS!MTB"
        threat_id = "2147928101"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec 04 0f b6 00 32 45 e0 88 45 f7}  //weight: 4, accuracy: Low
        $x_1_2 = {89 14 24 89 c1 e8 ?? ?? ?? ?? 83 ec 04 0f b6 5d 9c 88 18 83 45 e4 01 8b 45 e4 3b 45 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AZ_2147928305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AZ!MTB"
        threat_id = "2147928305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 44 24 10 83 c0 ?? 89 44 24 ?? 83 6c 24 ?? ?? 8a 44 24 ?? 30 04 2f 83 fb 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMCT_2147928392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMCT!MTB"
        threat_id = "2147928392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 10 05 00 00 10 00 00 00 10 05 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 73 72 63 00 00 00 00 10 00 00 00 20 05 00 00 10 00 00 00 20 05 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BA_2147928679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BA!MTB"
        threat_id = "2147928679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0f b6 c0 8a 84 04 ?? ?? 00 00 8b 54 24 10 8b 8c 24 ?? ?? 00 00 30 04 11 42 39 f2 0f 85}  //weight: 4, accuracy: Low
        $x_1_2 = {8b 4c 24 08 00 c1 89 4c 24 08 0f b6 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_HNAC_2147928736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.HNAC!MTB"
        threat_id = "2147928736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 c1 88 e8 30 c8}  //weight: 10, accuracy: High
        $x_5_2 = {0f af c8 89 ca 89 c8 89 cf f7 d2 [0-16] 21 ?? 81 ?? ?? ?? ?? ?? (81|89)}  //weight: 5, accuracy: Low
        $x_5_3 = {0f af c8 89 ca 89 cb f7 d2 89 [0-21] 25 ?? ?? ?? ?? 81}  //weight: 5, accuracy: Low
        $x_1_4 = {8d 48 ff 0f af c8 89}  //weight: 1, accuracy: High
        $x_1_5 = {8d 69 ff 0f af e9 89}  //weight: 1, accuracy: High
        $x_1_6 = {09 ce 89 c1 f7 d1 31 d6 89 c2}  //weight: 1, accuracy: High
        $x_1_7 = {0f 9c 44 24 0b [0-176] 80 ?? 01 80 ?? 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_BN_2147928782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BN!MTB"
        threat_id = "2147928782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 e0 ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? 00 00 ?? ?? 00 00 ?? ?? 00 00 3a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 ?? ?? ?? ?? ?? ?? ?? ?? 00 20 00 00 00 ?? ?? 00 00 ?? 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 74 61 67 67 61 6e 74 00 40}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NLB_2147928887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NLB!MTB"
        threat_id = "2147928887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_crypted.dll" ascii //weight: 2
        $x_1_2 = "@bmnvidjapmuqvqlivxazircppbjomunmxpjyeiwubtphnmhendbjxyloyarbch" ascii //weight: 1
        $x_1_3 = "ptkiouuecnxbzqhwftynkvokpwliaipsbjysbghjppqikbqtmnhet" ascii //weight: 1
        $x_1_4 = "xbfyibczyizhsiwigxshdojulzcfjnvoakgvhgs" ascii //weight: 1
        $x_1_5 = "laqxkqcpfyvpakmoyctaiwbatatssaylldhvrbchranhq" ascii //weight: 1
        $x_1_6 = "ocdxlonrhtobxzbmmppsktncfvbqheqvmuejpgo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ADHA_2147928929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ADHA!MTB"
        threat_id = "2147928929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d6 c1 ea 05 89 55 f8 8b 45 e4 01 45 f8 8b 45 f0 c1 e6 04 03 75 d8 8d 0c 03 33 f1 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NLD_2147929005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NLD!MTB"
        threat_id = "2147929005"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 ec 04 8b 4d f0 8b 45 0c 89 04 24 e8 46 00 00 00 83 ec 04 8b 4d fc 31 e9}  //weight: 2, accuracy: High
        $x_1_2 = {8b 45 ec c6 40 76 01 8b 4d fc 31 e9 e8 a4 76 00 00 8b 45 ec 89 ec 5d}  //weight: 1, accuracy: High
        $x_1_3 = {55 89 e5 83 ec 28 8b 45 08 89 45 e0 89 45 e4 8b 45 10 8b 45 0c a1 ?? ?? ?? ?? 31 e8 89 45 fc 8b 45 10 8d 4d ec 89 04 24}  //weight: 1, accuracy: Low
        $x_1_4 = {55 89 e5 83 ec 14 8b 45 08 a1 ?? ?? ?? ?? 31 e8 89 45 fc 89 4d f4 8b 4d f4 89 4d f0 8b 45 08 89 45 f8 8d 45 f8 89 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALMC_2147929062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALMC!MTB"
        threat_id = "2147929062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 de 83 e6 0c 89 c2 81 f2 46 dd 63 f6 01 f2 89 d6 21 ce 89 d7 31 cf 29 d7 01 f7 f7 d1 21 d1 09 f9 81 c1 cf 15 e1 4c 89 ca 83 e2 01 83 f1 01 8d 0c 51 88 4c 04 14 40 83 c3 02 83 f8 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NLF_2147929116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NLF!MTB"
        threat_id = "2147929116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b7 c9 89 cb f7 d3 0f b7 f6 21 f3 01 db 31 f1 31 c0 39 cb 0f 94 c0 8b 4c 24 04}  //weight: 2, accuracy: High
        $x_1_2 = {0f be 0c 1e 31 d1 0f af cd 43 89 ca 39 df 75 f0}  //weight: 1, accuracy: High
        $x_1_3 = {90 89 ca 80 c2 06 32 54 0c 1c 80 c2 d0 88 54 0c 1c 41 83 f9 04 75 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NLH_2147929117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NLH!MTB"
        threat_id = "2147929117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 75 e8 0f be 34 1e 31 f0 8b 75 e8 0f af c7 43 39 da 75 ec}  //weight: 2, accuracy: High
        $x_1_2 = {89 d7 f7 df 31 f7 4a 21 f2 01 d2 29 fa 8d 34 09 83 e6 74 f7 de 01 ce 83 c6 7a 83 e6 7a}  //weight: 1, accuracy: High
        $x_1_3 = {01 f9 01 c2 89 ce 31 d6 f7 d1 21 d1 01 c9 29 f1 89 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAI_2147929133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAI!MTB"
        threat_id = "2147929133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b c6 c1 e8 05 89 45 f8 8b 45 e4 01 45 f8 8b 4d f0 c1 e6 04 03 75 d8 8d 14 0b 33 f2 81 3d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_SXOS_2147929153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.SXOS!MTB"
        threat_id = "2147929153"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 46 89 44 24 0c 83 6c 24 0c 0a 90 83 6c 24 0c 3c 8a 44 24 0c 30 04 2f 83 fb 0f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_APP_2147929202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.APP!MTB"
        threat_id = "2147929202"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 c3 0f b6 cb 0f b6 94 0d ?? fe ff ff 88 94 3d ?? fe ff ff 88 84 0d ?? fe ff ff 02 84 3d ?? fe ff ff 0f b6 c0 0f b6 84 05 ?? fe ff ff 8b 4d 08 8b 55 d4 30 04 11 89 d1 41 3b 4d 0c 0f 84}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BK_2147929361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BK!MTB"
        threat_id = "2147929361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 44 24 18 c1 f8 1f 89 44 24 0c 8b 54 24 08 c1 fa 1f 89 54 24 10 ?? ?? ?? ?? ?? ff 8b 44 24 08 89 04 24 8b 4c 24 10 89 4c 24 04 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 4c 24 20 81 f9 73 02 00 00 0f 8e 51 01 00 00 8b 54 24 24 81 fa 73 02 00 00 0f 8e 2c 01 00 00 8b 5c 24 28 81 fb 73 02 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNT_2147929368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNT!MTB"
        threat_id = "2147929368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 40 00 00 c0 2e 69 64 61 ?? 61 20 20 00 10 00 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 00 e0 2e 72 73 72 63 00 00 00 fc 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GNT_2147929368_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GNT!MTB"
        threat_id = "2147929368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 44 05 00 00 00 60 00 00 00 06 00 00 00 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69}  //weight: 10, accuracy: High
        $x_1_2 = {64 00 65 00 66 00 4f 00 66 00 66 00 2e 00 65 00 78 00 65 00 00 00 00 00 48 00 12 00}  //weight: 1, accuracy: High
        $x_1_3 = "defOff.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_MBV_2147929405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.MBV!MTB"
        threat_id = "2147929405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 ce 83 e6 74 89 d3 81 f3 c5 00 00 00 29 f3 fe c3 32 18 80 c3 ?? 88 18 40 4a 83 c1 fe 83 fa ed 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTM_2147929471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTM!MTB"
        threat_id = "2147929471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 00 00 e0 2e 72 73 72 63 20 20 20 00 10 00 00 00 30 05 00 00 00 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69}  //weight: 5, accuracy: High
        $x_5_2 = {40 00 00 e0 2e 74 61 67 67 61 6e 74 00 30 00 00 00 60 2f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTM_2147929471_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTM!MTB"
        threat_id = "2147929471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? 00 00 00 30 05 00 00 ?? 00 00 00 70 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69}  //weight: 5, accuracy: Low
        $x_5_2 = {40 00 00 c0 20 20 20 20 20 20 20 20 00 ?? ?? 00 00 50 05 00 00 02 00 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = "%userappdata%\\RestartApp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTK_2147929479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTK!MTB"
        threat_id = "2147929479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 89 ca 83 f2 ?? 83 e1 37 01 c9 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTK_2147929479_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTK!MTB"
        threat_id = "2147929479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 0d ?? ?? ?? ?? 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 50 33 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTK_2147929479_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTK!MTB"
        threat_id = "2147929479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {88 5b 00 00 2b c1 33 d0 0f af 95}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 8b 85 ?? ?? ?? ?? 50 6a 00 ff 95 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? c7 85 ?? ?? ?? ?? d0 f9 82 20 83 bd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTK_2147929479_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTK!MTB"
        threat_id = "2147929479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 84 05 ?? ?? ?? ?? 8b 8d ?? ?? ?? ?? 0f b6 8c 0d ?? ?? ?? ?? 01 c8 b9 00 01 00 00 99 f7 f9 89 95 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 0f b6 b4 05 ?? ?? ?? ?? 8b 45 08 8b 8d ?? ?? ?? ?? 0f b6 14 08 31 f2 88 14 08 8b 85 ?? ?? ?? ?? 83 c0 01 89 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_PII_2147929566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.PII!MTB"
        threat_id = "2147929566"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d3 c1 ea 05 8d 0c 18 89 55 fc 8b 45 e8 01 45 fc 8b c3 c1 e0 ?? 03 45 e0 33 45 fc 33 c1 2b f8 89 7d f0 8b 45 d8 29 45 f8 83 6d ?? 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMCX_2147929567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMCX!MTB"
        threat_id = "2147929567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 18 89 65 ?? 83 ec 18 89 65 ?? c7 00 ?? ?? ?? ?? c7 40 04 ?? ?? ?? ?? c7 40 08 ?? ?? ?? ?? c7 40 0c ?? ?? ?? ?? c7 40 10 ?? ?? ?? ?? 31 c9 90 [0-21] 31 [0-47] fe c2 88 14 08 [0-15] 83 e2 [0-15] 8d 0c 51 83 f9 14 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_SPOS_2147929582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.SPOS!MTB"
        threat_id = "2147929582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 20 20 00 10 05 00 00 10 00 00 00 48 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 20 05 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTL_2147929728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTL!MTB"
        threat_id = "2147929728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b cb c1 e1 ?? 03 4d ?? 8d 14 18 33 ca 33 4d ?? 05 ?? ?? ?? ?? 2b f9 83 6d ?? ?? 89 7d ?? 89 45 ?? 0f 85}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTR_2147929911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTR!MTB"
        threat_id = "2147929911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 70 05 00 00 04 00 00 00 70 05}  //weight: 5, accuracy: High
        $x_5_2 = {20 20 20 00 20 20 20 20 00 60 05 00 00 10 00 00 00 60 05 00 00 10}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_OKV_2147929941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.OKV!MTB"
        threat_id = "2147929941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 ca 80 c2 c9 32 14 08 80 c2 6e 88 14 08 41 83 f9 20 75 ?? 50 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_RRX_2147930298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.RRX!MTB"
        threat_id = "2147930298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 ff d6 8b 55 14 33 c0 85 ff 74 ?? 8b c8 83 e1 03 8a 4c 0d ?? 30 0c 06 40 3b c7 72 ?? ff 45 10 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTG_2147930782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTG!MTB"
        threat_id = "2147930782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {20 20 20 00 20 20 20 20 00 00 05 00 00 10 00 00 00 60 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01}  //weight: 5, accuracy: High
        $x_5_2 = {4a 00 00 04 00 00 00 98 1c 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 74 61 67 67 61 6e 74}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAIV_2147930875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAIV!MTB"
        threat_id = "2147930875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 9c 0f 49 9e 00 00 88 1c 0e 81 fa 8d 00 00 00 ?? ?? a3 ?? ?? ?? ?? 41 3b ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMCY_2147930984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMCY!MTB"
        threat_id = "2147930984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 00 90 24 00 00 10 00 00 00 90 24 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMCZ_2147930986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMCZ!MTB"
        threat_id = "2147930986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 00 60 05 00 00 10 00 00 00 86 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAA_2147931031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAA!MTB"
        threat_id = "2147931031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 32 4b 13 01 00 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 90 04 00 00 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTC_2147931057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTC!MTB"
        threat_id = "2147931057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 68 06 00 00 00 60 00 00 00 08 00 00 00 32 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64}  //weight: 10, accuracy: High
        $x_1_2 = "defOff.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BO_2147931196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BO!MTB"
        threat_id = "2147931196"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {31 75 fc 81 3d ?? ?? ?? 00 13 02 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {c1 e6 04 03 75 ?? 8d 14 0b 33 f2 81 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {81 fe 42 71 20 00 7f 09 46 81 fe 12 7d 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_Z_2147931352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.Z!MTB"
        threat_id = "2147931352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 30 05 00 00 10 00 00 00 7a 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 40 05 00 00 02 00 00 00 8a 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AE_2147931353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AE!MTB"
        threat_id = "2147931353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c6 c1 e8 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? c1 e6 ?? 03 75 ?? 8d 14 0b 33 f2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GLK_2147931602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GLK!MTB"
        threat_id = "2147931602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 04 ?? ?? ?? ?? 31 c1 ba ?? ?? ?? ?? 29 ca 83 c1 ?? 81 e2 ?? ?? ?? ?? 83 e1 ?? 29 d1 88 8c 04 ?? ?? ?? ?? 40 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAB_2147931930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAB!MTB"
        threat_id = "2147931930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8a 84 32 4b 13 01 00 88 04 31 8b 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_YBD_2147932088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.YBD!MTB"
        threat_id = "2147932088"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {8b 45 08 0f 10 45 e0 0f 57 05 ?? ?? ?? ?? 0f 11 45 e0 0f 10 45 f0 0f 57 05 ?? ?? ?? ?? 0f 11 45 f0 f2 0f 10 45 e0 f2 0f 10 4d e8 f2 0f 10 5d f0 f2 0f 10 55}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ZZ_2147932122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ZZ!MTB"
        threat_id = "2147932122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 40 05 00 00 10 00 00 00 84 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 50 05 00 00 02 00 00 00 94 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMDG_2147932479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMDG!MTB"
        threat_id = "2147932479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fe 81 ef ?? ?? ?? ?? 03 c7 31 03 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 8b f0 83 c6 04 6a 00 e8 ?? ?? ?? ?? 03 f0 01 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_PMK_2147932636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.PMK!MTB"
        threat_id = "2147932636"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 c0 0f 1f 44 00 00 8b c8 83 e1 03 8a 4c 0d ?? 30 0c 02 40 3b c6 72 ef 47 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAD_2147932667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAD!MTB"
        threat_id = "2147932667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {87 d1 03 f3 33 d5 4f f7 d3 f7 12 46 f7 d3 33 dd f7 d6 49 2b df f7 de 33 c7 c1 c3 13 f7 d6 f7 d6 c1 cb 13 33 c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ZR_2147932826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ZR!MTB"
        threat_id = "2147932826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 80 05 00 00 10 00 00 00 92 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 ac 01 00 00 00 90 05 00 00 02 00 00 00 a2 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EWP_2147933278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EWP!MTB"
        threat_id = "2147933278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 fa 83 e2 03 32 04 13 88 46 01 46 47 49 75 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BM_2147933341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BM!MTB"
        threat_id = "2147933341"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {89 45 f8 8b 0d ?? ?? ?? 00 81 c1 fa 00 00 00 8b 55 f8 0f b6 02 33 c1 8b 4d f8 88 01 e9}  //weight: 4, accuracy: Low
        $x_1_2 = {03 c2 33 d2 b9 00 01 00 00 f7 f1 89 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTQ_2147933772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTQ!MTB"
        threat_id = "2147933772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 4c 04 ?? 89 c2 81 ca ?? ?? ?? ?? 31 ca 89 d1 81 f1 ?? ?? ?? ?? 83 e2 ?? 8d 0c 51 fe c1 88 4c 04 ?? 89 c1 83 e1}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 b4 04 ?? ?? ?? ?? 89 c2 31 ca 21 f2 31 ca b3 9d 28 d3 88 9c 04 ?? ?? ?? ?? 40 49 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LummaC_GE_2147933798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GE!MTB"
        threat_id = "2147933798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff c6 ff cf fe c3 8a 94 1d ?? ?? ?? ?? 02 c2 8a 8c 05 ?? ?? ?? ?? 88 8c 1d ?? ?? ?? ?? 88 94 05 ?? ?? ?? ?? 02 ca 8a 8c 0d ?? ?? ?? ?? 30 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BP_2147934016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BP!MTB"
        threat_id = "2147934016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {83 c4 08 88 45 ff 0f b6 4d ff 8b 55 08 03 55 f4 0f b6 02 33 c1 8b 4d 08 03 4d f4 88 01 e9}  //weight: 4, accuracy: High
        $x_1_2 = {f7 f6 03 ca 0f b6 c1 5e 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AAE_2147934161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AAE!MTB"
        threat_id = "2147934161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 03 8b 4d ?? 83 e9 ?? 89 06 83 6d ?? 01 89 13 89 4d ?? 75 ?? 89 16 89 03 8b 4f ?? 33 c8 89 0b 8b 07 33 c2 89 06 83 c6 ?? 8b 45 ?? 40 89 45 ?? 3b 45 ?? 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCJU_2147934301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJU!MTB"
        threat_id = "2147934301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 80 c1 ?? 32 4c 04 02 80 c1 ?? 88 4c 04 02 40 83 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BQ_2147934447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BQ!MTB"
        threat_id = "2147934447"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 e4 99 f7 7d e0 8b 45 e4 8b 4d ec 8b 75 dc 8b 04 81 33 04 96 8b 4d e4 8b 55 ec 89 04 8a e9}  //weight: 4, accuracy: High
        $x_1_2 = {0f b6 55 f4 03 04 91 5e 8b 4d fc 33 cd e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BR_2147934828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BR!MTB"
        threat_id = "2147934828"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 45 f8 0f b7 08 03 4d fc 89 4d fc 8b 55 f8 0f b7 42 02 c1 e0 0b 33 45 fc 89 45 e8 8b 4d fc c1 e1 10 33 4d e8 89 4d fc 8b 55 f8 83 c2 04 89 55 f8 8b 45 fc c1 e8 0b 03 45 fc 89 45 fc eb}  //weight: 4, accuracy: High
        $x_1_2 = {03 4d fc 89 4d fc 8b 45 fc 8b e5 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAG_2147934836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAG!MTB"
        threat_id = "2147934836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 0c 16 30 d9 88 0c 16 42 39 94 24 ?? ?? ?? ?? 89 f9 0f 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAG_2147934836_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAG!MTB"
        threat_id = "2147934836"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {88 45 ff 0f b6 55 ff 8b 45 08 03 45 f4 0f b6 08 33 ca 8b 55 08 03 55 f4 88 0a e9}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_FAF_2147935400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.FAF!MTB"
        threat_id = "2147935400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {87 c2 41 c1 cb 12 87 c1 2b f2 33 de f7 d6 21 05 ?? ?? ?? ?? 87 c3 f7 de 87 d6 c1 c8 1c 87 f3 f7 d1 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BS_2147935593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BS!MTB"
        threat_id = "2147935593"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 c1 0f b6 c1 f7 d1 89 ca 81 e2 00 ff ff ff 09 d0 31 c1 21 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTD_2147935663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTD!MTB"
        threat_id = "2147935663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1d e9 b6 df 59 88 d8 8c 59 88 d8 8c 59 88 d8 8c 33 94 da 8c 70 88 d8 8c 59 88 d9 8c 5b 88 d8 8c eb 94 c8 8c 5b 88 d8 8c 59 88 d8 8c 56 88 d8 8c e1 8e de 8c 58 88 d8 8c 52 69 63 68 59 88 d8 8c}  //weight: 5, accuracy: High
        $x_5_2 = {5b f0 06 00 6f 00 00 00 00 e0 06 00 48 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GQR_2147935873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GQR!MTB"
        threat_id = "2147935873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f af c8 89 c8 83 e1 ?? f7 d0 89 c3 83 e3 ?? 09 d9 31 c8 85 c8 0f 95 c0 0f 94 c4 83 fa ?? 0f 9c c1 83 fa ?? 0f 9f c5 89 ca 08 e1 20 ec 20 c2 30 c5 80 f1 ?? 08 e2 08 e9 b8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_SXXS_2147935885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.SXXS!MTB"
        threat_id = "2147935885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c1 80 c1 cf 32 0c 02 80 c1 62 88 0c 02 40 83 f8 1a 75}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 94 0f d2 9f 07 14 31 ca 89 d6 83 e6 2d 81 f2 ad 00 00 00 8d 14 72 80 c2 f7 88 94 0f d2 9f 07 14 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_CCIR_2147936010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCIR!MTB"
        threat_id = "2147936010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 94 c1 0f 95 c2 83 f8 0a 0f 9c c5 83 f8 09 b8 ?? ?? ?? ?? 0f 9f c6 20 d5 20 f1 08 d6 08 cd 88 e9 30 f1 84 ed 0f 45 c6 84 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_SOSX_2147936306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.SOSX!MTB"
        threat_id = "2147936306"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 0c b9 ?? ?? ?? ?? 89 44 24 28 8b 44 24 28 3d ?? ?? ?? ?? b8 ?? ?? ?? ?? 0f 4c c1 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTB_2147936332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTB!MTB"
        threat_id = "2147936332"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 24 00 00 50 ?? 00 00 4c 01 07 00 32 34 d0 67 00 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NL_2147936334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NL!MTB"
        threat_id = "2147936334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {75 34 ca 34 19 35 46 35 4e 35 54 35 6a 35 75 35 7d 35 98 35 a3 35 db 35 e1 35 0d 36 28 36 62 36 6b 36 71 36 b0 36 b4 36 c4 36 c8 36 d8 36 dc 36 e0 36 e8 36 00 37 04 37 1c 37 2c 37 30 37 52 37 98 37 9e 37 d1}  //weight: 2, accuracy: High
        $x_1_2 = "cerebrotonia.aspx" ascii //weight: 1
        $x_1_3 = "bray.xls" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ZUU_2147936663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ZUU!MTB"
        threat_id = "2147936663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 c1 83 e1 02 09 ca 0f af d6 01 fa 8b 7c 24 2c 83 f0 5b 01 c2 80 c2 01 8b 84 24 a8 00 00 00 88 54 04 6b 8b 84 24 ?? ?? ?? ?? d1 e0 83 e0 02 83 b4 24 a8 00 00 00 01 01 84 24 a8 00 00 00 8b 84 24 a8 00 00 00 e9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTZ_2147936689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTZ!MTB"
        threat_id = "2147936689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 8c 14 ?? ?? ?? ?? 31 d1 89 4c 24 ?? 8b 4c 24 ?? 80 c1 ?? 88 8c 14 ?? ?? ?? ?? 42 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GTZ_2147936689_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GTZ!MTB"
        threat_id = "2147936689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 00 e0 2e 74 ?? 67 67 61 6e 74 00 40 00 00 00 20 44 00 00 22 00}  //weight: 10, accuracy: Low
        $x_1_2 = "defOff.exe" ascii //weight: 1
        $x_1_3 = "offDef.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_LummaC_CCJT_2147936887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.CCJT!MTB"
        threat_id = "2147936887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 94 c6 0f 44 c3 83 3d ?? ?? ?? ?? ?? 0f 9c c2 0f 4d c6 89 fe 30 f2 0f 45 c3 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BT_2147936984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BT!MTB"
        threat_id = "2147936984"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c1 8b 4d ?? 30 08 8b 45 ?? 8b 4d ?? 89 45 ?? 2b 45 ?? 89 4d ?? 3b c8 0f 82}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BV_2147937246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BV!MTB"
        threat_id = "2147937246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {32 0c 16 30 d9 88 0c 16 42 39 94 24}  //weight: 3, accuracy: High
        $x_2_2 = {d0 e9 00 d9 0f b6 c9 8d 1c 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAT_2147937252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAT!MTB"
        threat_id = "2147937252"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {21 c1 31 d1 89 4d f0 8b 4d f0 80 c1 32 88 8c 06 b6 da 2b d9 40}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAY_2147937254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAY!MTB"
        threat_id = "2147937254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f b6 8c 04 46 e8 43 cc 31 c1 89 4c 24 04 8b 4c 24 04 80 c1 62 88 8c 04 46 e8 43 cc 40 3d be 17 bc 33}  //weight: 5, accuracy: High
        $x_5_2 = {89 4c 24 08 8b 44 24 08 89 c1 f7 d1 83 e1 1a 25 e5 00 00 00 29 c8 88 84 2c 11 f4 74 a0 45 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EATE_2147937525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EATE!MTB"
        threat_id = "2147937525"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 d6 c1 ee 1e 31 d6 69 d6 65 89 07 6c 01 ca 83 c2 fe 89 54 88 fc 81 f9 71 02 00 00 74 18 89 d6 c1 ee 1e 31 d6 69 d6 65 89 07 6c 01 ca 4a 89 14 88 83 c1 02}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAZZ_2147937527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAZZ!MTB"
        threat_id = "2147937527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d f0 83 e9 01 89 4d f0 83 7d f0 00 76 3f 8b 55 f8 0f b7 02 03 45 fc 89 45 fc 8b 4d f8 0f b7 51 02 c1 e2 0b 33 55 fc 89 55 e8 8b 45 fc c1 e0 10 33 45 e8 89 45 fc 8b 4d f8 83 c1 04 89 4d f8 8b 55 fc c1 ea 0b 03 55 fc 89 55 fc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALU_2147937700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALU!MTB"
        threat_id = "2147937700"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 6a 00 89 85 a8 df ff ff 8d 85 00 de ff ff 89 8d ac df ff ff c5 fd 7f 85 40 de ff ff c5 f8 28 8d 60 de ff ff c5 f0 57 8d a0 df ff ff 6a 00 6a 01 c5 f8 29 8d 60 de ff ff 50 c5 f8 77}  //weight: 2, accuracy: High
        $x_1_2 = {6a 00 50 8d 85 d8 df ff ff 50 8d 8d 88 de ff ff e8 ?? ?? ?? ?? 8d 85 3c df ff ff 50 68 00 20 00 00 8d 85 d8 df ff ff 50 56 ff d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ACLM_2147937889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ACLM!MTB"
        threat_id = "2147937889"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 ca 83 e2 0a 8d 5a ff 83 e3 02 89 cf 83 e7 08 0f af df 89 d6 29 fa 83 f6 02 01 f2 89 ce 83 e6 02 0f af d6 89 ce 81 f6 ?? ?? ?? ?? 01 de 01 d6 0f b6 14 08 31 d6 89 75 f0 8b 55 f0 80 c2 c2 88 14 08 89 ca 81 f2 ?? ?? ?? ?? 89 ce 83 ce 01 21 d6 83 f1 01 8d 0c 71 83 f9 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAAT_2147937895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAAT!MTB"
        threat_id = "2147937895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 d7 89 7c 24 04 8b 54 24 04 80 c2 04 88 94 04 01 00 00 80 40 49}  //weight: 5, accuracy: High
        $x_5_2 = {8d 14 7a 42 21 f2 89 54 24 04 8b 54 24 04 80 c2 a6 88 94 04 52 ff ff ff 40 49}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMM_2147937923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMM!MTB"
        threat_id = "2147937923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 eb 83 e2 09 89 c5 81 e5 ?? ?? ?? ?? 09 d5 31 dd 81 f5 ?? ?? ?? ?? 09 ef 89 f3 f7 d3 89 fa 21 da 89 fd 21 f5 29 fe 8d 14 56 31 fb 01 fb 29 eb 21 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_AMC_2147937924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.AMC!MTB"
        threat_id = "2147937924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 cf 81 f7 e1 00 00 00 89 ca 81 f2 1e cd 22 95 81 c9 e1 32 dd 6a 21 d1 89 ca 83 e2 02 89 cb 83 cb 02 0f af da 01 fb 81 e1 fd 00 00 00 83 f2 02 0f af d1 01 da fe c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_BW_2147938065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.BW!MTB"
        threat_id = "2147938065"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 84 05 ?? ?? ?? ?? 31 d0 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? 01 8b 45 ?? 3b 45 ?? 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GH_2147938163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GH!MTB"
        threat_id = "2147938163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 1c 0a 30 c3 88 1c 0a 41 39 8c 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAOO_2147938595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAOO!MTB"
        threat_id = "2147938595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {31 fb 89 5c 24 04 8b 5c 24 04 80 c3 78 88 9c 3c e8 53 1f 1e 47}  //weight: 5, accuracy: High
        $x_5_2 = {21 c7 89 7c 24 04 8b 44 24 04 04 4e 88 84 14 ca e2 4c bf 42 4e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAH_2147938602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAH!MTB"
        threat_id = "2147938602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 4d ec 80 c1 22 88 8c 1e 86 87 6c 1e 40 89 45 e8 8b 45 e0 43 48}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EAN_2147938604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EAN!MTB"
        threat_id = "2147938604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 d0 8b 55 f0 04 e6 8b 75 e8 88 84 0e 1c 8a ef d9 41 4a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALA_2147939122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALA!MTB"
        threat_id = "2147939122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f7 d6 33 1d 9c 2d 48 00 c1 c9 0d c1 ce 12 c1 c6 12 c1 c1 0d f7 d6 01 35 29 29 48 00 c7 05 87 28 48 00 a4 ff b0 51 4f c1 cb 1a 40 33 ca f7 de ff 15}  //weight: 3, accuracy: High
        $x_1_2 = {c1 c6 0d 2b 1d 4b 07 48 00 09 05 5a 28 48 00 43 e8 ?? ?? ?? ?? c1 e0 15 33 d2 f7 d6 ff c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_ALMZ_2147939551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.ALMZ!MTB"
        threat_id = "2147939551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 48 f4 f7 d9 1b c9 23 c8 51 6a 00 33 c0 38 45 b3 6a 00 6a 00 ff 75 b8 0f 94 c0 6a 01 83 c0 02 50 a1 70 9d 46 00 6a 10 68 ff 01 0f 00 50 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GXM_2147939552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GXM!MTB"
        threat_id = "2147939552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 ca c1 ea ?? 80 ca ?? 88 16 c1 e9 ?? 89 ca 83 f2 ?? 83 c9 ?? 21 d1 80 c9 ?? 88 4e ?? 80 e3 ?? 80 cb ?? 88 5e ?? b9 03 00 00 00 01 ce}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EANI_2147940173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EANI!MTB"
        threat_id = "2147940173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {83 ec 10 0f b7 45 da 83 c0 01 66 89 45 da 8b 45 cc 0f b7 40 06 66 39 45 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EHI_2147940175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EHI!MTB"
        threat_id = "2147940175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 95 64 ed ff ff 01 c2 83 c0 01 89 95 64 ed ff ff 3d 10 27 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_NFS_2147940329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.NFS!MTB"
        threat_id = "2147940329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 21 f8 89 da 21 f2 0f a4 c2 01 01 c0 01 f9 11 f3 89 d6 31 de 89 c7 31 cf f7 d2 f7 d0 21 c8 21 da}  //weight: 1, accuracy: High
        $x_2_2 = {01 f1 fe c1 89 c6 0f ad d6 89 d7 d3 ef f6 c1 ?? ?? ?? 89 fe 31 ff 31 d7 31 c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_IGB_2147940533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.IGB!MTB"
        threat_id = "2147940533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 fa 89 c3 c1 eb 12 89 c7 c1 ef 11 81 e7 e0 00 00 00 81 f3 f0 00 00 00 01 fb 8b 7c 24 ?? 88 1f 89 c3 c1 eb 0c 80 e3 3f 80 cb 80 88 5f 01 c1 e8 06 24 3f 0c 80 88 47 02 b0 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_EGN_2147941302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.EGN!MTB"
        threat_id = "2147941302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 c2 0f b6 c0 8a 84 05 f8 fe ff ff 30 83 ?? ?? ?? ?? 43 81 fb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaC_GZM_2147941524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaC.GZM!MTB"
        threat_id = "2147941524"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d9 81 f1 ?? ?? ?? ?? 83 e3 ?? 01 db 29 cb 88 9c 14 ?? ?? ?? ?? 42 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

