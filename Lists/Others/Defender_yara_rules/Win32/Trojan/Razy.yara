rule Trojan_Win32_Razy_V_2147743607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.V!MTB"
        threat_id = "2147743607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4a 03 32 8a ?? ?? ?? ?? 32 cb 88 8a ?? ?? ?? ?? 42 83 fa ?? 7c e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 41 03 32 81 ?? ?? ?? ?? 32 c2 88 81 ?? ?? ?? ?? 41 83 f9 ?? 7c e9}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 41 03 32 c2 30 81 ?? ?? ?? ?? 41 83 f9 ?? 7c ef}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_S_2147744055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.S!MSR"
        threat_id = "2147744055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HttpCrackUrl" ascii //weight: 1
        $x_1_2 = "http://xzqpl.chujz.com/l14.gif" wide //weight: 1
        $x_1_3 = "shield_2345explorer.exe" ascii //weight: 1
        $x_1_4 = "http://xzsite.chujz.com/soft/ad.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_T_2147744068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.T!MSR"
        threat_id = "2147744068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "47"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "http://xzsite.chujz.com/soft/ad.html" wide //weight: 10
        $x_10_2 = "\\extra.zip" wide //weight: 10
        $x_10_3 = "qhactivedefense" ascii //weight: 10
        $x_10_4 = "360totalsecurity" ascii //weight: 10
        $x_1_5 = "ethereal" ascii //weight: 1
        $x_1_6 = "httpanalyzer" ascii //weight: 1
        $x_1_7 = "ida pro" ascii //weight: 1
        $x_1_8 = "ollydbg" ascii //weight: 1
        $x_1_9 = "vboxservice" ascii //weight: 1
        $x_1_10 = "vmtool" ascii //weight: 1
        $x_1_11 = "wireshark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_MR_2147760725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.MR!MTB"
        threat_id = "2147760725"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 83 ec 08 56 8b 45 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? 8b 4d ?? 69 c9 ?? ?? ?? ?? 89 4d ?? 8b 55 ?? 81 ea ?? ?? ?? ?? 89 55 ?? a1 ?? ?? ?? ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 08 03 30 8b 4d 08 89 31 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? 05 ?? ?? ?? ?? 8b 55 08 8b 0a 2b c8 8b 55 08 89 0a 5e 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_G_2147761913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.G!MTB"
        threat_id = "2147761913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 c0 31 1a 42 81 c0 ?? ?? ?? ?? 29 c8 39 fa 75 df c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_SIBB_2147797099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.SIBB!MTB"
        threat_id = "2147797099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 b9 40 00 00 00 41 b8 00 ?? 00 00 ba ?? ?? ?? ?? 33 c9 ff 15 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 8b 0d ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 4c 8d 05 b1 6b 03 00 ba 04 48 8b 0d ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 28 39 04 24 73 ?? 8b 04 24 48 89 44 24 ?? 33 d2 8b 04 24 b9 ?? ?? ?? ?? f7 f1 8b c2 8b c0 48 8b 4c 24 30 0f be 04 01 48 8b 4c 24 20 48 8b 54 24 01 0f b6 0c 11 33 c8 8b c1 8b 0c 24 48 8b 54 24 20 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CC_2147811421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CC!MTB"
        threat_id = "2147811421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 db 74 01 ea 31 0e 29 f8 81 c6 04 00 00 00 29 c0 81 e8 92 2f 63 8b 39 de 75 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CD_2147811422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CD!MTB"
        threat_id = "2147811422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 01 ea 31 0a 01 d8 81 c2 04 00 00 00 46 39 fa 75 ec}  //weight: 2, accuracy: High
        $x_2_2 = {74 01 ea 31 01 81 c1 04 00 00 00 81 c7 [0-4] bb [0-4] 39 f1 75 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CG_2147812748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CG!MTB"
        threat_id = "2147812748"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {39 f6 74 01 ea 31 38 81 c1 [0-4] 81 c0 04 00 00 00 49 39 d8 75 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {31 1a 83 ec 04 c7 04 24 [0-4] 5f 29 c1 81 c2 04 00 00 00 39 f2 75 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CH_2147812749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CH!MTB"
        threat_id = "2147812749"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 ea 31 13 81 c7 [0-4] 81 c3 04 00 00 00 4e 39 c3 75 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CJ_2147813106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CJ!MTB"
        threat_id = "2147813106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 01 ea 31 19 48 81 ef [0-4] 81 c1 04 00 00 00 39 d1 75 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {01 ea 31 1e 09 c9 81 ea [0-4] 81 c6 04 00 00 00 21 d2 39 fe 75 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CK_2147813294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CK!MTB"
        threat_id = "2147813294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 c0 74 01 ea 31 0a 81 c2 04 00 00 00 39 c2 75 ef}  //weight: 2, accuracy: High
        $x_2_2 = {42 09 df 4b 81 eb 19 ec 0b 91 81 fa cf 50 00 01 75 c1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CM_2147813503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CM!MTB"
        threat_id = "2147813503"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 f7 31 01 09 de 81 eb ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 29 db 39 d1 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CN_2147813504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CN!MTB"
        threat_id = "2147813504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 37 81 c3 [0-4] 47 01 cb 29 d9 39 d7 75 d7}  //weight: 2, accuracy: Low
        $x_2_2 = {31 39 83 ec 04 89 14 24 5a 41 39 d9 75 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CQ_2147813953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CQ!MTB"
        threat_id = "2147813953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 d7 31 0b 43 68 [0-4] 8b 3c 24 83 c4 04 81 c2 [0-4] 39 c3 75 d0}  //weight: 2, accuracy: Low
        $x_2_2 = {31 08 01 ff 40 21 df 21 df 39 f0 75 d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CR_2147813954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CR!MTB"
        threat_id = "2147813954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 30 29 d1 81 c0 04 00 00 00 39 d8 75 ed}  //weight: 2, accuracy: High
        $x_2_2 = {31 16 46 09 df 09 db 39 c6 75 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_CL_2147814125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CL!MTB"
        threat_id = "2147814125"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d7 21 fa 31 08 40 39 f0 75 eb}  //weight: 2, accuracy: High
        $x_2_2 = {31 1f 81 c7 04 00 00 00 81 c2 [0-4] 29 f1 39 c7 75 e7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_GZS_2147814242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GZS!MTB"
        threat_id = "2147814242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 f8 47 bb ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? e8 ?? ?? ?? ?? 21 c7 01 c0 31 1a 48 81 c0 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 81 e8 c6 34 00 c0 09 c0 39 f2 75 d1 29 f8 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GN_2147814246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GN!MTB"
        threat_id = "2147814246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 39 29 d2 68 c3 b6 f8 44 8b 14 24 83 c4 ?? 81 c1 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 39 f1 75 cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GX_2147814613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GX!MTB"
        threat_id = "2147814613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d8 85 40 00 5a e8 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 31 11 81 c1 ?? ?? ?? ?? b8 ?? ?? ?? ?? 29 c0 39 d9 75 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GV_2147814815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GV!MTB"
        threat_id = "2147814815"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {42 31 19 41 09 f2 39 c1 75 ec 21 d2 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GR_2147814964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GR!MTB"
        threat_id = "2147814964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 01 d8 e8 ?? ?? ?? ?? 48 21 db 31 16 43 68 ?? ?? ?? ?? 8b 1c 24 83 c4 04 81 c6 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 fe 75 d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CS_2147815029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CS!MTB"
        threat_id = "2147815029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ea 31 33 b9 [0-4] 81 c3 04 00 00 00 21 c9 81 ea [0-4] 39 c3 75 e2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CU_2147815112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CU!MTB"
        threat_id = "2147815112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 57 5f 81 c1 [0-4] 81 fb 09 72 00 01 75 a3}  //weight: 2, accuracy: Low
        $x_2_2 = {31 32 01 c0 42 89 c9 39 fa 75 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_QQ_2147815162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.QQ!MTB"
        threat_id = "2147815162"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 ff 01 ff e8 ?? ?? ?? ?? 31 33 81 e8 ?? ?? ?? ?? 43 81 c7 ?? ?? ?? ?? 09 c7 39 cb 75 dd}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CV_2147815326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CV!MTB"
        threat_id = "2147815326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 19 89 d0 41 81 c2 [0-4] 52 5a 39 f1 75 db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_K_2147815550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.K!MTB"
        threat_id = "2147815550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {ba e8 b4 52 2e 29 ca 31 38 40 09 c9 39 f0 75 dd}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CW_2147815680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CW!MTB"
        threat_id = "2147815680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 16 81 c6 01 00 00 00 09 ff 29 c9 39 c6 75 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_S_2147815758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.S!MTB"
        threat_id = "2147815758"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 fa 34 eb 5f 81 c3 ?? ?? ?? ?? 81 fb f4 01 00 00 75 05 bb ?? ?? ?? ?? 01 f9 29 ff c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_QP_2147815942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.QP!MTB"
        threat_id = "2147815942"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 f0 31 1f 81 c7 ?? ?? ?? ?? 01 c0 29 f6 39 d7 75 e2 81 ee ?? ?? ?? ?? 01 c6 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AD_2147816061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AD!MTB"
        threat_id = "2147816061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 c0 bf d8 85 40 00 e8 ?? ?? ?? ?? 31 3b 81 c3 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 39 cb 75 e4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GE_2147816292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GE!MTB"
        threat_id = "2147816292"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bf d8 85 40 00 01 c2 e8 ?? ?? ?? ?? 21 d2 31 3e 46 09 d2 40 39 de 75 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_D_2147816520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.D!MTB"
        threat_id = "2147816520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {29 cf 81 ef ?? ?? ?? ?? 31 10 09 c9 40 4f 81 ef ?? ?? ?? ?? 39 d8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_XB_2147817133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.XB!MTB"
        threat_id = "2147817133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c1 24 15 27 16 39 f6 74 01 ea 31 33 4a 81 c0 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 39 fb 75 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_XA_2147817374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.XA!MTB"
        threat_id = "2147817374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 08 81 ea ?? ?? ?? ?? 09 ff 81 c0 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 01 d6 39 d8 75 df 83 ec 04 89 34 24 5a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_FX_2147817568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.FX!MTB"
        threat_id = "2147817568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 19 81 ea ?? ?? ?? ?? 81 e8 01 00 00 00 81 c1 04 00 00 00 29 f6 39 f9 75 e1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_VN_2147819358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.VN!MTB"
        threat_id = "2147819358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 95 71 67 68 ?? ?? ?? ?? 58 4f 81 e9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 06 81 c6 ?? ?? ?? ?? 89 c9 39 de 75 e0 68 ?? ?? ?? ?? 5f c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_RPY_2147819975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.RPY!MTB"
        threat_id = "2147819975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 06 81 c1 8a 91 ac 6f 81 c6 04 00 00 00 39 d6 75 e9 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_RPY_2147819975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.RPY!MTB"
        threat_id = "2147819975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 34 81 e9 00 00 00 00 40 3b c2 0f 82}  //weight: 1, accuracy: Low
        $x_1_2 = {31 02 81 c2 04 00 00 00 21 fb 39 f2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_UE_2147824986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.UE!MTB"
        threat_id = "2147824986"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3e 21 c2 29 c2 81 c6 ?? ?? ?? ?? 39 ce ?? ?? 29 d2 c3 09 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_UF_2147825152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.UF!MTB"
        threat_id = "2147825152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 de 81 c3 ?? ?? ?? ?? 31 0a 21 de 29 db 81 c2 ?? ?? ?? ?? 4b 39 c2 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AZY_2147842896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AZY!MTB"
        threat_id = "2147842896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 1f 33 99 ?? ?? ?? ?? f8 cf 2b f4 8b 4b 6c 89 ec 06 d3 cd a7 8d 76 f7 03 6a 95 61 5b 18 5b 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GNP_2147851594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GNP!MTB"
        threat_id = "2147851594"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 5b 81 c7 ?? ?? ?? ?? 31 16 89 f9 01 df 81 c6 04 00 00 00 39 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_DS_2147852320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.DS!MTB"
        threat_id = "2147852320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b6 d8 2c d8 85 0a 20 32 08 fc ed 9e 39 5c 5c 6c fa 44 8b 8d 22 8d 44 08 8d 45 d8 6a 7e 17 f7 0d 1c 1b f6 62 27 8b 48 a8 00 02 81 4d 42 cd f0 db cc b0 26 a0 da bf df 6c 86 01 7b 23 d9 e0 41 1d 41 e8 df 18 3b 70 ac}  //weight: 1, accuracy: High
        $x_1_2 = {16 37 40 48 e5 83 f0 e8 0b 84 c9 dc b7 a9 88 01 eb d0 56 93 08 be e7 b6 ee 5c 39 25 11 83 fa 1e 21 4d 71 98 e3 98 7b 83 f9 09 74 3e 3b f8 0d 31 20 dd ba 93 3d 0a 75 0b 6e eb c9 15 3b 56 74 2c 76 42 7b ce 67 9d 9b 10}  //weight: 1, accuracy: High
        $x_1_3 = {ca 08 a5 3e 3d 83 a5 dd c9 76 0c 01 c8 fc e8 f3 ed 1a ee 63 c7 85 f8 b4 f0 09 68 fc 72 50 7b dd 77 37 4b 85 f4 14 6a 01 68 bb e3 61 b5 21 05 dd 18 77 5f 12 68 38 80 e8 73 96 14 1f ba 96 e4 c0 be e4 81 fc 1c 56 3c 2c 84 7d 53 02 1f 36 3c 1c ec 1e 19}  //weight: 1, accuracy: High
        $x_1_4 = {ea f7 16 9f 1b f8 ee 28 f6 e8 8d 2c d4 29 68 70 26 c3 16 9b 8d cd e7 1b 2d 48 77 10 b6 d8 63 32 22 d8 5e 4d 14 ac 74 8a 9d 31 20 fc 7b 20 9f 63 93 ef 94 49 79 17 e3 15 ff 35 66 91 b3 03 76 11 d1 9f 9b 7c 67 bf b5}  //weight: 1, accuracy: High
        $x_1_5 = {db 68 c0 b0 67 b7 3b c9 68 af ef 04 e8 a6 50 b0 ee 10 08 16 ee e4 8f ff 3c 08 47 21 f2 95 6a b7 01 7e d6 ec ec 58 ec 68 a4 7f 1d e8 5e 7f 00 01 b6 d8 2c d8 85 0a 20 32 08 fc ed 9e 39 5c 5c 6c fa 44 8b 8d 22 8d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AMAB_2147852457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AMAB!MTB"
        threat_id = "2147852457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d 0c 7d ?? 8b 45 f8 99 f7 7d f4 8b 45 f0 8a 0c 10 88 4d ff 8b 55 08 03 55 f8 0f be 02 0f be 4d ff 33 c1 8b 55 08 03 55 f8 88 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_KA_2147890150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.KA!MTB"
        threat_id = "2147890150"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 0b 01 f6 09 f0 81 e1 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 21 d2 31 0f 21 c2 81 c0 ?? ?? ?? ?? 40 47 89 f0 ba ?? ?? ?? ?? 21 d2 81 c3 ?? ?? ?? ?? f7 d6 29 d0 81 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NR_2147893668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NR!MTB"
        threat_id = "2147893668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 00 00 00 83 ec ?? 75 05 74 03 33 bd ?? ?? ?? ?? 83 c4 04 eb 06 4c 29 c0 eb 05 2a eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NR_2147893668_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NR!MTB"
        threat_id = "2147893668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff 96 cc 65 0b 00 83 c7 ?? 8d 5e fc 31 c0 8a 07 47 09 c0 74 22 3c ?? 77 11 01 c3}  //weight: 3, accuracy: Low
        $x_3_2 = {24 0f c1 e0 ?? 66 8b 07 83 c7 ?? eb e2 8b ae c0 65 0b 00 8d be ?? ?? ?? ?? bb 00 10 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NR_2147893668_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NR!MTB"
        threat_id = "2147893668"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 3f 81 eb ?? ?? ?? ?? 01 c9 81 e7 ?? ?? ?? ?? 89 d9 29 cb 81 c2 ?? ?? ?? ?? 89 cb 89 d9 81 fa ?? ?? ?? ?? 75 05 ba 00 00 00 00 01 cb}  //weight: 5, accuracy: Low
        $x_5_2 = {31 3e f7 d3 89 d9 21 c9 81 c6 ?? ?? ?? ?? 81 c1 01 00 00 00 21 c9 49 39 c6 0f 8c 96 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_SPDR_2147895166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.SPDR!MTB"
        threat_id = "2147895166"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 d8 85 40 00 5a e8 ?? ?? ?? ?? 29 cf 31 16 81 c6 01 00 00 00 81 ef ba f0 a8 bc 21 c9 39 de 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AMBA_2147895215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AMBA!MTB"
        threat_id = "2147895215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 f0 29 f0 31 1f 09 f0 47 39 cf}  //weight: 1, accuracy: High
        $x_1_2 = {8b 1b 29 c0 81 e3 ff 00 00 00 42 81 fa f4 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AMBA_2147895215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AMBA!MTB"
        threat_id = "2147895215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 19 46 89 c0 41 39 d1 75}  //weight: 1, accuracy: High
        $x_1_2 = {8d 1c 1f 8b 1b 29 c6 81 e3 ff 00 00 00 89 f6 81 c7 01 00 00 00 09 c6 81 c6 ?? ?? ?? ?? 81 ff f4 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_SPDX_2147895921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.SPDX!MTB"
        threat_id = "2147895921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 e0 ea 40 00 bf d2 d5 63 a9 e8 ?? ?? ?? ?? 29 fb 31 0a 01 df 47 81 c2 01 00 00 00 47 89 fb 39 c2 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NRA_2147897179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NRA!MTB"
        threat_id = "2147897179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 87 84 08 00 00 3b 74 24 ?? 0f 87 7a 08 00 00 c1 e8 ?? 83 e3 0f 2e ff 24 9d ?? ?? ?? ?? 87 db 8b 06 8d 76 ?? 8b d8 d1 d8}  //weight: 5, accuracy: Low
        $x_1_2 = "ibillingsystems" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_ARA_2147897709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.ARA!MTB"
        threat_id = "2147897709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {88 11 8a 00 8b 4d 10 03 c2 25 ff 00 00 00 03 cf 8a 84 05 fc fe ff ff 30 01 47 3b 7d 14 7c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_ARA_2147897709_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.ARA!MTB"
        threat_id = "2147897709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Cum 4 Sluts.lnk" ascii //weight: 2
        $x_2_2 = "\\WINDOWS\\SYSTEM32\\Cum 4 Sluts-uninstall.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_SPDE_2147898106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.SPDE!MTB"
        threat_id = "2147898106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 13 46 81 c3 04 00 00 00 39 cb 75 ee}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GAB_2147898391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GAB!MTB"
        threat_id = "2147898391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 68 10 60 10 30 28 a8 ?? ?? ?? ?? b0 f8 a0 ?? ?? ?? ?? 40 d0 38 a0 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? e0 ?? 88 d0 88 50 b0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_CCGM_2147900473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.CCGM!MTB"
        threat_id = "2147900473"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 47 28 31 06 83 c6 04 3b 37 0f 82}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_GMX_2147901115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.GMX!MTB"
        threat_id = "2147901115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 32 89 d9 09 d8 42 81 c1 ?? ?? ?? ?? f7 d1 b8 ?? ?? ?? ?? 47 4b 81 e8 ?? ?? ?? ?? 09 d9 81 fa ?? ?? ?? ?? 0f 8c}  //weight: 10, accuracy: Low
        $x_10_2 = {21 cb 09 c1 81 c0 ?? ?? ?? ?? 31 16 01 c9 81 c1 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 09 c9 bb ?? ?? ?? ?? 40 81 c7 ?? ?? ?? ?? 21 db 29 c3 01 c9 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Razy_EC_2147907536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.EC!MTB"
        threat_id = "2147907536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f8 3e 34 02 90 01 00 00 00 50 b3 02 f1 28 04 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f 01 0b 01 07 0a 00 60 12 00 00 30 05 01 00 00 00 00 b4 e8 44 02}  //weight: 1, accuracy: High
        $x_1_3 = {10 d2 3b 01 00 70 77 01 00 e0 3b 01}  //weight: 1, accuracy: High
        $x_1_4 = {f1 28 04 00 00 50 b3 02 00 30 04 00 00 f0 3b 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NA_2147912532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NA!MTB"
        threat_id = "2147912532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Creating token stealing shellcode" ascii //weight: 1
        $x_1_2 = "Exploiting vulnerability" ascii //weight: 1
        $x_1_3 = "sc start remoteaccess" ascii //weight: 1
        $x_1_4 = "Elevating privileges to SYSTEM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_NE_2147925338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.NE!MTB"
        threat_id = "2147925338"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b d9 8d 43 ?? 83 38 ?? 75 04 33 c0 eb 34 83 cf ff f0 0f c1 38 4f 75 28 ff 73 ?? 8d 4d ?? e8 cb ad ff ff 8b 03 83 65 fc ?? 8b 70 ?? 8b ce}  //weight: 3, accuracy: Low
        $x_1_2 = "NxTch.exe" wide //weight: 1
        $x_1_3 = "is.ooffs.xyz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_BSA_2147926366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.BSA!MTB"
        threat_id = "2147926366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "hHYour computer has been trashed by the MEMZ trojan. Now enjo_" ascii //weight: 10
        $x_1_2 = "Nyan Cat..." ascii //weight: 1
        $x_1_3 = "YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN." ascii //weight: 1
        $x_1_4 = "Your computer won't boot up again," ascii //weight: 1
        $x_1_5 = "so use it as long as you can!" ascii //weight: 1
        $x_1_6 = "Trying to kill MEMZ will cause your system to be" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Razy_PGR_2147937929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.PGR!MTB"
        threat_id = "2147937929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 59 09 f6 ?? ?? ?? ?? ?? 31 10 81 c0 ?? ?? ?? ?? 46 39 d8 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_PGR_2147937929_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.PGR!MTB"
        threat_id = "2147937929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {66 bb e0 2c 8d 15 ?? ?? ?? ?? 87 cb c1 db 0a 89 d7 ?? 33 f7 c1 e3 0d 33 d8 81 f2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_PGR_2147937929_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.PGR!MTB"
        threat_id = "2147937929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 4d b4 8a 10 8b 45 e8 89 c1 81 c1 ?? ?? ?? ?? 89 4d e8 8a 75 cb 80 c6 4f 88 75 cb 88 10 8b 45 d8 8b 4d b0 01 c8 89 45 d8 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_ARZ_2147939574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.ARZ!MTB"
        threat_id = "2147939574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {c6 85 5c ff ff ff 56 c6 85 5d ff ff ff 69 c6 85 5e ff ff ff 72 c6 85 5f ff ff ff 74 c6 85 60 ff ff ff 75 c6 85 61 ff ff ff 61 c6 85 62 ff ff ff 6c c6 85 63 ff ff ff 41 c6 85 64 ff ff ff 6c c6 85 65 ff ff ff 6c c6 85 66 ff ff ff 6f c6 85 67 ff ff ff 63}  //weight: 3, accuracy: High
        $x_2_2 = {c6 85 4c ff ff ff 43 c6 85 4d ff ff ff 72 c6 85 4e ff ff ff 65 c6 85 4f ff ff ff 61 c6 85 50 ff ff ff 74 c6 85 51 ff ff ff 65 c6 85 52 ff ff ff 54 c6 85 53 ff ff ff 68 c6 85 54 ff ff ff 72 c6 85 55 ff ff ff 65 c6 85 56 ff ff ff 61 c6 85 57 ff ff ff 64}  //weight: 2, accuracy: High
        $x_1_3 = {c6 45 98 57 c6 45 99 69 c6 45 9a 6e c6 45 9b 45 c6 45 9c 78 c6 45 9d 65 c6 45 9e 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_PGZ_2147940189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.PGZ!MTB"
        threat_id = "2147940189"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2e 74 65 78 74 00 00 00 ae 18 00 00 00 ?? ?? 00 00 1a 00 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60}  //weight: 4, accuracy: Low
        $x_1_2 = {2e 64 61 74 61 00 00 00 00 ?? 09 00 00 ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AYR_2147940861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AYR!MTB"
        threat_id = "2147940861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 fa 83 ec 04 c7 04 24 ?? ?? ?? ?? 09 d1 81 e9 ?? ?? ?? ?? 21 fe ff d3 81 c7 ?? ?? ?? ?? 42 29 d7 5b 89 ca f7 d6 89 d7 68 ?? ?? ?? ?? 46 09 f2 f7 d2 50 42 29 d1 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_C_2147945058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.C!MTB"
        threat_id = "2147945058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Spy Is Active !" wide //weight: 2
        $x_2_2 = "Reporting : This Computer Turned On At:" wide //weight: 2
        $x_1_3 = "InformationAccess.txt" wide //weight: 1
        $x_1_4 = "Adobe!.exe" wide //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_PGRZ_2147946036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.PGRZ!MTB"
        threat_id = "2147946036"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 3f 75 75 3d 75 3f f4 d6 75 3d 1b 75 75 75 5a 1f 6e 24 3f 4a 1f 3d f4 7d 75 3d f4 75 9d 6e 75 80 02 00 00 bd 75 97 bd 3f ac a9 01 91 25 76 86 91 cd 73 a5 a5 2d a4 b6 ea 02 08 18 9b 81}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_AC_2147951445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.AC!MTB"
        threat_id = "2147951445"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 89 e5 53 57 56 83 e4 f8 81 ec 88 00 00 00 8b 45 08 31 c9 8b 54 24 78 8b 74 24 7c c7 44 24 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Razy_LM_2147952037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Razy.LM!MTB"
        threat_id = "2147952037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 84 0d fc fe ff ff 88 84 3d fc fe ff ff 89 4d fc 88 94 0d fc fe ff ff 0f b6 8c 3d fc fe ff ff 0f b6 c2 03 c8 81 e1 ff 00 00 80 79 ?? 49 81 c9 00 ff ff ff 41 0f b6 84 0d fc fe ff ff 32 04 33 8b 4d fc 88 06 46 ff 4d 08}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

