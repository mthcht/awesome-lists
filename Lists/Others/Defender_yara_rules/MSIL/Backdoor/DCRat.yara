rule Backdoor_MSIL_DCRat_GA_2147819111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.GA!MTB"
        threat_id = "2147819111"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DCRat" ascii //weight: 10
        $x_5_2 = "DCRat.Code" ascii //weight: 5
        $x_1_3 = "Camera" ascii //weight: 1
        $x_1_4 = "SELECT * FROM" ascii //weight: 1
        $x_1_5 = "Antivirus" ascii //weight: 1
        $x_1_6 = "schtasks" ascii //weight: 1
        $x_1_7 = "Webcam" ascii //weight: 1
        $x_1_8 = "stealer" ascii //weight: 1
        $x_1_9 = "browser" ascii //weight: 1
        $x_1_10 = "Discord" ascii //weight: 1
        $x_1_11 = "Screenshot" ascii //weight: 1
        $x_1_12 = "SELECT * FROM FirewallProduct" ascii //weight: 1
        $x_1_13 = "dplugin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_2147825893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat!MTB"
        threat_id = "2147825893"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 ff 03 3e 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 35 01 00 00 22 01 00 00 ad 04}  //weight: 3, accuracy: High
        $x_1_2 = "{11111-22222-10009-11112}" wide //weight: 1
        $x_1_3 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_4 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_RS_2147833671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.RS!MTB"
        threat_id = "2147833671"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 44 2b 45 2b 4a 2b 4b 18 5b 1e 2c 24 8d 1e 00 00 01 2b 42 16 2b 42 2b 1e 2b 41 2b 42 18 5b 2b 41 08 18 6f 22 00 00 0a 1f 10 28 23 00 00 0a 9c 08 18 58 16 2d fb 0c 08 18 2c cd 06 16 2d f3 32 d8 19 2c d5 07 2a 02 2b b9 6f 24 00 00 0a 2b b4 0a 2b b3 06 2b b2 0b 2b bb 0c 2b bb 07 2b bc 08 2b bb 02 2b bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_AM_2147835174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.AM!MTB"
        threat_id = "2147835174"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff a3 3f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 21 01 00 00 18 01 00 00 8c 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "DCRat.Code" wide //weight: 1
        $x_1_3 = "aHR0cHM6Ly9pcGluZm8uaW8vanNvbg" wide //weight: 1
        $x_1_4 = "Antivirus:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_B_2147843173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.B!MTB"
        threat_id = "2147843173"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 13 06 11 06 09 8e 69}  //weight: 2, accuracy: High
        $x_2_2 = {20 40 42 0f 00 5e 0b de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_SP_2147844276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.SP!MTB"
        threat_id = "2147844276"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 0b 00 00 0a 0a 06 28 ?? ?? ?? 0a 03 50 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 0f 00 00 0a 0c 08 07 6f ?? ?? ?? 0a 08 18 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 02 50 16 02 50}  //weight: 2, accuracy: Low
        $x_1_2 = "cMDTM.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_D_2147844635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.D!MTB"
        threat_id = "2147844635"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/stripchart /computer:localhost /period:5 /dataonly /samples" wide //weight: 2
        $x_2_2 = "del /a /q /f" wide //weight: 2
        $x_2_3 = "/c net user" wide //weight: 2
        $x_2_4 = "DCRat.Code" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_SPD_2147845025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.SPD!MTB"
        threat_id = "2147845025"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 18 9a 28 ?? ?? ?? 0a 0c 11 04 8e 69 1a 32 0a 11 04 19 9a 28 ?? ?? ?? 0a 0d 02 7c 58 00 00 04}  //weight: 3, accuracy: Low
        $x_1_2 = "BuildInstallationTweaksPlugin.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_F_2147845488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.F!MTB"
        threat_id = "2147845488"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff b7 3f 09 1e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 26 01 00 00 16 01 00 00 7f 05 00 00 2a 0d}  //weight: 2, accuracy: High
        $x_2_2 = "Confuser" ascii //weight: 2
        $x_2_3 = "BZip2" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_SPG_2147847221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.SPG!MTB"
        threat_id = "2147847221"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 6f 08 00 00 0a 0b 07 72 53 00 00 70 6f ?? ?? ?? 0a a5 0a 00 00 01 13 04 12 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 08 28 ?? ?? ?? 06 26 09 6f 0c 00 00 0a 2d cb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_G_2147852761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.G!MTB"
        threat_id = "2147852761"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 09 06 16 06 8e 69 6f ?? 00 00 0a 13 04 08 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 11 04 6f ?? 00 00 0a 13 05 2b}  //weight: 2, accuracy: Low
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_H_2147852773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.H!MTB"
        threat_id = "2147852773"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {77 ff b7 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 30 01 00 00 0c 01 00 00 1e 05 00 00 85 06}  //weight: 2, accuracy: High
        $x_1_2 = "UNCOMPRESSED_END" ascii //weight: 1
        $x_1_3 = "UNCONDITIONAL_MATCHLEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_MA_2147896257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.MA!MTB"
        threat_id = "2147896257"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 0a 02 28 ?? ?? ?? 0a 06 16 9a 03 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 7d ?? ?? ?? 04 02 06 18 9a 02 7b ?? ?? ?? 04 73 ?? ?? ?? 06 06 17 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_KAA_2147898416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.KAA!MTB"
        threat_id = "2147898416"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 11 04 11 0a 02 11 0a 91 03 11 0a 03 6f ?? 00 00 0a 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_I_2147899095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.I!MTB"
        threat_id = "2147899095"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a3 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 24 01 00 00 af 03 00 00 f8 0b 00 00 03 1c}  //weight: 2, accuracy: High
        $x_2_2 = "DarkCrystal RAT" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_J_2147899096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.J!MTB"
        threat_id = "2147899096"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a3 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 24 01 00 00 af 03 00 00 04 0c 00 00 15 1c}  //weight: 2, accuracy: High
        $x_2_2 = "DarkCrystal RAT" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_K_2147899714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.K!MTB"
        threat_id = "2147899714"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "jSECRMN2uUh0fW6MeH.Y7OR5DLD9poLlR4axw" ascii //weight: 2
        $x_2_2 = "GxV7QmoeICF2mh50fu.FP6E8LuOYh1uRDvJng" ascii //weight: 2
        $x_2_3 = "mvpbOg99PjLvdbnkrI.cLBjm8fZMMinCvfQFZ" ascii //weight: 2
        $x_2_4 = "DarkCrystal RAT" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_L_2147899788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.L!MTB"
        threat_id = "2147899788"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hBG0VnIlUfOCISBMZK.WTT95vPmmENthbNmPH" ascii //weight: 2
        $x_2_2 = "bqs6JKWlADqlEDalKA.MbWDAkGFfnmAESC5PM" ascii //weight: 2
        $x_2_3 = "29kPcnkQO6kESJwAVp.F4xJDtTN9YB4err3DC" ascii //weight: 2
        $x_2_4 = "DarkCrystal RAT" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_MB_2147900161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.MB!MTB"
        threat_id = "2147900161"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 ff a3 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 24 01 00 00 af 03 00 00 0e 0c 00 00 fd 1b 00 00 68 0b}  //weight: 1, accuracy: High
        $x_1_2 = "cy00fYiJIAjLkm1TTp" ascii //weight: 1
        $x_1_3 = "QNCrsiJpiyNybOjyV3.Ph5OjfZTud820ZkHal" ascii //weight: 1
        $x_1_4 = "W0m6SlQQvxn91H2ugf" ascii //weight: 1
        $x_1_5 = "Xke4Hr1b6dpqQlljFp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_SPF_2147901616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.SPF!MTB"
        threat_id = "2147901616"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "6c915634-4d3e-4325-b890-d8e2f1a3244f" ascii //weight: 2
        $x_1_2 = "XIqcjxmvSNORDdOW3SZ5kk8vNzmnFjXwwIIGcoxU" ascii //weight: 1
        $x_1_3 = "eBqg1qYY2MBJc40AiZ.t1oQwgWNtVa1T4XkgM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_M_2147902540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.M!MTB"
        threat_id = "2147902540"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 55 02 00 09 00 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 18 00 00 00 02 00 00 00 01 00 00 00 05}  //weight: 2, accuracy: High
        $x_2_2 = "DarkCrystal RAT" wide //weight: 2
        $x_1_3 = "lzmat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_PADQ_2147905183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.PADQ!MTB"
        threat_id = "2147905183"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 11 06 61 13 0e 16 13 0f 38 2d 00 00 00 11 0f 16 3e 0c 00 00 00 11 0b 1e 62 13 0b 11 0c 1e 58 13 0c 08 11 0a 11 0f 58 11 0e 11 0b 5f 11 0c 1f 1f 5f 64 d2 9c 11 0f 17 58 13 0f 11 0f 06 3f cb}  //weight: 1, accuracy: High
        $x_1_2 = {fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 11 00 00 00 64 61 fe 0e 15 00 fe 0c 15 00 fe 0c 11 00 58 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 0f 00 00 00 62 61 fe 0e 15 00 fe 0c 15 00 fe 0c 12 00 58 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 20 17 00 00 00 64 61 fe 0e 15 00 fe 0c 15 00 fe 0c 15 00 58 fe 0e 15 00 fe 0c 12 00 20 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_YY_2147910969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.YY!MTB"
        threat_id = "2147910969"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "261"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = "DarkCrystal RAT" ascii //weight: 100
        $x_100_3 = "\".NET Reactor\"" ascii //weight: 100
        $x_10_4 = "{11111-22222-50001-00000}" ascii //weight: 10
        $x_10_5 = "clrjit.dll" ascii //weight: 10
        $x_10_6 = "Virtual" ascii //weight: 10
        $x_10_7 = "Process" ascii //weight: 10
        $x_10_8 = "{11111-22222-40001-00001}" ascii //weight: 10
        $x_10_9 = "{11111-22222-40001-00002}" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_RHA_2147911323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.RHA!MTB"
        threat_id = "2147911323"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stealerlogstatus" wide //weight: 1
        $x_1_2 = "DCRat.Code" wide //weight: 1
        $x_1_3 = "svchost" wide //weight: 1
        $x_1_4 = "schtasks.exe" wide //weight: 1
        $x_1_5 = "screenshot" wide //weight: 1
        $x_1_6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_2_7 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 06 00 00 5a 16 00 00 06 00 00 00 00 00 00 6e 79 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_RHC_2147916588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.RHC!MTB"
        threat_id = "2147916588"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "stealerlogstatus" wide //weight: 1
        $x_1_2 = "passwords" wide //weight: 1
        $x_1_3 = "screenshot" wide //weight: 1
        $x_1_4 = "keyloggerdata" wide //weight: 1
        $x_1_5 = "Webcams" wide //weight: 1
        $x_1_6 = "cookies" wide //weight: 1
        $x_1_7 = "DCRat.Code" wide //weight: 1
        $x_1_8 = "Grabbing" wide //weight: 1
        $x_2_9 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 06 00 00 34 0c 00 00 06 00 00 00 00 00 00 2e 53 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_DCRat_GZZ_2147941219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/DCRat.GZZ!MTB"
        threat_id = "2147941219"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 25 16 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a a2 25 17 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a a2 25 18 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 19 72 ?? 01 00 70 72 ?? 00 00 70 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 1a 72 ?? 01 00 70 72 ?? 00 00 70 72 ?? 01 00 70 28 ?? 00 00 0a a2 25 1b 72 ?? 01 00 70 72 ?? 00 00 70 72 ?? 01 00 70 28 ?? 00 00 0a a2 7e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

