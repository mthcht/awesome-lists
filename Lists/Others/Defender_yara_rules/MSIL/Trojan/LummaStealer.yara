rule Trojan_MSIL_LummaStealer_A_2147847408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.A!MTB"
        threat_id = "2147847408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 b2 00 00 00 81 01 00 00 e1 05 00 00 f9 06 00 00 d5 05}  //weight: 2, accuracy: High
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "OpenSubKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_A_2147847408_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.A!MTB"
        threat_id = "2147847408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 03 8e 69 5d 17 58 17 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? ?? 03 08 19 58 18 59 03 8e 69 5d 91 59 20 ?? ?? ?? ?? 58 19 58 20 ?? ?? ?? ?? 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 1a 58 19 59 6e 5a 31 b1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AACB_2147849623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AACB!MTB"
        threat_id = "2147849623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 07 2b 3e 00 08 13 08 16 13 09 11 08 12 09 28 ?? 00 00 0a 00 08 07 11 07 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 de 0d 11 09 2c 08 11 08 28 ?? 00 00 0a 00 dc}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAFK_2147850999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAFK!MTB"
        threat_id = "2147850999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 08 28 ?? 00 00 06 25 17 28 ?? 00 00 06 25 18 28 ?? 00 00 06 25 06 28 ?? 00 00 06 28 ?? 00 00 06 07 16 07 8e 69 28 ?? 00 00 06 0d 20 ?? 00 00 00 38}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAFU_2147851345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAFU!MTB"
        threat_id = "2147851345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_2_4 = "a0f7e22d-8423-465f-9d4f-7274ab9ba414" ascii //weight: 2
        $x_2_5 = "CL.RegAsm.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAIA_2147851968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAIA!MTB"
        threat_id = "2147851968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 fc 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "nTOz2aV5mHQGFJ9hs6yIM2XFsxZzjzUgXXG0bRWhjIA=" wide //weight: 1
        $x_1_3 = "$$$A$ms$iS$c$a$n$B$u$f$f$er$$$" wide //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAJM_2147852664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAJM!MTB"
        threat_id = "2147852664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 02 11 08 02 11 08 91 11 01 61 11 00 11 03 91 61 d2 9c 38 ?? ?? ff ff 00 28 ?? 00 00 0a 03 6f ?? 00 00 0a 13}  //weight: 4, accuracy: Low
        $x_1_2 = "Main_Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAJP_2147852697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAJP!MTB"
        threat_id = "2147852697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 17 28 ?? 05 00 06 20 00 00 00 00 28 ?? 05 00 06 3a ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 00 11 05 11 0a 6f ?? 00 00 0a 20 01 00 00 00 28 ?? 05 00 06 39 ?? ff ff ff 26 38 ?? ff ff ff 00 11 09 11 04 16 11 04 8e 69 28 ?? 05 00 06 13 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_B_2147852740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.B!MTB"
        threat_id = "2147852740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/create /tn \"{0}\" /tr \"{1}\" /sc minute /mo 1" wide //weight: 2
        $x_2_2 = "schtasks" wide //weight: 2
        $x_2_3 = "/query /tn" wide //weight: 2
        $x_2_4 = "TargetPath" wide //weight: 2
        $x_2_5 = "CreateShortcut" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_PSUT_2147852966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.PSUT!MTB"
        threat_id = "2147852966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 68 67 14 16 9a 26 16 2d f9 28 ?? 00 00 06 7e 19 00 00 04 28 ?? 00 00 06 80 1b 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCAO_2147890128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCAO!MTB"
        threat_id = "2147890128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 11 05 91 13 06 08 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 59 65 61 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 5a 65 58 61 65 65 11 06 59 66 20 ?? ?? ?? ?? 20 ?? ?? ?? ?? 58 66 66 66 61 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 65 61 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 5a 52 08 17 58 0c 11 05 17 58 13 05 11 05 11 04 8e 69 32 92}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAOE_2147890312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAOE!MTB"
        threat_id = "2147890312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreamAPI_CSharp.Properties.Resources" wide //weight: 1
        $x_1_2 = "70a20485-a36f-4aae-bf34-4623e6bba783" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAPA_2147890524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAPA!MTB"
        threat_id = "2147890524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 20 88 48 79 7b 28 ?? 0b 00 06 28 ?? 0b 00 06 20 eb 48 79 7b 28 ?? 0b 00 06 28 ?? 0b 00 06 28 ?? 0b 00 06 13 09}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AAQU_2147892088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AAQU!MTB"
        threat_id = "2147892088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 0b 07 28 ?? 00 00 06 0d 16 20 ae 0b 0c 00 d8 7e ?? 02 00 04 7b ?? 02 00 04 2d 10 26 72 01 00 00 70 18 28 ?? ?? 00 0a 2b 02 11 09}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_C_2147892653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.C!MTB"
        threat_id = "2147892653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Remove -ItemProperty" wide //weight: 2
        $x_2_2 = "'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run' -Name" wide //weight: 2
        $x_2_3 = "gnirtS" wide //weight: 2
        $x_2_4 = "epyTytreporP-" wide //weight: 2
        $x_2_5 = "llehs" wide //weight: 2
        $x_2_6 = "eulaV" wide //weight: 2
        $x_2_7 = "power" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AMAA_2147892941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AMAA!MTB"
        threat_id = "2147892941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 07 38 ?? 00 00 00 11 07 13 08 38}  //weight: 4, accuracy: Low
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCCO_2147892974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCCO!MTB"
        threat_id = "2147892974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 01 11 02 11 01 93 20 ?? ?? ?? ?? 61 02 61 d1 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_E_2147892998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.E!MTB"
        threat_id = "2147892998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 16 07 16 1f 10}  //weight: 2, accuracy: High
        $x_2_2 = {08 16 07 1f 0f 1f 10}  //weight: 2, accuracy: High
        $x_2_3 = {09 04 16 04 8e 69 6f}  //weight: 2, accuracy: High
        $x_1_4 = "ResourceManager" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_E_2147892998_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.E!MTB"
        threat_id = "2147892998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oELWXSYqUjfvJOMuqgEOCJFcBckeF" ascii //weight: 1
        $x_1_2 = "dKAoMzVdoGMRAuUpnzHLYIx.dll" ascii //weight: 1
        $x_1_3 = "IEHFelbWpfskRKObtNEOyPsKdFPhK" ascii //weight: 1
        $x_2_4 = "bFISQFXZrlhowSppjMcUMEWMVO.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCCR_2147893142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCCR!MTB"
        threat_id = "2147893142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jaEHVOhUEVqrwqvjHIu" ascii //weight: 1
        $x_1_2 = "jhjQBrhWTqEOnSvtx8n" ascii //weight: 1
        $x_1_3 = "YJooTihFdybT9hQIknm" ascii //weight: 1
        $x_1_4 = "W4J61qhf8GRECFpl97u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_D_2147894010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.D!MTB"
        threat_id = "2147894010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mwTjzuNjzvaOWMphJrHxDCCiwskBF" ascii //weight: 1
        $x_1_2 = "AeLziORPazhmjqjqVRwUAQEDYBdVV" ascii //weight: 1
        $x_1_3 = "zydUOchkJtaUMbVdFDjykZApjfFfm" ascii //weight: 1
        $x_1_4 = "boUzIWhLhLDZGCLBanZcFsafhsdCv" ascii //weight: 1
        $x_1_5 = "krebeLHxsnOahIWzhvQlKYKdXyM" ascii //weight: 1
        $x_1_6 = "xFMtnazdAKmRwNcurDPFrHUVkMwPs" ascii //weight: 1
        $x_1_7 = "sxWsBcgMSxRdUCKXevfJKgAGAKoM.dll" ascii //weight: 1
        $x_1_8 = "nYCXFNKZaRnGnQmyFIHZNbCx" ascii //weight: 1
        $x_1_9 = "qIadkkJWSlcNQdQofhpMzxrd.dll" ascii //weight: 1
        $x_1_10 = "LsVgHFhAfthrvrwvVQnXVYBStlK.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCCW_2147894276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCCW!MTB"
        threat_id = "2147894276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 06 07 93 1f 3c 28 ?? ?? ?? ?? 61 02 61 d1 9d 38 ?? ?? ?? ?? 1e 28 ?? ?? ?? ?? 0c 2b b6 06 8e 69 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MA_2147896635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MA!MTB"
        threat_id = "2147896635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 11 03 16 11 03 8e 69 28 ?? ?? ?? 06 13 06 20 0c 00 00 00 28 ?? ?? ?? 06 3a 35 fe ff ff 26 38 2b fe ff ff 02 1f 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MA_2147896635_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MA!MTB"
        threat_id = "2147896635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 bf b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 f0 01 00 00 ea 00 00 00 39}  //weight: 5, accuracy: High
        $x_2_2 = "65773928-B6D0-2A57-231D-B0777A627A2C" ascii //weight: 2
        $x_2_3 = "CDBAA1C1-68A9-017B-C41D-303E45BB7F53" ascii //weight: 2
        $x_2_4 = "error_correction_update_check.My.Resources" ascii //weight: 2
        $x_2_5 = "installation_solution_for_use.My.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaStealer_UL_2147896651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.UL!MTB"
        threat_id = "2147896651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e 08 0a 00 04 0e 06 17 59 e0 95 58 0e 05 28 b4 2f 00 06 58 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SK_2147900370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SK!MTB"
        threat_id = "2147900370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 ae 00 00 00 58 d2 81 1c 00 00 01 03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 af 00 00 00 59 d2 81 1c 00 00 01 03 50 06 8f 1c 00 00 01 25 71 1c 00 00 01 20 e8 00 00 00 58 d2 81 1c 00 00 01 dd 03 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "Blinsson" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCFY_2147900754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCFY!MTB"
        threat_id = "2147900754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 00 61 00 6c 00 58 00 58 00 58}  //weight: 1, accuracy: High
        $x_1_2 = {58 00 4e 00 61 00 6d 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {06 49 06 35 06 43 06 27 06 28 06 6d 00 61 00 4e 00 79 00 42 00 6c 00 6c}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 6a 00 69 00 65 00 67 00 68 00 73 00 65 00 67 00 4e 00 61 00 6d 00 34 00 34 00 34 00 34 00 65}  //weight: 1, accuracy: High
        $x_1_5 = {53 00 2d 00 74 00 2d 00 2f 00 75 00 2f 00 2d 00 2f 00 62 00 2f 00 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCHE_2147901696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCHE!MTB"
        threat_id = "2147901696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C21220212a22120212l2120212l2120212B2120212y2121220212N2120212a2120221212m" wide //weight: 1
        $x_1_2 = "S`t`u`b`c`r`y`.`N`I`K`B`I`N`A`R`Y`3`2`b`i`t" wide //weight: 1
        $x_1_3 = "B2120212y2121220212N2120212a2120221212m22120212e" wide //weight: 1
        $x_1_4 = "L32313233o3231323A3231323d" wide //weight: 1
        $x_1_5 = "e7879787t7879787T7879787y7879787p" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_LummaStealer_SPPS_2147901841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SPPS!MTB"
        threat_id = "2147901841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 07 08 07 8e 69 5d 1f ?? 58 1f ?? 58 1f ?? 59 91 61 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MB_2147901890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MB!MTB"
        threat_id = "2147901890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 25 17 72 ?? ?? ?? 70 a2 25 18 11 02 a2 a2 a2 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MB_2147901890_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MB!MTB"
        threat_id = "2147901890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 17 1f 0b 6f ?? ?? ?? 0a 0c 08 02 8e 69 3c ?? ?? ?? ?? 08 02 8e 69 3d ?? ?? ?? ?? 73 ?? ?? ?? 06 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "d17b41c9-3955-4890-95b8-887aac006e0b" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCHI_2147901942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCHI!MTB"
        threat_id = "2147901942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 00 41 00 4e 00 be 03 c0 03 c0 03 bf 03 bc 03 b9 03 b6 03 b7 03 b5 03 b7 03 b4 03 c3 03 c5 03 bb 03 b9 03 c4 03 c8 03 49 00 42 00 4b 00 49 00 4e}  //weight: 1, accuracy: High
        $x_1_2 = {bc 03 b7 03 b9 03 ba 03 bd 03 c8 03 b5 03 b7 03 b5 03 bd 03 c5 03 b7 03 b5 03 b7 03 bb 03 bc 03}  //weight: 1, accuracy: High
        $x_1_3 = {bc 03 b6 03 c0 03 c0 03 c5 03 bd 03 c1 03 c8 03 b3 03 bd 03 c4 03 c5 03 c0 03 c7 03 c5 03 b9 03 c8 03 bb 03 c8 03 be 03 bc 03 bd 03 bc 03 c3 03 b9 03 c4 03 be 03 be 03 b7 03 c7 03 c4 03}  //weight: 1, accuracy: High
        $x_1_4 = {b2 03 c8 03 c6 03 b7 03 bc 03 be 03 bc 03 bf 03 c7 03 b3 03 6f 00 76 00 bc 03 b5 03 bd 03 bf 03 b6 03 bb 03 b1 03 c5 03 b9 03 b7 03 bf 03 b3 03 c0 03 bf 03 c0 03 bf 03 c3 03}  //weight: 1, accuracy: High
        $x_1_5 = {b7 03 ba 03 bf 03 b9 03 c6 03 b7 03 bc 03 bd 03 bc 03 b6 03 be 03 bc 03 b6 03 bc 03 bc 03 bd 03 be 03 bd 03 c7 03 b4 03 c7 03 c0 03 bb 03 bc 03 c3 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NA_2147901952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NA!MTB"
        threat_id = "2147901952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 93 00 00 70 1b 28 ?? 00 00 06 72 93 00 00 70 28 ?? 00 00 0a 13 06 11 06 28 ?? 00 00 0a 16}  //weight: 5, accuracy: Low
        $x_1_2 = "load_world.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NA_2147901952_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NA!MTB"
        threat_id = "2147901952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 61 38 00 06 0c 28 ?? ?? 00 0a 03 6f ?? ?? 00 0a 28 ?? ?? 00 06 0d 73 ?? ?? 00 0a 13 04 28 ?? ?? 00 06 13 05 11 05 08 6f ?? ?? 00 0a 11 05 09 6f ?? ?? 00 0a 11 04 11 05}  //weight: 5, accuracy: Low
        $x_1_2 = "live_stream_from_cosmos_events_app.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NA_2147901952_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NA!MTB"
        threat_id = "2147901952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05}  //weight: 5, accuracy: Low
        $x_1_2 = "Account/Login" ascii //weight: 1
        $x_1_3 = "WebMatrix.WebData.Resources.WebDataResources" ascii //weight: 1
        $x_1_4 = "enablePasswordReset" ascii //weight: 1
        $x_1_5 = "[Password], PasswordSalt" ascii //weight: 1
        $x_1_6 = "SET PasswordFailuresSinceLastSuccess" ascii //weight: 1
        $x_1_7 = "cryptoKey =" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_PADI_2147902152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.PADI!MTB"
        threat_id = "2147902152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 9a 00 00 00 61 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 1f 40 58 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 1f 43 59 d2 81 1a 00 00 01 03 50 06 8f 1a 00 00 01 25 71 1a 00 00 01 20 b8 00 00 00 58 d2 81 1a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAB_2147903528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAB!MTB"
        threat_id = "2147903528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 0e 91 61 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {11 0f 11 10 11 10 08 58 9e 11 10 17 58 13 10 11 10 11 0f 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f c5 07 00 0a 26 02 28 ?? 07 00 0a 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {28 c7 07 00 0a 06 16 06 8e 69 6f ?? 07 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 06 00 00 01 14 14 14 28 44 00 00 0a 28 52 00 00 0a 02}  //weight: 3, accuracy: High
        $x_3_2 = {7b 66 00 00 04 14 72 ?? 01 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 37 00 00 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 7e 65 03 00 04 28 ?? ?? 00 06 80 66 03 00 04 28 ?? ?? 00 06 28 a9 13 00 06 28 ?? ?? 00 06 61 28 ?? ?? 00 06 33 11 28 ?? ?? 00 06 80 66 03 00 04}  //weight: 5, accuracy: Low
        $x_1_2 = "LoaderV1.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 28 9e 00 00 0a 39 ?? 00 00 00 7e ?? 00 00 04 74 2f 00 00 01 2a 07 17 58 0b 07 7e 3e 00 00 04 8e 69 3f d2 ff ff ff}  //weight: 3, accuracy: Low
        $x_3_2 = {02 6f 9a 00 00 0a 6f ?? 00 00 0a 25 7e ?? 00 00 04 74 2f 00 00 01 6f 9a 00 00 0a 6f 9b 00 00 0a}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 13 16 11 16 20 ?? ?? ?? 80 2e 1d 11 16 20 ?? ?? ?? 7f 2e 14 08 11 05 07 91 11 06 07 91 58 58 0c 08 20 ?? ?? ?? 00 5d 0c 11 05 07 91 13 0f 11 05 07 11 05 08 91 9c 11 05 08 11 0f 9c 07 17 58 0b 07 20 00 01 00 00 32 b7}  //weight: 5, accuracy: Low
        $x_1_2 = "kjcbkjiw" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Kateyko_crypted" ascii //weight: 2
        $x_2_2 = "$2a281279-e1a5-4b0a-b2ef-192de95d38cd" ascii //weight: 2
        $x_2_3 = "Mozilla Firefox browser for all" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NL_2147903607_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NL!MTB"
        threat_id = "2147903607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 10 8d 76 00 00 01 13 14 11 09 28 ?? ?? ?? 0a 16 11 14 16 1a 28 ?? ?? ?? 0a 11 0a 28 36}  //weight: 5, accuracy: Low
        $x_1_2 = "programm_categories_products_update.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAC_2147903808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAC!MTB"
        threat_id = "2147903808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0d 8f ?? 00 00 01 25 71 ?? 00 00 01 11 01 11 11 91 61 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {11 01 11 03 91 11 01 11 15 91 58 20 00 ?? 00 00 5d 13 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAD_2147904261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAD!MTB"
        threat_id = "2147904261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 09 11 ?? 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ARA_2147904388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ARA!MTB"
        threat_id = "2147904388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e3 06 0d 2b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCHT_2147904422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCHT!MTB"
        threat_id = "2147904422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 0a 74 ?? ?? ?? ?? 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? ?? ?? ?? 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 01 00 0a 26 1f 10 13 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAE_2147904487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAE!MTB"
        threat_id = "2147904487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 13 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 0e 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAF_2147904501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAF!MTB"
        threat_id = "2147904501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d4 91 61 07 11 ?? 17 6a 58 07 8e 69 6a 5d d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAG_2147904693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAG!MTB"
        threat_id = "2147904693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 09 11 0e 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AMMB_2147904783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AMMB!MTB"
        threat_id = "2147904783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 11 0b 8f ?? 00 00 01 25 71 ?? 00 00 01 08 11 ?? 91 61 d2 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAH_2147904787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAH!MTB"
        threat_id = "2147904787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 09 8f 1d 00 00 01 25 71 1d 00 00 01 11 ?? 11 ?? 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AMMD_2147905295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AMMD!MTB"
        threat_id = "2147905295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 08 11 ?? 91 61 d2 81}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NLM_2147905705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NLM!MTB"
        threat_id = "2147905705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 14 72 5f 29 00 70 16 8d ?? ?? 00 01 14 14 14 28 ?? ?? 00 0a 28 39 00 00 0a 13 05 11 04 11 05 28 ?? ?? 00 0a 6f 34 01 00 0a 00 11 0c 11 0b 12 0c 28 ?? ?? 00 0a 13 0e 11 0e 2d c4 11 04 6f ?? ?? 00 0a 28 08 00 00 2b}  //weight: 3, accuracy: Low
        $x_3_2 = {28 d0 00 00 0a 14 72 ?? ?? 00 70 17 8d ?? ?? 00 01 25 16 72 00 24 00 70 a2 14}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NLS_2147906115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NLS!MTB"
        threat_id = "2147906115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 41 00 00 04 07 9a 06 28 ?? 00 00 0a 39 ?? 00 00 00 7e ?? 00 00 04 74 ?? 00 00 01 2a 07 17 58 0b 07 7e ?? 00 00 04 8e 69 3f d2 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Prosimian" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ALM_2147906215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ALM!MTB"
        threat_id = "2147906215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 19 6c 11 1a 6c 5b 28 4b 00 00 0a b7 13 10 20 02}  //weight: 2, accuracy: High
        $x_1_2 = "This assembly is protected by an unregistered version of Eziriz's" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ALM_2147906215_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ALM!MTB"
        threat_id = "2147906215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oFYSVYzChxVsXWmRsYqu.dll" ascii //weight: 1
        $x_1_2 = "tzYslkEExBzhWQjYATHOe.dll" ascii //weight: 1
        $x_1_3 = "OdZokoKlJenvDbhTg.dll" ascii //weight: 1
        $x_1_4 = "HeWSfFWuFmmMEQy.dll" ascii //weight: 1
        $x_1_5 = "ILLnogZyZLUtVXiOvwRHpTewBNs.dll" ascii //weight: 1
        $x_1_6 = "d4f5e6a7-b8c9-4012-8a34-56789abcd012" ascii //weight: 1
        $x_1_7 = "5Pioneering technology solutions for a smarter future" ascii //weight: 1
        $x_1_8 = "QuantumWave Innovations Trademark" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NM_2147906801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NM!MTB"
        threat_id = "2147906801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1f 10 8d 7e 00 00 01 13 14 11 09 28 ?? 07 00 0a 16 11 14 16 1a 28 ?? 07 00 0a 11 0a 28 ?? 07 00 0a 16 11 14}  //weight: 3, accuracy: Low
        $x_1_2 = "FernandoKap_digitalEU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NM_2147906801_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NM!MTB"
        threat_id = "2147906801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {28 0b 00 00 06 73 ?? 00 00 06 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? 00 00 06 15 7e ?? 00 00 04 16 8f ?? 00 00 01 7e ?? 00 00 04 8e 69 1f 40 12 00 28 0a 00 00 06}  //weight: 3, accuracy: Low
        $x_3_2 = {26 16 0b 20 88 01 00 00 0c 16 16 7e ?? 00 00 04 08 8f ?? 00 00 01 7e ?? 00 00 04 16 12 01 28 08 00 00 06}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NM_2147906801_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NM!MTB"
        threat_id = "2147906801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "VioletRichPlayer364David.ZODvl" ascii //weight: 2
        $x_2_2 = "teach we solution module i connect she i service she" ascii //weight: 2
        $x_2_3 = "system rough connect explore project" ascii //weight: 2
        $x_1_4 = "$b2a7142c-b5a4-416b-90bd-cf3632694be8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RPZ_2147907580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RPZ!MTB"
        threat_id = "2147907580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 47 09 11 0c 91 61 d2 52 11 0a 17 58 13 0a 11 0a 03 8e 69 32 a5 11 09 17 58 13 09 11 09 17 32 95 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SPDO_2147907935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SPDO!MTB"
        threat_id = "2147907935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 58 20 00 01 00 00 5d 0b 08 09 07 91 58 20 00 01 00 00 5d 0c 16 13 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_G_2147913012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.G!MTB"
        threat_id = "2147913012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bd 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3d 00 00 00 83 00 00 00 6b 03 00 00 70 05}  //weight: 2, accuracy: High
        $x_1_2 = "_crypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDE_2147913016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDE!MTB"
        threat_id = "2147913016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SkyHigh Technologies Trademark" ascii //weight: 1
        $x_1_2 = "Revolutionizing connectivity with cutting-edge cloud solutions." ascii //weight: 1
        $x_1_3 = "QuantumWave" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GP_2147913067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GP!MTB"
        threat_id = "2147913067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DOylgMLvRcnaTTPsnBc" ascii //weight: 1
        $x_1_2 = "OergBcaAGPSxGICMDFJxnj" ascii //weight: 1
        $x_1_3 = "rwZVySkKFaHXHPcjNWwZrfQkmj" ascii //weight: 1
        $x_1_4 = "LypLLCLTwrZTRuAthcfxEHS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_LummaStealer_NB_2147913085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NB!MTB"
        threat_id = "2147913085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54}  //weight: 5, accuracy: High
        $x_5_2 = "fc43a296-9ea0-490c-90ea-4bd21e241862" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_H_2147913093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.H!MTB"
        threat_id = "2147913093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 bd 02 3c 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3e 00 00 00 82 00 00 00 d9 04 00 00 4a 05}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAI_2147913121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAI!MTB"
        threat_id = "2147913121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YinZSuXobJqksJupKDSTZo" ascii //weight: 1
        $x_1_2 = "lZENxFPfdXCRdPVUGvhsKtiu" ascii //weight: 1
        $x_1_3 = "rMIkOKRtEE" ascii //weight: 1
        $x_1_4 = "dIZqSDpklXuEfJggP" ascii //weight: 1
        $x_1_5 = "Leading the future of integrated technology solutions." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDF_2147913514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDF!MTB"
        threat_id = "2147913514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Celestial Innovations Trademark" ascii //weight: 1
        $x_1_2 = "Innovative solutions driving the future of technology" ascii //weight: 1
        $x_1_3 = "a7f8d6b4-e9d3-4019-8b24-98765bcdef12" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCIQ_2147913515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCIQ!MTB"
        threat_id = "2147913515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b 62 fe 0c ?? 00 59 fe 0c ?? 00 61 fe 0c 1a 00 58 fe 0e 1a 00 fe 0c 1a 00 76 6c 6d 58 13 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDG_2147913780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDG!MTB"
        threat_id = "2147913780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c3e7b1d9-f2c5-4a92-9b23-6f7c8e4d9101" ascii //weight: 1
        $x_1_2 = "AetherDynamics" ascii //weight: 1
        $x_1_3 = "Aether Advanced Suite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SM_2147915523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SM!MTB"
        threat_id = "2147915523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CosmicEdge Technologies Trademark" ascii //weight: 2
        $x_2_2 = "$e3d2f8a9-b7c5-4a23-8d12-65432abcde90" ascii //weight: 2
        $x_2_3 = "Pushing the boundaries of technology for a brighter tomorrow" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAJ_2147915538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAJ!MTB"
        threat_id = "2147915538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QPbwWOQpzTU" ascii //weight: 1
        $x_1_2 = "dOuAtAnZoN" ascii //weight: 1
        $x_1_3 = "meIxWaqIXuNCIStc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAK_2147915539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAK!MTB"
        threat_id = "2147915539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "b3d4c5e6-f7a8-9012-bcde-34567ef89012" ascii //weight: 1
        $x_1_2 = "LuminaraTech Innovations" ascii //weight: 1
        $x_1_3 = "innovations for a brighter technological future" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AMAM_2147915834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AMAM!MTB"
        threat_id = "2147915834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jTmZfSdSRiWIrtIZDvBhg" ascii //weight: 1
        $x_1_2 = "HApQgvjzSydrlmPbxPPnxed" ascii //weight: 1
        $x_1_3 = "HQXlADyFVmXGDBnnWfZOeGwGVIpW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAL_2147915898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAL!MTB"
        threat_id = "2147915898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d3e4f5a6-b7c8-9012-abcd-23456ef78901" ascii //weight: 1
        $x_1_2 = "HyperionTech Innovations Trademark" ascii //weight: 1
        $x_1_3 = "Transforming the world with cutting-edge technology innovations" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_I_2147915966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.I!MTB"
        threat_id = "2147915966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 02 8e 69 fe 04}  //weight: 2, accuracy: High
        $x_2_2 = {06 17 58 0a 08}  //weight: 2, accuracy: High
        $x_2_3 = {02 06 02 06 91 66 d2 9c}  //weight: 2, accuracy: High
        $x_4_4 = "_appdata" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAM_2147916977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAM!MTB"
        threat_id = "2147916977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6f8af69d-486a-4cd6-ba6e-83ae85bbc060" ascii //weight: 1
        $x_1_2 = "Intel Core Inc. Trademark" ascii //weight: 1
        $x_1_3 = "Adjectives which will randomly appear with a click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_J_2147917152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.J!MTB"
        threat_id = "2147917152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {57 fd 02 fc 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 93 09 00 00 79 03}  //weight: 4, accuracy: High
        $x_2_2 = "GetDelegateForFunctionPointer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NK_2147917178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NK!MTB"
        threat_id = "2147917178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 69 8d 25 00 00 01 25 17 73 ?? 00 00 0a 13 04 06 6f ?? 00 00 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f 16 00 00 06}  //weight: 3, accuracy: Low
        $x_1_2 = "JSylCAgIufPyrE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCJB_2147917223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCJB!MTB"
        threat_id = "2147917223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 06 03 04 6f 17 00 00 0a 0b 02 07 28 05 00 00 06 0c de 14 07 2c 06 07 6f 18 00 00 0a dc 06 2c 06 06 6f 18 00 00 0a dc 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_CCJB_2147917223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.CCJB!MTB"
        threat_id = "2147917223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 06 07 93 20 98 00 00 00 61 02 61 d1 9d 07 17 59 25 0b 16 2f e9}  //weight: 1, accuracy: High
        $x_2_2 = {11 06 11 07 11 05 11 07 6f d9 00 00 0a 20 67 0f 00 00 61 d1 9d 1f 09 13 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_LLO_2147917735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.LLO!MTB"
        threat_id = "2147917735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 01 00 00 04 02 25 17 58 10 00 91 7e 01 00 00 04 02 25 17 58 10 00 91 1e 62 60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 10 62 60 7e 01 00 00 04 02 25 17 58 10 00 91 1f 18 62 60 0c 28 ?? ?? ?? 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 17 00 00 0a a5 01 00 00 1b 0b 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAN_2147919410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAN!MTB"
        threat_id = "2147919410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 13 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 1f 91 61 d2 81 ?? 00 00 01 11 13 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPB_2147919705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPB!MTB"
        threat_id = "2147919705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 d2 81 1c 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPB_2147919705_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPB!MTB"
        threat_id = "2147919705"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FMsmfPvpRTiJdDAipsx" ascii //weight: 2
        $x_2_2 = "btvHvRxBAlYaRPY" ascii //weight: 2
        $x_2_3 = "ZKLLDguMzDHE" ascii //weight: 2
        $x_2_4 = "fVpJRuXUyhGxRhaIcgZK" ascii //weight: 2
        $x_2_5 = "xPloyPSpijYoSnlkGGCGIgDL" ascii //weight: 2
        $x_2_6 = "alkmJIovvMRZyWZasQMu" ascii //weight: 2
        $x_2_7 = "ClvBQJCDBVnRhnruzdGZe" ascii //weight: 2
        $x_2_8 = "XCXbpOpdgKSRNNPjIVwWYugAU" ascii //weight: 2
        $x_1_9 = "tLrmzJMsrWOFWmoOxcctAcCafzA.d" ascii //weight: 1
        $x_1_10 = "FgLHhdSuJHOQcVWHZfF.d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_LummaStealer_SARA_2147919850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SARA!MTB"
        threat_id = "2147919850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17 58 13 13}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAO_2147920031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAO!MTB"
        threat_id = "2147920031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 13 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 1c 91 61 d2 81 ?? 00 00 01 11 13 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SDE_2147920106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SDE!MTB"
        threat_id = "2147920106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 25 11 27 37 09 11 2b 11 40 61 13 2c 2b 0a 11 3c 6e 11 29 6a 5b 6d 13 2c 11 31 6e 11 2b 6a 2f 09 11 42 11 3d 61 13 2b 2b 24 11 30 6e 11 22 6a 61 69 13 28 11 39 6e 11 36 6a 61 69 13 36 11 34 6e 11 23 6a 5b 26 11 20 6a 11 27 6e 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_KAP_2147920349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.KAP!MTB"
        threat_id = "2147920349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 1d 17 6f ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 11 13 17 58 13 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPC_2147920618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPC!MTB"
        threat_id = "2147920618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 d2 81 ?? 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AMAI_2147920676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AMAI!MTB"
        threat_id = "2147920676"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 03 08 03 8e 69 5d 91 9c 08 17 58 0c}  //weight: 1, accuracy: High
        $x_2_2 = {91 61 d2 81 [0-30] 02 8e 69 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AYB_2147921621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AYB!MTB"
        threat_id = "2147921621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JustABackDoor\\obj\\Debug\\JustABackDoor.pdb" ascii //weight: 2
        $x_1_2 = "$78abf6e4-a4da-4498-8eff-73869225ff27" ascii //weight: 1
        $x_1_3 = "JustABackDoor.Executor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AYB_2147921621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AYB!MTB"
        threat_id = "2147921621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AFTER INSTALLATION, SOLARA WILL APPEAR ON YOUR DESKTOP" wide //weight: 2
        $x_1_2 = "Add-MpPreference -ExclusionPath" wide //weight: 1
        $x_1_3 = "properties/bla.jpg" wide //weight: 1
        $x_1_4 = "debug.exe" wide //weight: 1
        $x_1_5 = "RunPowerShellCommand" ascii //weight: 1
        $x_1_6 = "debug.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AYC_2147921622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AYC!MTB"
        threat_id = "2147921622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "psicologiaecultura.com.br" ascii //weight: 2
        $x_1_2 = "function Hide-Console" ascii //weight: 1
        $x_1_3 = "StartRvrShell" ascii //weight: 1
        $x_1_4 = "if ($exeName -eq \"RSGame.exe\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPD_2147921833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPD!MTB"
        threat_id = "2147921833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 d2 81 14 00 00 01 de 05 13 [0-32] 03 8e 69 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MUM_2147922434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MUM!MTB"
        threat_id = "2147922434"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {61 69 13 26 08 17 58 20 ?? ?? ?? 00 5d 0c 09 06 08 91 58 20 ?? ?? ?? 00 5d 0d 06 08 91 13 27 06 08 06 09 91 9c 06 09 11 27 9c 06 08 91 06 09 91 58}  //weight: 4, accuracy: Low
        $x_5_2 = {6a 5b 26 11 2b 11 2e 37 07 11 33 11 33 5b 13 31 16 13 34 12 1f 28 19 00 00 0a 12 34 28 ?? ?? ?? 0a 26 16 13 35 12 28 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 35}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDH_2147922994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDH!MTB"
        threat_id = "2147922994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 73 20 00 00 0a 0c 08 06 07 6f 21 00 00 0a 0d 73 22 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDI_2147923018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDI!MTB"
        threat_id = "2147923018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 06 07 6f 22 00 00 0a 0d 73 23 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SN_2147923164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SN!MTB"
        threat_id = "2147923164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 03 00 00 04 06 06 9e 02 7b 03 00 00 04 06 94 28 14 00 00 0a 06 17 58 0a 06 02 7b 03 00 00 04 8e 69 32 db}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SO_2147923797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SO!MTB"
        threat_id = "2147923797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 72 61 00 00 70 6f 1e 00 00 0a 80 02 00 00 04 dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_K_2147924020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.K!MTB"
        threat_id = "2147924020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 06 02 06 91 66 d2 9c 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81}  //weight: 4, accuracy: Low
        $x_2_2 = {06 17 58 0a 06 02 8e 69 fe 04 0b 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ALS_2147924061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ALS!MTB"
        threat_id = "2147924061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 3a 00 02 06 02 06 91 66 d2 9c 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 79 59 d2 81 36 00 00 01 02 06 8f 36 00 00 01 25 71 36 00 00 01 1f 57 59 d2 81 36 00 00 01 00 06 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPE_2147925158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPE!MTB"
        threat_id = "2147925158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 11 09 11 05 5a 06 58 17 6a 58 13 0b 07 11 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_RDK_2147925457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.RDK!MTB"
        threat_id = "2147925457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "a64ee66e-f604-483f-beee-080eadea5823" ascii //weight: 2
        $x_1_2 = "design network them green innovate" ascii //weight: 1
        $x_1_3 = "complex integrate build quick sun understand network power fast support" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_NCT_2147927980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.NCT!MTB"
        threat_id = "2147927980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PuOfXRUnHTOhvjNvnlxr" ascii //weight: 2
        $x_1_2 = "LsXIBKnWqmnzMaBjtpyTiovMLiUZ" ascii //weight: 1
        $x_1_3 = "tsrnKMMRWaSmgIGBadTmRDVK.dll" ascii //weight: 1
        $x_1_4 = "IvRzfftVAexkHoQJPrcwNKzchoyZQ" ascii //weight: 1
        $x_1_5 = "EMgVkXRBlViHxiKJoGXomDnkozkr.dll" ascii //weight: 1
        $x_1_6 = "chOlmHyzMfNVwhhnOfizMLqiz" ascii //weight: 1
        $x_1_7 = "nxtSvXVgJXelyGLBfuddwnihiSLb.dll" ascii //weight: 1
        $x_1_8 = "wDSDpeHhJZHHlukYvJFvIbzlFEz.dll" ascii //weight: 1
        $x_1_9 = "QrUrwtPcnxxkwnxalgzJPWVFgTlT.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_PKPH_2147928171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.PKPH!MTB"
        threat_id = "2147928171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 04 02 11 04 91 07 61 06 09 91 61 d2 9c 09 03 6f ?? ?? ?? ?? 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 04 17 58 13 04 11 04 02 8e 69 17 59 32 cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SKJ_2147928836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SKJ!MTB"
        threat_id = "2147928836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0f 00 00 0a 72 01 00 00 70 28 10 00 00 0a 6f 11 00 00 0a 0a 28 0f 00 00 0a 72 33 00 00 70 28 10 00 00 0a 6f 11 00 00 0a 0b 73 12 00 00 0a 25 6f 13 00 00 0a 06 07 6f 14 00 00 0a 7e 01 00 00 04 6f 15 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GSC_2147928974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GSC!MTB"
        threat_id = "2147928974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 11 65 05 00 01 01 12 61 06 00 01 12 69 12 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ZARA_2147929651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ZARA!MTB"
        threat_id = "2147929651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 11 05 8f 1d 00 00 01 25 47 06 11 07 91 61 d2 52 11 05 17 58 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPL_2147929751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPL!MTB"
        threat_id = "2147929751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 66 5f 02 66 03 5f 60 8c 29 00 00 01 0a 2b 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPPA_2147930086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPPA!MTB"
        threat_id = "2147930086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 47 11 00 11 06 91 61 d2 52 20 ?? 00 00 00 7e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPPB_2147930087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPPB!MTB"
        threat_id = "2147930087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tm5McYSCxHrGi4S+xs0dRKxy+8/OKxRNXx1SEPQEI804Dz4Y8PunFang" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DC_2147930287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DC!MTB"
        threat_id = "2147930287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 07 1f 28 5a 58 13 08 28 20 00 00 0a 07 11 08 1e 6f 21 00 00 0a 17 8d 29 00 00 01 6f 22 00 00 0a 13 09 28 20 00 00 0a 11 09 6f 23 00 00 0a 28 24 00 00 0a 72 f2 00 00 70 28 25 00 00 0a 39 41 00 00 00 07 11 08 1f 14 58 28 1f 00 00 0a 13 0a 07 11 08 1f 10 58 28 1f 00 00 0a 13 0b 11 0b 8d 1d 00 00 01 80 05 00 00 04 07 11 0a 6e 7e 05 00 00 04 16 6a 11 0b 6e 28 26 00 00 0a 17 13 06 38 0e 00 00 00 11 07 17 58 13 07 11 07 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AYA_2147930959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AYA!MTB"
        threat_id = "2147930959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$cd7ada21-2b00-4720-b46f-d785c125c466" ascii //weight: 3
        $x_1_2 = "TextForm\\obj\\Debug\\TextForm.pdb" ascii //weight: 1
        $x_1_3 = "The moon is shining brightly outside. Only those who reverse this application are hardcore suckers." wide //weight: 1
        $x_1_4 = "AddToDefenderExclusions" ascii //weight: 1
        $x_1_5 = "IsAdministrator" ascii //weight: 1
        $x_1_6 = "Restarting the program with administrator privileges..." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SPCZ_2147930969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SPCZ!MTB"
        threat_id = "2147930969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 07 06 09 06 08 91 9c 06 08 11 07 9c dd}  //weight: 4, accuracy: High
        $x_1_2 = {5d 13 06 02 11 05 8f 1d 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_AFJA_2147931191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.AFJA!MTB"
        threat_id = "2147931191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 06 09 91 09 1f 25 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69 32 d0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DD_2147931238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DD!MTB"
        threat_id = "2147931238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DF_2147931684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DF!MTB"
        threat_id = "2147931684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Dwasakj.Properties.Resources" ascii //weight: 20
        $x_1_2 = "get_CookieContainer" ascii //weight: 1
        $x_1_3 = "get_Credentials" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "Base64String" ascii //weight: 1
        $x_1_7 = "file:///" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GPPF_2147931802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GPPF!MTB"
        threat_id = "2147931802"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 d2 52 11 30 17 58 13 30 11 30 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DH_2147932560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DH!MTB"
        threat_id = "2147932560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d d2 61 d2 9c 08 09 8f ?? ?? ?? ?? 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69 32 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_GC_2147933309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.GC!MTB"
        threat_id = "2147933309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 f2 00 00 70 28 2a 00 00 0a 0a 06 8e 69 0b 2b 0f 06 07 06 07 93 20 76 00 00 00 61 02 61 d1 9d 07 17 59 25 0b 16 2f e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_PA_2147933416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.PA!MTB"
        threat_id = "2147933416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d d2 61 d2 9c 08 09 8f ?? ?? ?? ?? 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_EAEJ_2147934432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.EAEJ!MTB"
        threat_id = "2147934432"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 05 0b 16 0c 2b 12 03 08 02 03 08 91 08 04 28 60 00 00 06 9c 08 17 d6 0c 08 07 31 ea 03 0a 2b 00 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DL_2147935493_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DL!MTB"
        threat_id = "2147935493"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 30 11 2d 11 2f 91 58 11 2e 11 2f 91 58 20 00 01 00 00 5d 13 30 11 2d 11 30 91 13 32 11 2d 11 30 11 2d 11 2f 91 9c 11 2d 11 2f 11 32 9c 11 2f 17 58 13 2f 11 2f}  //weight: 1, accuracy: High
        $x_1_2 = {11 2e 11 2b 11 2d 91 58 11 2c 11 2d 91 58 20 00 01 00 00 5d 13 2e 11 2b 11 2e 91 13 30 11 2b 11 2e 11 2b 11 2d 91 9c 11 2b 11 2d 11 30 9c 11 2d 17 58 13 2d 11 2d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_LummaStealer_SP_2147936257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SP!MTB"
        threat_id = "2147936257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 07 1f 28 5a 58 13 08 28 1e 00 00 0a 07 11 08 1e 6f 1f 00 00 0a 17 8d 1f 00 00 01 6f 20 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = "Charter.exe" ascii //weight: 2
        $x_2_3 = "$ac049bfa-2dd8-4f1a-9314-11e3fed61454" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_MMR_2147939062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.MMR!MTB"
        threat_id = "2147939062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 07 6f 9b 01 00 0a 00 09 07 6f 9c 01 00 0a 00 09 19 6f 9d 01 00 0a 00 09 6f 9e 01 00 0a 13 07 73 9f 01 00 0a 13 04 11 04 11 07 17 73 a0 01 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SQ_2147939555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SQ!MTB"
        threat_id = "2147939555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 1d 5d 1f 0d d8 13 04 11 04 1f 32 fe 02 13 05 11 05 2c 05 17 0b 00 2b 04 00 16 0b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_SWA_2147940144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.SWA!MTB"
        threat_id = "2147940144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0d 11 17 11 19 28 ?? 01 00 0a 25 13 1c 11 1c 4a 11 0b 11 17 11 1b 28 ?? 01 00 0a 11 0c 11 1b 11 19 28 ?? 01 00 0a d8 d6 54 11 1b 17 d6 13 1b 11 1b 11 1a 31 ca}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_DR_2147940285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.DR!MTB"
        threat_id = "2147940285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 bf 00 00 70 a2 25 17 28 ?? ?? ?? 0a 13 09 12 09 28 ?? ?? ?? 0a a2 25 18 72 c3 00 00 70 a2 25 19 11 07 a2 25 1a 72 db 00 00 70 a2 25 1b 11 08 a2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_LummaStealer_ZUV_2147941599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/LummaStealer.ZUV!MTB"
        threat_id = "2147941599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LummaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 05 11 07 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 12 08 28 ?? 00 00 0a 58 86 12 08 28 ?? 00 00 0a 58 86 6c 23 00 00 00 00 00 00 08 40 5b 28 ?? 00 00 0a b7 13 09 11 09 04 d8 20 ff 00 00 00 5b 13 0a 09 11 05 11 07 11 0a 11 0a 11 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

