rule Trojan_MSIL_Netwire_KZD_2147814763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.KZD!MTB"
        threat_id = "2147814763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQAAMAAAAEAAAA" wide //weight: 1
        $x_1_2 = "cm9ncmFtIGNhbm5" wide //weight: 1
        $x_1_3 = "//8AALgAAAAAAAA" wide //weight: 1
        $x_1_4 = "MDAwMDAwMDAwMDAwI" wide //weight: 1
        $x_2_5 = "GetTypes" ascii //weight: 2
        $x_2_6 = "IDeferred" ascii //weight: 2
        $x_2_7 = "InvokeMember" ascii //weight: 2
        $x_2_8 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_KJX_2147814766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.KJX!MTB"
        threat_id = "2147814766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09 1d 09}  //weight: 1, accuracy: High
        $x_1_2 = {34 00 1d 09 4d 00 1d 09 1d 09 75 00 1d 09 44 00 1d 09}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 1d 09 47 00 30 00 1d 09 5a 00 51 00 1d 09 1d 09 1d 09}  //weight: 1, accuracy: High
        $x_1_4 = {4d 00 51 00 1d 09 30 00 1d 09 1d 09 1d 09 1d 09 4b 00 67 00}  //weight: 1, accuracy: High
        $x_1_5 = {67 00 1d 09 1d 09 1d 09 51 00 42 00 54 00 1d 09 48 00 51 00 1d 09}  //weight: 1, accuracy: High
        $x_2_6 = "GetType" ascii //weight: 2
        $x_2_7 = "Replace" ascii //weight: 2
        $x_2_8 = "IDeferred" ascii //weight: 2
        $x_2_9 = "InvokeMember" ascii //weight: 2
        $x_2_10 = "FromBase64String" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_LJX_2147814767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.LJX!MTB"
        threat_id = "2147814767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 8d 5e 00 00 01 25 16 1f 23 9d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 28 ?? ?? ?? 0a 74 48 00 00 01 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_GLB_2147814769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.GLB!MTB"
        threat_id = "2147814769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GetTypes" ascii //weight: 2
        $x_2_2 = "Replace" ascii //weight: 2
        $x_2_3 = "IDeferred" ascii //weight: 2
        $x_2_4 = "FromBase64String" ascii //weight: 2
        $x_2_5 = "HCVQuestionnaire.frmCESD.resources" ascii //weight: 2
        $x_2_6 = "ToString" ascii //weight: 2
        $x_2_7 = "HCVQuestionnaire" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_SOR_2147815340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.SOR!MTB"
        threat_id = "2147815340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AutoJack" ascii //weight: 1
        $x_1_2 = "IDeferred" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "_Z_________________________________________" ascii //weight: 1
        $x_1_6 = "GetExportedTypes" ascii //weight: 1
        $x_1_7 = "AutoJack.View.EngineView.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_MOR_2147815341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.MOR!MTB"
        threat_id = "2147815341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetType" ascii //weight: 1
        $x_1_2 = "GetExportedTypes" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_7_4 = {17 8d 59 00 00 01 25 16 1f 20 9d 28 ?? ?? ?? 0a 20 00 01 00 00 14 14 17 8d 10 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 74 30 00 00 01 0a 2b 00 06 2a}  //weight: 7, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_ASQ_2147815343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.ASQ!MTB"
        threat_id = "2147815343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 11 04 20 00 38 01 00 5d 07 11 04 20 00 38 01 00 5d 91 08 11 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 07 11 04 17 58 20 00 38 01 00 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d a2}  //weight: 10, accuracy: Low
        $x_1_2 = "IDeferred" ascii //weight: 1
        $x_1_3 = "_Z_________________________________________" ascii //weight: 1
        $x_1_4 = "tfinal" ascii //weight: 1
        $x_1_5 = "ifcX5gLET" wide //weight: 1
        $x_1_6 = "GetMethod" ascii //weight: 1
        $x_1_7 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_TSQ_2147815344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.TSQ!MTB"
        threat_id = "2147815344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kotadiainc.com" ascii //weight: 10
        $x_1_2 = "GetResponseStream" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GetType" ascii //weight: 1
        $x_1_6 = "ReadBytes" ascii //weight: 1
        $x_1_7 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_IRJ_2147818346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.IRJ!MTB"
        threat_id = "2147818346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 d6 12 00 06 0b 07 03 16 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 28 ?? ?? ?? 0a 14 72 9a c8 00 70 72 a6 c8 00 70 72 aa c8 00 70 28 ?? ?? ?? 0a 72 b2 c8 00 70 72 b8 c8 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 18 8d 17 00 00 01 25 17 18 8d 17 00 00 01 25 16 05 a2 25 17 04 a2 a2 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_YZS_2147820394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.YZS!MTB"
        threat_id = "2147820394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 17 da 11 05 da 02 11 05 91}  //weight: 1, accuracy: High
        $x_1_2 = {61 8c 15 00 00 01}  //weight: 1, accuracy: High
        $x_1_3 = {17 8d 03 00 00 01 13 08 11 08 16}  //weight: 1, accuracy: High
        $x_1_4 = {8c 17 00 00 01 a2 11 08 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_AMFA_2147823106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.AMFA!MTB"
        threat_id = "2147823106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 f8 00 00 0c 2b 11 06 08 20 00 01 00 00 28 ?? ?? ?? 06 0a 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_FICC_2147824707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.FICC!MTB"
        threat_id = "2147824707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 0b 8f 10 00 00 01 25 71 10 00 00 01 7e 01 00 00 04 11 0b 1f 10 5d 91 61 d2 81 10 00 00 01 00 11 0b 17 58 13 0b 11 0b 07 8e 69 fe 04 13 0e 11 0e 2d cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_TENW_2147824911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.TENW!MTB"
        threat_id = "2147824911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 ?? ?? ?? 01 6f ?? ?? ?? 0a 1a 9a 80 ?? ?? ?? 04 23 d1 37 b7 3b 43 62 20 40}  //weight: 1, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_BAM_2147825128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.BAM!MTB"
        threat_id = "2147825128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 07 02 8e b7 5d 02 07 02 8e b7 5d 91 08 07 08 8e b7 5d 91 61 02 07 17 58 02 8e b7 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 2f cb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_FCG_2147825956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.FCG!MTB"
        threat_id = "2147825956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e b7 5d 91}  //weight: 1, accuracy: High
        $x_1_2 = {8e b7 5d 91 61 8c ?? ?? ?? 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_XNR_2147825960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.XNR!MTB"
        threat_id = "2147825960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 8f 0a 00 00 01 25 47 03 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_JQK_2147825961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.JQK!MTB"
        threat_id = "2147825961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 7e 18 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = {7e 18 00 00 04 8e b7 5d 91 61 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NTW_2147827638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NTW!MTB"
        threat_id = "2147827638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 16 20 00 10 00 00 6f ?? ?? ?? 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f ?? ?? ?? 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "DeferredDisposable" ascii //weight: 1
        $x_1_5 = "B8D25T" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_SEF_2147827640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.SEF!MTB"
        threat_id = "2147827640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 04 02 11 04 91 03 11 04 03 8e b7 5d 91 61 07 11 04 07 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_CR_2147828107_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.CR!MTB"
        threat_id = "2147828107"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 61 d2 9c 11 05 17 58 16 2d 04 13 05 11 05 06 8e 69 32 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NTA_2147828206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NTA!MTB"
        threat_id = "2147828206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 19 8d 11 00 00 01 25 16 09 a2 25 17 16 8c ?? ?? ?? 01 a2 25 18 11 05 8c ?? ?? ?? 01 a2 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
        $x_1_6 = "CompressionMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_BWFA_2147828290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.BWFA!MTB"
        threat_id = "2147828290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {18 17 8d 11 00 00 01 25 16 02 a2 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "G4G15" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_WYM_2147829490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.WYM!MTB"
        threat_id = "2147829490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 03 11 06 91 07 11 06 07 8e 69 5d 91 61 08 61 d2 6f ?? ?? ?? 0a 00 00 11 06 17 58}  //weight: 1, accuracy: Low
        $x_1_2 = "asfsafsafs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEA_2147829570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEA!MTB"
        threat_id = "2147829570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "QABSjHE8uXUjVoIU+Ci0Cg==" wide //weight: 5
        $x_5_2 = "G6EGqPV5J0c=" wide //weight: 5
        $x_2_3 = "DnsExit_Netw.exe" wide //weight: 2
        $x_2_4 = "ShortPddddddddddddrocess" wide //weight: 2
        $x_1_5 = "ObfuscatedByGoliath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEB_2147829895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEB!MTB"
        threat_id = "2147829895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OOe2EPadKy963M6" ascii //weight: 3
        $x_3_2 = "rtBoocl" ascii //weight: 3
        $x_3_3 = "WhoCalledMe" ascii //weight: 3
        $x_2_4 = "iSfsG9CPnk" ascii //weight: 2
        $x_2_5 = "bPohsREc2PVZJFJ" ascii //weight: 2
        $x_1_6 = "c:\\Tempe.txt" wide //weight: 1
        $x_1_7 = "aELxsuBREvr7KkRcMS2fiRoaY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEC_2147830478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEC!MTB"
        threat_id = "2147830478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 b6 00 00 06 02 03 28 1d 00 00 0a 28 b0 00 00 06 6f 1e 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = "SXdHTGR3T0E0V1hkWXdDSFEzMTlNOEw1R0t0aGpFY3k=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEE_2147832258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEE!MTB"
        threat_id = "2147832258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 a8 00 00 0a 28 aa 00 00 0a 28 ab 00 00 0a 0b 07 28 9b 00 00 06 28 2e 00 00 0a 0c 72 f1 00 04 70 28 ac 00 00 0a 6f ad 00 00 0a}  //weight: 5, accuracy: High
        $x_2_2 = "Load" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEF_2147832263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEF!MTB"
        threat_id = "2147832263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$02bedfb9-c173-423a-b0a4-def5668bbd4d" ascii //weight: 5
        $x_5_2 = "Summary.txt" wide //weight: 5
        $x_5_3 = "Summary.htm" wide //weight: 5
        $x_5_4 = "fuzzyHash" ascii //weight: 5
        $x_5_5 = "LENGTHS_AND_KINDS" ascii //weight: 5
        $x_5_6 = "COMPUTER_NAME_PROPERTY" ascii //weight: 5
        $x_5_7 = "Minneapolis" wide //weight: 5
        $x_3_8 = "CommandReader" ascii //weight: 3
        $x_3_9 = "ConsoleClient" ascii //weight: 3
        $x_3_10 = "Imagem" wide //weight: 3
        $x_3_11 = "BreakDebugger" ascii //weight: 3
        $x_1_12 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_13 = "StartupPath" ascii //weight: 1
        $x_1_14 = "WaitBag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_AN_2147832526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.AN!MTB"
        threat_id = "2147832526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 09 11 0a 6f ?? 00 00 0a 13 0b 2b 19 11 0a 11 09 6f ?? 00 00 0a 0d 08 09 28 ?? 00 00 0a d6 0c 11 09 17 d6 13 09 11 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_AN_2147832526_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.AN!MTB"
        threat_id = "2147832526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {70 18 8d 17 00 00 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 14 14 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Actions2EventsMapping" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_AGX_2147834666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.AGX!MTB"
        threat_id = "2147834666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0d 2b 36 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "intel22" wide //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "DnsRip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_AIFT_2147835047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.AIFT!MTB"
        threat_id = "2147835047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 49 00 16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "GetPixel" wide //weight: 1
        $x_1_3 = "CargoWise.White" wide //weight: 1
        $x_1_4 = "IntelReaderLibrary" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_EXTF_2147837443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.EXTF!MTB"
        threat_id = "2147837443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 07 09 6f d1 00 00 0a 00 07 18 6f d2 00 00 0a 00 07 6f d3 00 00 0a 03 16 03 8e 69}  //weight: 2, accuracy: High
        $x_1_2 = "ZEroKaRun" wide //weight: 1
        $x_1_3 = "IiamsLaaO" wide //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEAA_2147840466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEAA!MTB"
        threat_id = "2147840466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {26 26 26 2b 36 2b 37 dd 5b 00 00 00 0b 15 2c f3 2b e4 28 2f 00 00 0a 2b ea 28 30 00 00 0a 2b c7 28 0e 00 00 06 2b c7 6f 31 00 00 0a 2b c2 28 32 00 00 0a 2b bd 07 2b c0}  //weight: 10, accuracy: High
        $x_1_2 = "SmartAssembly.Attributes" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEAB_2147840467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEAB!MTB"
        threat_id = "2147840467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 0f 00 00 0a 6f 10 00 00 0a 28 14 00 00 0a 73 15 00 00 0a 6f 16 00 00 0a 11 09 0c 08 6f 17 00 00 0a 17 6f 18 00 00 0a 08}  //weight: 10, accuracy: High
        $x_5_2 = "L0Mgc2NodGFza3MgL2NyZWF0ZSAvdG4gXGtaR0dIIC90ciAi" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_NEAC_2147840979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.NEAC!MTB"
        threat_id = "2147840979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 16 13 04 2b 1f 09 11 04 18 5b 07 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 16 2d 06 11 04 18 58 13 04 16 2d ba 11 04 08 32 d9}  //weight: 10, accuracy: Low
        $x_5_2 = "SmartAssembly.Attributes" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_IFA_2147896144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.IFA!MTB"
        threat_id = "2147896144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Korando" wide //weight: 1
        $x_1_2 = "IDeferred" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "_Z_________________________________________" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "ToInt32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Netwire_CH_2147941361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Netwire.CH!MTB"
        threat_id = "2147941361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 5f 6d 0b 11 04 06 95 13 06 11 04 06 11 04 07 95 9e 11 04 07 11 06 9e 09 11 07 02 11 07 91 11 04 11 04 06 95 11 04 07 95 58 6e 20 ?? ?? ?? ?? 6a 5f 69 95 61 d2 9c 00 11 07 17 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

