rule Trojan_MSIL_Heracles_DY_2147793171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.DY!MTB"
        threat_id = "2147793171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "afsggsdfsdfsdfsdfd" ascii //weight: 1
        $x_1_2 = "bvsdvdssd" ascii //weight: 1
        $x_1_3 = "hfghggfgd" wide //weight: 1
        $x_1_4 = "_ICON_1915" wide //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
        $x_1_6 = "_ENABLE_PROFILING" wide //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_RS_2147833674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.RS!MTB"
        threat_id = "2147833674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 28 02 00 00 06 0c 28 27 00 00 0a 06 6f 28 00 00 0a 0d 73 29 00 00 0a 13 04 16 13 05 2b 1d}  //weight: 5, accuracy: High
        $x_5_2 = {11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f 2a 00 00 0a 11 05 17 58 13 05 11 05 08 8e 69 32 dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_RS_2147833674_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.RS!MTB"
        threat_id = "2147833674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Metal.dll" ascii //weight: 1
        $x_1_2 = "Pesticide Applicator" ascii //weight: 1
        $x_1_3 = "{11111-22222-10009-11112}" ascii //weight: 1
        $x_1_4 = "System.Reflection" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_6 = "GetDelegateForFunctionPointer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AIA_2147837452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AIA!MTB"
        threat_id = "2147837452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 07 14 28 ?? ?? ?? 0a 2c 26 07 d0 39 00 00 02 28}  //weight: 2, accuracy: Low
        $x_1_2 = "SELECT PROCESSID FROM WIN32_PROCESS WHERE PARENTPROCESSID = {0}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBB_2147837796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBB!MTB"
        threat_id = "2147837796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gzncWTUIBcvI3vgDaKitPPU/eU63BQT5" wide //weight: 1
        $x_1_2 = "wF89082Ryy+DC9Hy5OVjyF32tinkM/M" wide //weight: 1
        $x_1_3 = "4Y5yMVeupyx7nq7yIfTFGN7jjnz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GCD_2147838030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GCD!MTB"
        threat_id = "2147838030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "mluZyA9ICRTUUxQYXJhbXMNC" wide //weight: 1
        $x_1_3 = "GFzdFdyaXRlVGltZ" wide //weight: 1
        $x_1_4 = "blN0cmluZyA9IC" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GCE_2147838181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GCE!MTB"
        threat_id = "2147838181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HWUFPUUF5QUdFQUlBQXRB" wide //weight: 1
        $x_1_2 = "VQU9RQXRBRFlBWmdBd0FHSUFOUUF" wide //weight: 1
        $x_1_3 = "PowerShell" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ReadKey_Box" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AGEA_2147838184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AGEA!MTB"
        threat_id = "2147838184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 58 47 52 00 11 05 17 58 13 05 11 05 28 ?? ?? ?? 06 8e 69 fe 04 13 06 11 06 2d d4 00 14 13 04 07 28 ?? ?? ?? 06 8e 69 6a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBX_2147838302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBX!MTB"
        threat_id = "2147838302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateDecryptor" ascii //weight: 1
        $x_2_2 = {53 00 65 00 6e 00 69 00 6f 00 72 00 00 11 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 00 0f 4c 00 20 00 6f 00 20 00 61 00 20 00 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBX_2147838302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBX!MTB"
        threat_id = "2147838302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 04 1c d6 5d 8c ?? 00 00 01 02 28 ?? 00 00 06 14 04 1c ?? ?? ?? ?? ?? 28 ?? 00 00 06 17 8d ?? 00 00 01 25 16 03 8c ?? 00 00 01 a2 25 0b 14 14 17 8d ?? 00 00 01 25 16 17 9c 25 0c}  //weight: 5, accuracy: Low
        $x_5_2 = "y0JYs9d1D2LbQg73Hqe6KAk58Rna4S5M" ascii //weight: 5
        $x_1_3 = "k9.Resources.resources" ascii //weight: 1
        $x_1_4 = "Data Encoder Crypter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBAF_2147838489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBAF!MTB"
        threat_id = "2147838489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 11 05 6f ?? 00 00 0a 13 07 16 16 16 16 28 ?? 00 00 0a 13 08 11 07 11 08 28 ?? 00 00 0a 13 09 11 09 2c 2c 07 19 8d ?? 00 00 01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 00 11 05 17 d6 13 05 11 05 11 06 31 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 03 11 00 11 02 11 00 8e 69 5d 91 7e ?? ?? ?? 04 11 02 91 61 d2 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 18 5b 08 06 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 9c 06 18 58 0a 06 09 32 e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 1a fe 01 2c 08 72 bf 11 00 70 0a 1b 0c 00 08 1c fe 01 2c 06 07 17 d6 0b 1d 0c 00 08 1b fe 01 2c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 8e 2d 0a 12 01 fe 15 02 00 00 1b 07 2a 7e ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 0a 03 16 06 03 8e 69 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 5b 0b 16 0d 2b 27 72 01 00 00 70 02 09 18 5a 18 6f 09 00 00 0a 28 0a 00 00 0a 1f 10 28 0b 00 00 0a 13 04 06 09 11 04 d2 9c 09 17 58 0d 09 07 32 d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AH_2147839028_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AH!MTB"
        threat_id = "2147839028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 13 0d 2b 14 08 11 0d 8f ?? ?? ?? 01 25 47 1e 61 d2 52 11 0d 17 58 13 0d 11 0d 08 8e 69 32 e5}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GDI_2147839259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GDI!MTB"
        threat_id = "2147839259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ql4wsYGamInVni" ascii //weight: 1
        $x_1_2 = "dmasAsystemQrtlsupportsl1w1E0" ascii //weight: 1
        $x_1_3 = "BthSQasksWv3_153" ascii //weight: 1
        $x_1_4 = "GetCurrentDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NEAA_2147839266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NEAA!MTB"
        threat_id = "2147839266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 1b 00 00 0a 6f 1c 00 00 0a 7e 05 00 00 04 25 2d 17 26 7e 04 00 00 04 fe 06 0f 00 00 06 73 1d 00 00 0a 25 80 05 00 00 04 28 01 00 00 2b 0a 06 14 28 1f 00 00 0a 2c 09 06 14 14 6f 20 00 00 0a 26 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 06 08 06 93 02 7b ?? 01 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0c 11 04 08 59 0d 02 7b 61 00 00 04 09 0e 04 0e 05 08 28 bb 00 00 0a 08 2a}  //weight: 3, accuracy: High
        $x_1_2 = "JHONNET SUPREME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 03 0c 2b f5 2a 06 6f ?? ?? 00 06 28 ?? ?? 00 0a 28 ?? ?? 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Njrgaoshxxooiksrgxt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lCkrJruYWGsIEJMFWxRcm" ascii //weight: 2
        $x_2_2 = "FNDOJbtsXqeTXnxt" ascii //weight: 2
        $x_2_3 = "Test.Properties.Resource1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {2b 1f 09 11 07 9a 08 28 24 00 00 0a 2c 0d 09 11 07 17 58 9a 13 04 16}  //weight: 7, accuracy: High
        $x_1_2 = "aspnet_wp.exe" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 d2 00 00 06 6f 89 01 00 0a 0d 28 cd 00 00 06 13 04 11 04 39 30 00 00 00 11 04 6f 15 00 00 0a 16 3e 23 00 00 00 11 04 20 40 0f 00 00 28 6d 00 00 06}  //weight: 2, accuracy: High
        $x_3_2 = {28 7a 01 00 0a 11 04 6f 89 01 00 0a 0d 04 8e 69 28 c6 01 00 0a 13 05 1f 0e 09 8e 69 58 04 8e 69 58 8d a9 00 00 01 13 06 11 06 16 16 9c 07 16 11 06 17 1e 28 60 01 00 0a 11 06 1f 09 09 8e}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {28 14 00 00 0a 13 09 11 09 6f 0b 00 00 0a 25 2d 0c 26 72 01 00 00 70 73 15 00 00 0a 7a 13 0a 11 0a 6f 16 00 00 0a 8e 69 8d 01 00 00 01 13 0b 11 0b 8e 16 fe 03 13 11 11 11 2c 05 11 0b 16 02 a2 11 0a 14 11 0b 6f 17 00 00 0a}  //weight: 3, accuracy: High
        $x_1_2 = "EntryPoint not found!!!!!!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 0f 04 00 06 06 20 ?? ?? ?? 35 60 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 4e 06 44 ?? ?? ?? ff 02 20 ?? ?? ?? 3b 06 60 ?? ?? ?? 00 00 04 06 20 ?? ?? ?? 3f 61 20 ?? ?? ?? 4d 06 5f 0a 02 fe ?? ?? ?? ?? 06 06 20 ?? ?? ?? 00 62 0a 73 ?? ?? ?? 06 20 ?? ?? ?? 18 06 60 0a 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 06 20 ?? ?? ?? 18 61 20 ?? ?? ?? 3e 06 5e 0a 02 20 ?? ?? ?? 45 06 20 ?? ?? ?? 00 5f 62 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "GHL.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NH_2147840063_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NH!MTB"
        threat_id = "2147840063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 04 11 07 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 13 08 12 08 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 0a 13 06 11 07 17 58 13 07 11 07 04 6f ?? ?? 00 0a fe 04 13 09 11 09 2d c4}  //weight: 5, accuracy: Low
        $x_5_2 = {28 aa 01 00 0a 0a 06 18 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 72 ?? ?? ?? 70 a2 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 18 6f ?? ?? ?? 0a 00 06 6f ?? ?? ?? 0a 0b}  //weight: 5, accuracy: Low
        $x_1_3 = "vSS14lpWNkDCYL3eEFOGwE=" wide //weight: 1
        $x_1_4 = "L6j0GMIxO6CSXLHsf070b" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SP_2147840220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SP!MTB"
        threat_id = "2147840220"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 08 11 04 08 8e 69 5d 91 07 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 07 8e 69 32 df}  //weight: 5, accuracy: Low
        $x_1_2 = "Snkfaebcnjaopjnjwwj.Ioaxdkllxorsivcr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAA_2147840312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAA!MTB"
        threat_id = "2147840312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {06 02 07 6f 92 00 00 0a 03 07 6f 92 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 1c 00 00 0a 32 e1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAA_2147840312_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAA!MTB"
        threat_id = "2147840312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 c1 00 00 70 28 ?? 00 00 0a 72 ed 00 00 70 28 ?? 00 00 0a 26 20 f4 01 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_2_2 = "vbpanel.com/panel/download/VertigoBoostPanel.zip" wide //weight: 2
        $x_1_3 = "VertigoBoostPanel.exe.config" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAB_2147840313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAB!MTB"
        threat_id = "2147840313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {24 40 32 d5 2a 06 2a 13 30 03 00 44 00 00 00 03 00 00 11 73 40 00 00 0a 0a 28 08 00 00 06 0b 07 16 07 8e 69 28 41 00 00 0a 07 28}  //weight: 2, accuracy: High
        $x_2_2 = {9a 13 04 06 11 04 6f 44 00 00 0a 09 17 58 0d 09 08 8e 69 32 e9 06 6f 45 00 00 0a 2a 7a 03 2c 13 02 7b 06}  //weight: 2, accuracy: High
        $x_2_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 [0-4] 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 2, accuracy: Low
        $x_1_4 = "GetTypes" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NBH_2147840344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NBH!MTB"
        threat_id = "2147840344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {12 02 fe 16 13 00 00 02 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 28 ?? ?? ?? 06 73 ?? ?? ?? 0a 7a 11 01 1a 9a a5 ?? ?? ?? 01 13 00 38 ?? ?? ?? ff 11 07 1f 13 58}  //weight: 5, accuracy: Low
        $x_1_2 = "Uydwtmtyckybjwckyo" ascii //weight: 1
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_DAK_2147841522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.DAK!MTB"
        threat_id = "2147841522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 1a 58 16 54 2b 2a 09 08 06 1a 58 4a 08 8e 69 5d 91 07 06 1a 58 4a 91 61 d2 6f ?? 00 00 0a 06 1e 58 06 1a 58 4a 54 06 1a 58 06 1e 58 4a 17 58 54 06 1a 58 4a 07 8e 69 32 cd}  //weight: 4, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_DAM_2147841594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.DAM!MTB"
        threat_id = "2147841594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 06 11 04 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 11 04 06 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 06 17 6f ?? 00 00 0a 08 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 09 16 09 8e 69 6f ?? 00 00 0a de 08}  //weight: 4, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHC_2147842032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHC!MTB"
        threat_id = "2147842032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 05 00 00 06 18 28 ?? 00 00 2b 7e ?? 00 00 04 20 ?? 00 00 00 97 29 ?? 00 00 11 13 03}  //weight: 5, accuracy: Low
        $x_1_2 = "A88ual" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBAR_2147842051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBAR!MTB"
        threat_id = "2147842051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 02 6f ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d 07 6f ?? 00 00 0a 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "payload.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHC_2147842157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHC!MTB"
        threat_id = "2147842157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2d 18 08 09 18 5b 06 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 09 18 58 0d 09 07 32 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHC_2147842157_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHC!MTB"
        threat_id = "2147842157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 00 09 08 16 73 ?? ?? ?? 0a 13 04 00 73 ?? ?? ?? 0a 13 05 00 11 04 11 05 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 0a 00 de 14 11 05 14 fe 01 13 07 11 07 2d 08 11 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHC_2147842157_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHC!MTB"
        threat_id = "2147842157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 2b 61 09 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 72 27 00 00 70 16 28 ?? ?? ?? 0a 2c 40 72 33 00 00 70 13 05 12 04 28 ?? ?? ?? 0a 11 05 16 28 ?? ?? ?? 0a 16 31 27 02 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 12 04 28 ?? ?? ?? 0a 11 05 72 a9 00 00 70 17 15 16 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Discord: Diartios#5850" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MA_2147842326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MA!MTB"
        threat_id = "2147842326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 07 6f 1b 00 00 0a 07 6f 1c 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0d de 1e 08 2c 06 08 6f 1f 00 00 0a dc}  //weight: 5, accuracy: High
        $x_2_2 = "lld.bsisjnenxcnnxJ" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAL_2147842893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAL!MTB"
        threat_id = "2147842893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 08 07 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0d 06 8e 69 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 06 26 7e ?? 00 00 04 6f ?? 00 00 06 de 14}  //weight: 3, accuracy: Low
        $x_1_2 = "_007Stub.Properties.Resources" wide //weight: 1
        $x_1_3 = "194.190.153.137/encrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABOJ_2147842973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABOJ!MTB"
        threat_id = "2147842973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {0a 0b 16 0c 07 8e 69 17 59 0d 38 ?? ?? ?? 00 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4 40 00 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28}  //weight: 6, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GFM_2147842999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GFM!MTB"
        threat_id = "2147842999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "binGBridge8usb1" ascii //weight: 1
        $x_1_2 = "ESZOjkInatt" ascii //weight: 1
        $x_1_3 = "suarrdo6da7Vder" ascii //weight: 1
        $x_1_4 = "vss8rensxon" ascii //weight: 1
        $x_1_5 = "OIRmORuntcfg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBCI_2147843071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBCI!MTB"
        threat_id = "2147843071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 00 57 00 66 00 71 00 43 00 38 00 73 00 38 00 55 00 4b 00 56 00 37 00 53 00 73 00 35 00 65 00 2f 00 48 00 56 00 6d 00 49 00 6f 00 35 00 64 00 7a 00 6f 00 72 00 62 00 49 00 44 00 42 00 42 00 62 00 66 00 36 00 6f 00 65 00 4b 00 45 00 50 00 4d 00 65 00 33 00 48 00 44 00 44 00 37 00 41 00 50 00 5a 00 4d 00 76 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHL_2147843409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHL!MTB"
        threat_id = "2147843409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 53 10 00 70 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 17 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_3 = "EnderIce2" wide //weight: 1
        $x_1_4 = "computar.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSJG_2147843736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSJG!MTB"
        threat_id = "2147843736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 6f b2 00 00 0a 0a 02 73 b3 00 00 0a 0b 07 06 16 73 b4 00 00 0a 0c 00 02 8e 69 8d 71 00 00 01 0d 08 09 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAE_2147843766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAE!MTB"
        threat_id = "2147843766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {1c 2d 1c 26 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 17 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de d2}  //weight: 3, accuracy: Low
        $x_2_2 = "WindowsFormsApp95.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAS_2147843925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAS!MTB"
        threat_id = "2147843925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 13 00 38 00 00 00 00 28 ?? 00 00 0a 11 00 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 13 01 38 00 00 00 00 dd ?? 00 00 00 26 38 00 00 00 00 dd}  //weight: 3, accuracy: Low
        $x_2_2 = "Castle.DynamicProxy.DynProxy" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAD_2147843927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAD!MTB"
        threat_id = "2147843927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 2b 41 00 00 7e 19 00 00 04 0c 28 ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 73 76 00 00 06 25 09 28 ?? 00 00 06 6f ?? 00 00 06 00 0b de 10 25 28 ?? 00 00 0a 13 04 00 28 ?? 00 00 0a de 00 00 2b 05 17 13 05 2b ba}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSIA_2147843934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSIA!MTB"
        threat_id = "2147843934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 01 28 0b 00 00 06 11 02 6f ?? ?? ?? 0a 20 03 00 00 00 7e 22 00 00 04 7b 29 00 00 04 3a ?? ?? ?? ff 26 20 02 00 00 00 38 ?? ?? ?? ff 11 04 28 0a 00 00 06 13 01 20 00 00 00 00 7e 22 00 00 04 7b 4e 00 00 04 39 ?? ?? ?? ff 26 20 00 00 00 00 38 ?? ?? ?? ff 02 28 05 00 00 0a 74 0b 00 00 01 13 04 38 ?? ?? ?? ff 73 06 00 00 0a 13 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSIF_2147843936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSIF!MTB"
        threat_id = "2147843936"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 0a 00 00 06 0c 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 73 ?? ?? ?? 0a 13 04 16 13 05 2b 1d 11 04 11 05 09 11 05 09 8e 69 5d 91 08 11 05 91 61 d2 6f ?? ?? ?? 0a 11 05 17 58 13 05 11 05 08 8e 69 32 dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSIG_2147843937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSIG!MTB"
        threat_id = "2147843937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 6b 00 00 70 13 07 20 00 00 00 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? ff 26 20 01 00 00 00 38 ?? ?? ?? ff 11 05 11 01 8e 69 3f ?? ?? ?? ff 20 05 00 00 00 38 ?? ?? ?? ff 11 04 13 09 20 02 00 00 00 38 ?? ?? ?? ff 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 03 38 6d ?? ?? ?? dd 76 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHL_2147843943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHL!MTB"
        threat_id = "2147843943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 4e 00 00 01 28 ?? ?? ?? 06 74 01 00 00 1b 28 ?? ?? ?? 06 17 2d 03 26 de 06 0a 2b fb 26 de d0 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHL_2147843943_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHL!MTB"
        threat_id = "2147843943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 8b 00 00 70 28 ?? ?? ?? 06 1b 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06}  //weight: 1, accuracy: Low
        $x_1_2 = {02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHL_2147843943_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHL!MTB"
        threat_id = "2147843943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 09 2b 33 11 08 11 09 9a 13 0a 11 0a 73 ?? 01 00 0a 13 0b 00 11 0b 6f ?? 01 00 0a 00 de 10 25 28 ?? 00 00 0a 13 0c 00 28 ?? 00 00 0a de 00 00 00 11 09 17 d6 13 09 11 09 11 08 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "CheckXSEO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHL_2147843943_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHL!MTB"
        threat_id = "2147843943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NorthAmericaUpdate.Properties.Resources" ascii //weight: 1
        $x_1_2 = "bc38f5e3-3a51-43c5-897a-178228d7f420" ascii //weight: 1
        $x_1_3 = "NorthAmericaUpdate.exe" wide //weight: 1
        $x_1_4 = "Update from Java" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSKJ_2147844905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSKJ!MTB"
        threat_id = "2147844905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 8b 00 00 70 28 4a 00 00 06 1d 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 49 00 00 06 1c 2d 06 26 de 09 0a 2b e2 0b 2b f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSKA_2147844988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSKA!MTB"
        threat_id = "2147844988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7e b5 00 00 0a 28 1a 00 00 0a 2c 06 7e ?? ?? ?? 0a 2a 02 28 ?? ?? ?? 0a 0a 28 ?? ?? ?? 0a 06 16 06 8e 69 6f b8 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABMX_2147845134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABMX!MTB"
        threat_id = "2147845134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 7e ?? ?? ?? 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 02 08 1d 58 1c 59 02 8e 69 5d 91 59 20 ?? ?? ?? 00 58 19 58 20 ?? ?? ?? 00 5d d2 9c 08 17 58 16 2c 3f 26 08 6a 02 8e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NSH_2147845665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NSH!MTB"
        threat_id = "2147845665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 07 6f 1b 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0d de 1e}  //weight: 5, accuracy: Low
        $x_1_2 = "Lkamparqc" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp1.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHJ_2147845772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHJ!MTB"
        threat_id = "2147845772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1a 00 00 0a 0b 06 07 6f ?? 00 00 0a 0c 02 8e 69 8d ?? 00 00 01 0d 08 02 16 02 8e 69 09 16 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Web_Browser.Form2.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABQR_2147845884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABQR!MTB"
        threat_id = "2147845884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 7e ?? 00 00 04 02 07 6f ?? 00 00 06 0c 2b 00 08 2a 3f 00 28 ?? 00 00 0a 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAH_2147846021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAH!MTB"
        threat_id = "2147846021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 08 13 07 16 13 08 2b 20 11 07 11 08 91 13 09 09 72 33 00 00 70 11 09 8c 19 00 00 01 6f ?? ?? ?? 0a 26 11 08 17 58 13 08 11 08 11 07 8e 69 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSMA_2147846181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSMA!MTB"
        threat_id = "2147846181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0e 00 00 06 0a 28 20 00 00 0a 06 6f 21 00 00 0a 28 0f 00 00 06 75 06 00 00 1b 28 10 00 00 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHE_2147846190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHE!MTB"
        threat_id = "2147846190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 11 07 19 5a 58 47 09 16 94 04 59 fe 04 16 fe 01 11 06 11 07 19 5a 58 47 09 16 94 04 58}  //weight: 5, accuracy: High
        $x_1_2 = "ZahuraCH.Utils.WinStructs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHE_2147846190_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHE!MTB"
        threat_id = "2147846190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 00 00 00 00 00 11 04 11 0c 28 ?? 00 00 06 20 ?? 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? 00 00 00 26 20 ?? 00 00 00 38 ?? 00 00 00 fe ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Oixlyxlb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHE_2147846190_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHE!MTB"
        threat_id = "2147846190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b fa 02 06 74 ?? 00 00 1b 18 9a 06 74 ?? 00 00 1b 1a 9a 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Qe.Resources.resources" ascii //weight: 1
        $x_1_3 = "SpecialDirectoriesProxy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAF_2147846218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAF!MTB"
        threat_id = "2147846218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 26 16 0d 2b 21 0a 2b e3 0b 2b ea 0c 2b f3 08 09 18 5b 06 09 18 6f ?? 01 00 0a 1f 10 28 ?? 01 00 0a 9c 09 18 58 0d 09 07 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHA_2147846325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHA!MTB"
        threat_id = "2147846325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 2b f5 07 08 18 5b 02 08 18 6f 39 00 00 0a 1f 10 28 8d 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABRW_2147846494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABRW!MTB"
        threat_id = "2147846494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 05 1a 8d ?? 00 00 01 25 16 11 04 a2 25 17 7e ?? 00 00 0a a2 25 18 07 a2 25 19 17 8c ?? 00 00 01 a2 13 06 11 05 08 6f ?? 00 00 0a 09 20 00 01 00 00 14 14 11 06}  //weight: 4, accuracy: Low
        $x_1_2 = "JHh66363.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHS_2147846588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHS!MTB"
        threat_id = "2147846588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 0e 00 00 0a 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 11 04 16 11 04 8e 69 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Ranchrose22" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHS_2147846588_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHS!MTB"
        threat_id = "2147846588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 bf 09 00 70 0a 73 ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 16 6f ?? ?? ?? 0a 25 6f ?? ?? ?? 0a 26 25 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "WotucSoftWare.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_CSSI_2147846728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.CSSI!MTB"
        threat_id = "2147846728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 75 81 00 00 01 11 05 11 0a 75 ?? ?? ?? ?? 11 0c 11 07 58 11 09 59 93 61 11 0b 75 ?? ?? ?? ?? 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f}  //weight: 5, accuracy: Low
        $x_1_2 = "d8435112e1243f.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_FAX_2147846781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.FAX!MTB"
        threat_id = "2147846781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 2b b1 08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 20 [0-4] 2b 97 09 07 8e 69 2f 08}  //weight: 2, accuracy: Low
        $x_2_2 = {25 26 2b 80 11 04 20 [0-4] 5a 20 [0-4] 61 38 ?? ff ff ff 07 8e 69 8d ?? 01 00 01 0c 16 0d 11 04 20 [0-4] 5a 20 [0-4] 61 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_FAY_2147846782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.FAY!MTB"
        threat_id = "2147846782"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABVS_2147846794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABVS!MTB"
        threat_id = "2147846794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lpProceskcabllaCnoitadilaVtreCetomeRytiruceSteNmetsyS81617" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "HttpUtility" ascii //weight: 1
        $x_1_4 = "HttpServerUtility" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_6 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 1
        $x_1_7 = "Sprauncy.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_CPV_2147846986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.CPV!MTB"
        threat_id = "2147846986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BrPaAMtlscyMXN39" ascii //weight: 1
        $x_1_2 = "MFBlam5Spekvr" ascii //weight: 1
        $x_1_3 = "SystelxRuntife_Serialinatirctl" ascii //weight: 1
        $x_1_4 = "artdotsiSTJUDT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBDD_2147847144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBDD!MTB"
        threat_id = "2147847144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 ff a3 ff 09 1e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 46 01 00 00 80 00 00 00 3a 01 00 00 ed 0b 00 00 42 0e 00 00 01 00 00 00 3c 05 00 00 11 00 00 00 63 07 00 00 2f 00 00 00 02 00 00 00 08 00 00 00 11 00 00 00 fb 00 00 00 09 00 00 00 2c 00 00 00 55 00 00 00 30 00 00 00 01 00 00 00 ae}  //weight: 5, accuracy: High
        $x_5_2 = {50 73 20 35 20 47 61 6d 65 00 00 0e 01 00 09 4d 61 72 76 65 6c 20 6d 64 00 00 11 01 00 0c 4d 61 72 76 65 6c 20 43 6f 72 70 2e 00 00 0e 01 00 09 35 2e 31 34 2e 32 32 2e 31 00 00 47 01 00 1a 2e 4e}  //weight: 5, accuracy: High
        $x_1_3 = {09 06 08 09 1a 09 59 6f}  //weight: 1, accuracy: High
        $x_1_4 = {1d 95 08 1d 95 61 9e}  //weight: 1, accuracy: High
        $x_1_5 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 1
        $x_1_6 = "SkipVerification" ascii //weight: 1
        $x_1_7 = {00 44 65 63 72 79 70 74 00 45 6e 63 72 79 70 74 00 50 61 72 61 6d 65 74 65 72 69 7a 65 64 54 68 72 65 61 64 53 74 61 72 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSOI_2147847460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSOI!MTB"
        threat_id = "2147847460"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 28 1d 00 00 0a 0a 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 01 00 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 00 08 18 6f ?? ?? ?? 0a 00 08 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MKV_2147847555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MKV!MTB"
        threat_id = "2147847555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 24 73 a0 00 00 0a 13 06 2b 13 28 a2 00 00 0a 11 12 16 11 12 8e 69 6f a3 00 00 0a 13 06 11 0b 20 63 62 35 fb 06 59 07 61 11 0b 19 5f 58 1b 62 58 13 0b 11 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAK_2147847715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAK!MTB"
        threat_id = "2147847715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 14 2b 19 74 ?? 00 00 01 2b 19 74 ?? 00 00 1b 2b 19 2b 1e de 22 28 ?? 03 00 06 2b e5 28 ?? 03 00 06 2b e0 28 ?? 02 00 06 2b e0 28 ?? 03 00 06 2b e0 0a 2b df 26 de bf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPCS_2147847824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPCS!MTB"
        threat_id = "2147847824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 07 07 11 07 91 18 59 20 ?? ?? ?? 00 5f d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e2}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MAAK_2147848151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MAAK!MTB"
        threat_id = "2147848151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dyn%%am%%icInv%%oke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABYH_2147848240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABYH!MTB"
        threat_id = "2147848240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0d d0 ?? 00 00 01 28 ?? 00 00 0a 09 72 ?? 00 00 70 28 ?? 00 00 0a 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 de 1e 08 2c 06 08 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSPI_2147848353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSPI!MTB"
        threat_id = "2147848353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? ?? ?? 06 13 03 20 00 00 00 00 7e 73 00 00 04 7b 3a 00 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 02 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 28 ?? ?? ?? 06 11 03 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 0d 00 00 06 13 01 38 00 00 00 00 dd 9d ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$cc7fad03-816e-432c-9b92-001f2d358388" ascii //weight: 2
        $x_2_2 = "server1.exe" ascii //weight: 2
        $x_2_3 = ".resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 8e 69 5d 7e ?? ?? ?? 04 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 06 03 08 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 07 91 7e ?? ?? ?? ?? 07 1e 5d 1f 1f 5f 63 d2 61 d2 0c 08 19 63 08 1b 62 60 d2 0c 08 7e ?? ?? ?? ?? 20 00 01 00 00 28 ?? ?? ?? 06 5a 20 00 01 00 00 5d d2 0c 06 07 08 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d b7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 0a 74 ?? ?? ?? 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 ?? ?? ?? 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? ?? ?? 0a 26 11 0f 1f 60 91 20 c6 00 00 00 59 13 0e 38}  //weight: 2, accuracy: Low
        $x_2_2 = {13 04 11 0a 74 ?? ?? ?? 1b 11 0c 93 13 05 11 0a 74 ?? ?? ?? 1b 11 0c 17 58 93 11 05 61 13 06 1e 13 0e 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 09 08 11 04 6f ?? ?? ?? 0a 11 04 1f 0a 5d 59 d1 6f ?? ?? ?? 0a 26 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a fe 04 13 05 11 05 2d d2}  //weight: 2, accuracy: Low
        $x_2_2 = {00 06 02 08 6f ?? ?? ?? 0a 03 08 07 5d 6f ?? ?? ?? 0a 61 d1 6f ?? ?? ?? 0a 26 00 08 17 58 0c 08 02 6f ?? ?? ?? 0a fe 04 0d 09 2d d4}  //weight: 2, accuracy: Low
        $x_1_3 = "DownloadFileAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARA_2147848464_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARA!MTB"
        threat_id = "2147848464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "L0MgcGluZyAxLjEuMS4xIC1uIDIgLXcgMjAwMCA+IE51bCAmIERlbCA=" wide //weight: 2
        $x_2_2 = ":Zone.Identifier" wide //weight: 2
        $x_2_3 = "DownloadString" ascii //weight: 2
        $x_2_4 = "CreateDecryptor" ascii //weight: 2
        $x_2_5 = "AesManaged" ascii //weight: 2
        $x_2_6 = ".resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ABZC_2147848475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ABZC!MTB"
        threat_id = "2147848475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 28 06 09 5d 13 08 06 09 5b 13 09 08 11 08 11 09 6f ?? 00 00 0a 13 0c 11 04 12 0c 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 09 11 05 5a fe 04 13 0a 11 0a 2d cb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHN_2147848980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHN!MTB"
        threat_id = "2147848980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 03 00 00 0a 2b 05 72 ?? ?? 00 70 26 2b 05 72 ?? ?? 00 70 20 ?? ?? 00 00 2b 05 72 ?? ?? 00 70 fe ?? ?? 00 2b 05 72 ?? ?? 00 70 00 2b 05}  //weight: 5, accuracy: Low
        $x_1_2 = "nJB0an" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_CXCF_2147849039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.CXCF!MTB"
        threat_id = "2147849039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CUluZGV4IA==" ascii //weight: 1
        $x_1_2 = "OiA=8RWxlbWVudHMgb2YgQml" ascii //weight: 1
        $x_1_3 = "0QXJyYXkgIGFmdGVyIH" ascii //weight: 1
        $x_1_4 = "NldHRpbmcgZmFsc2U6" ascii //weight: 1
        $x_1_5 = "SmartAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSPT_2147849359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSPT!MTB"
        threat_id = "2147849359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 28 24 00 00 0a 0a 28 ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 0b 25 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 16 06 8e 69 6f 31 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSPX_2147849361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSPX!MTB"
        threat_id = "2147849361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 09 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 06 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 26 de 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AB_2147849707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AB!MTB"
        threat_id = "2147849707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fe 0c 01 00 fe 0c 02 00 93 fe 0e 03 00 fe 0c 00 00 fe 0c 03 00 fe 09 02 00 59 d1 6f 07 00 00 0a 26 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 01 00 8e 69 32 c5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AADR_2147850011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AADR!MTB"
        threat_id = "2147850011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 2b 13 04 11 04 1f 10 28 ?? 00 00 2b 11 04 6f ?? 00 00 0a 1f 10 59}  //weight: 5, accuracy: Low
        $x_1_2 = "7C584G8GF8FIGHH47S7Z54" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAED_2147850185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAED!MTB"
        threat_id = "2147850185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSRV_2147850757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSRV!MTB"
        threat_id = "2147850757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 09 16 09 8e 69 6f 1d 00 00 0a 0d 02 37 00 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSRY_2147850760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSRY!MTB"
        threat_id = "2147850760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 16 00 00 0a 00 11 07 72 9d 01 00 70 28 17 00 00 0a 16 fe 01 13 10 11 10 2d 0c 00 11 06 28 18 00 00 0a 26 00 2b 0f 00 11 06 28 19 00 00 0a 28 18 00 00 0a 26 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSSL_2147851113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSSL!MTB"
        threat_id = "2147851113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 12 04 6f ?? 00 00 0a 26 06 17 58 0a 06 28 ?? 00 00 06 6f ?? 00 00 0a fe 04 0d 09 2d de 08 28 ?? 00 00 0a 80 02 00 00 04 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSSP_2147851185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSSP!MTB"
        threat_id = "2147851185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 72 cf 02 00 70 28 ?? 00 00 0a 13 04 28 ?? 00 00 0a 72 3d 03 00 70 08 09 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAP_2147851317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAP!MTB"
        threat_id = "2147851317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 05 8f ?? 00 00 01 25 13 06 11 06 47 03 11 05 91 06 09 91 61 07 61 d6 b4 52 09 04 6f ?? 00 00 0a 17 da 33 04 16 0d 2b 04 09 17 d6 0d 11 05 17 d6 13 05 11 05 11 04 31 c6 08 03 8e 69 1f 70 07 61 b4 9c 08 2a}  //weight: 2, accuracy: Low
        $x_1_2 = {0a 04 09 6f ?? 00 00 0a 61 28 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 17 fe 01 2c 0e 72}  //weight: 1, accuracy: Low
        $x_1_3 = "XOREncrypt" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAGQ_2147851422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAGQ!MTB"
        threat_id = "2147851422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 13 05 11 05 72 01 00 00 70 6f ?? 00 00 0a 13 06 d0 ?? 00 00 01 28 ?? 00 00 0a 11 06 72 4d 00 00 70 28 ?? 00 00 0a 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 de 14 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHR_2147851480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHR!MTB"
        threat_id = "2147851480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 27 06 07 9a 25 6f ?? 00 00 0a 6f ?? 01 00 0a 80 3a 00 00 04 28 ?? 00 00 06 28 ?? 01 00 0a 16 28 ?? 00 00 0a 07 17 58 0b 07 06 8e 69 32 d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHR_2147851480_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHR!MTB"
        threat_id = "2147851480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 25 6f 1f 00 00 0a 72 ?? 00 00 70 6f 22 00 00 0a 25 6f 1f 00 00 0a 17 6f 23 00 00 0a 06 1f 64 20 d0 07 00 00 6f 19 00 00 0a 28 1a 00 00 0a 6f 24 00 00 0a 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHR_2147851480_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHR!MTB"
        threat_id = "2147851480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 58 1f 18 6a 58 11 09 6a 58 11 0a 1f 28 5a 6a 58 28 13 00 00 0a 13 0b 11 0b 28 17 00 00 0a 1f 2e 40 19 01 00 00 11 0b 28 12 00 00 0a 17 6a 58 28}  //weight: 1, accuracy: High
        $x_1_2 = {08 06 8e 69 28 0e 00 00 0a 1f 40 12 01 6f 12 00 00 06 26 06 16 08 06 8e 69 28 0f 00 00 0a 7e 04 00 00 04 08 06 8e 69 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHR_2147851480_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHR!MTB"
        threat_id = "2147851480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 8e 69 0b 72 ?? 00 00 70 0c 02 8e 69 17 33 06 02 16 9a 0c 2b 3a 02 8e 2d 2b}  //weight: 2, accuracy: Low
        $x_1_2 = "Process is elevated" wide //weight: 1
        $x_1_3 = "Attempting to inject into" wide //weight: 1
        $x_1_4 = "Shellcode Process Injector.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHR_2147851480_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHR!MTB"
        threat_id = "2147851480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Integration library for MalwareBytes antivirus service" wide //weight: 2
        $x_1_2 = "MalwareBytes Integration Solutions" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "d58e08cd-3b9b-4e9b-b04a-2c9ef8faab75" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSTA_2147851564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSTA!MTB"
        threat_id = "2147851564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0b 14 0c 38 30 00 00 00 00 73 09 00 00 0a 72 8d 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0c dd 06 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ASBL_2147851798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ASBL!MTB"
        threat_id = "2147851798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 02 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05 dd}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHR_2147851876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHR!MTB"
        threat_id = "2147851876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 c2 00 00 0a 02 6f ?? ?? ?? 0a 0b 06 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 20 ?? ?? ?? 61 72 ?? ?? ?? 70 20 ?? ?? ?? 61 28 ?? ?? ?? 2b 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 0c de 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "OxyDorks_v3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHR_2147851876_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHR!MTB"
        threat_id = "2147851876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 1b 00 00 0a 0a 72 ?? ?? ?? 70 0b 72 ?? ?? ?? 70 0c 06 72 ?? ?? ?? 70 08 6f ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 07 6f ?? ?? ?? 0a 00 73 ?? ?? ?? 0a 0d 09 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 17 6f ?? ?? ?? 0a 00 07 08 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Your_Skidded_Spoofer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAIG_2147852009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAIG!MTB"
        threat_id = "2147852009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 1c 5d 16 fe 01 0d 09 2c 08 1d 13 07 38 ?? ff ff ff 1f 09 2b f5 03 17 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 17 13 07 38 ?? ff ff ff 03 18 8d ?? 00 00 01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 6a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSUD_2147852363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSUD!MTB"
        threat_id = "2147852363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 7b 06 00 00 04 04 6f ?? 00 00 0a 16 05 6f ?? 00 00 0a 00 02 7b 09 00 00 04 04 05 02 7b 06 00 00 04 05 28 ?? 00 00 06 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAH_2147852481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAH!MTB"
        threat_id = "2147852481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 1f 20 8d ?? 00 00 01 0d 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 25 16 09 16 1f 10 28 ?? 00 00 0a 16 09 1f 0f 1f 10 28 ?? 00 00 0a 06 09 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 13 04 02 28 ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 0f}  //weight: 2, accuracy: Low
        $x_1_2 = "C schtasks /create /f /sc {0} /rl highest /tn {1} /tr {2}" wide //weight: 1
        $x_1_3 = "D9nUERwbEyNwAZu9wUgHYXVpd3mzHrmBFQ" wide //weight: 1
        $x_1_4 = "namespace1.Resource1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBHU_2147852848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBHU!MTB"
        threat_id = "2147852848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\file\\sam.zip" wide //weight: 1
        $x_1_2 = "protect.zip" wide //weight: 1
        $x_1_3 = "welwkdqiuwzxprkw" wide //weight: 1
        $x_1_4 = "ramadan38" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAKN_2147853038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAKN!MTB"
        threat_id = "2147853038"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 21 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "XB2j5Gwv6ftrYs+yaekTzGNhODnSNZkbIG+wsxT7wMI=" wide //weight: 1
        $x_1_4 = "Francia.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAKQ_2147853111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAKQ!MTB"
        threat_id = "2147853111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 07 07 8e 69 5d 07 11 07 07 8e 69 5d 91 08 11 07 08 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 28 ?? 00 00 06 07 11 07 17 58 07 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 06 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_RDA_2147853225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.RDA!MTB"
        threat_id = "2147853225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9989a000-3c0c-409d-8448-c4db3f061a95" ascii //weight: 1
        $x_1_2 = "test404" ascii //weight: 1
        $x_1_3 = "Resources" ascii //weight: 1
        $x_1_4 = "AboutBox1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSVI_2147888167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSVI!MTB"
        threat_id = "2147888167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 41 00 00 0a 13 27 28 ?? 00 00 0a 13 28 7e 1e 00 00 04 06 20 44 c3 a4 68 58 07 61 60 80 1e 00 00 04 11 27 73 43 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AALY_2147888487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AALY!MTB"
        threat_id = "2147888487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 0a 06 07 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 17 2c e8 09 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AANU_2147889410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AANU!MTB"
        threat_id = "2147889410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 72 01 00 00 70 28 ?? 00 00 0a 72 33 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04 14 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "6z7sscZFKovK3/1uZPqeeg==" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAC_2147890319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAC!MTB"
        threat_id = "2147890319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? 00 00 06 6e 02 07 17 58 02 8e 69 5d 91 28 ?? 00 00 06 6a 59 20 00 01 00 00 6a 58 20 00 01 00 00 6a 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAC_2147890319_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAC!MTB"
        threat_id = "2147890319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0d 09 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 09 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 11 04 06 6f ?? 00 00 0a 00 11 04 05 6f ?? 00 00 0a 00 11 04 0e 04 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 03 16 03 8e b7 6f ?? 00 00 0a 0b 11 04 6f ?? 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBIV_2147890404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBIV!MTB"
        threat_id = "2147890404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$cc7fad03-816e-432c-9b92-001f2d358379" ascii //weight: 1
        $x_1_2 = "server.Resources.resource" ascii //weight: 1
        $x_1_3 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_4 = "server1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAOZ_2147890513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAOZ!MTB"
        threat_id = "2147890513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 02 11 07 11 09 28 ?? 00 00 06 13 0b 20 00 00 00 00 7e ?? 02 00 04 7b ?? 01 00 04 3a ?? 00 00 00 26 20 00 00 00 00 38 ?? 00 00 00 fe 0c 08 00}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHH_2147891167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHH!MTB"
        threat_id = "2147891167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 12 17 58 13 12 11 1a 20 ?? ?? ?? d4 5a 20 ?? ?? ?? 9f 61 38 ?? ?? ?? ff 20 ?? ?? ?? d5 13 0d 11 1a 20 ?? ?? ?? 80 5a 20 ?? ?? ?? ec 61 38 ?? ?? ?? ff 11 0e 11 05 32 08 20 ?? ?? ?? e3 25}  //weight: 5, accuracy: Low
        $x_1_2 = "server.Resources.resources" ascii //weight: 1
        $x_1_3 = "ConfuserEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NHM_2147891689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NHM!MTB"
        threat_id = "2147891689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 02 7b 52 00 00 04 08 11 05 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 11 05 59 6f ?? 00 00 0a 58 13 05 11 05 6a 02 7b ?? 00 00 04 6f ?? 00 00 0a 32 ca}  //weight: 5, accuracy: Low
        $x_1_2 = "PasswordStealer.Stealer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAD_2147891899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAD!MTB"
        threat_id = "2147891899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 10 d2 13 35 11 10 1e 63 d1 13 10 11 1c 11 09 91 13 25 11 1c 11 09 11 23 11 25 61 11 19 19 58 61 11 35 61 d2 9c 11 25 13 19 17 11 09 58 13 09 11 09 11 27 32 a4}  //weight: 1, accuracy: High
        $x_1_2 = {11 2e 11 17 11 16 11 17 91 9d 17 11 17 58 13 17 11 17 11 18 32 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPAP_2147892264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPAP!MTB"
        threat_id = "2147892264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 08 9a 0d 09 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 2c 11 09 20 80 00 00 00 28 ?? ?? ?? 0a 09 28 ?? ?? ?? 0a 08 17 58 0c 08 07 8e 69 32 ca}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AART_2147892558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AART!MTB"
        threat_id = "2147892558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 20 31 2c 00 00 28 ?? 00 00 06 28 ?? 00 00 06 20 ca 2b 00 00 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AASG_2147892865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AASG!MTB"
        threat_id = "2147892865"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 11 00 28 ?? 06 00 06 11 00 28 ?? 06 00 06 28 ?? 06 00 06 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPAQ_2147892883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPAQ!MTB"
        threat_id = "2147892883"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 72 01 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 72 5b 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 08 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPAI_2147892972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPAI!MTB"
        threat_id = "2147892972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 04 07 11 04 91 06 59 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e8 09}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AASQ_2147892995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AASQ!MTB"
        threat_id = "2147892995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0b 11 0b 28 ?? 1c 00 06 11 0b 28 ?? 1c 00 06 28 ?? 1c 00 06 13 0d}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBJV_2147893421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBJV!MTB"
        threat_id = "2147893421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02}  //weight: 1, accuracy: High
        $x_1_2 = "$720bbda6-b2b8-4864-973f-9562fffa481b" ascii //weight: 1
        $x_1_3 = "Two_Dice.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAUB_2147893922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAUB!MTB"
        threat_id = "2147893922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 09 28 ?? 00 00 06 20 02 00 00 00 38 ?? ff ff ff 00 00 11 05 6f ?? 00 00 0a 13 0c 38 ?? 00 00 00 00 11 05 17 28 ?? 00 00 06 20 00 00 00 00 28 ?? 00 00 06 39}  //weight: 2, accuracy: Low
        $x_2_2 = {11 0c 11 0b 16 11 0b 8e 69 28 ?? 00 00 06 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPAU_2147893933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPAU!MTB"
        threat_id = "2147893933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 06 07 6e 06 8e 69 6a 5d b7 91 d7 11 04 07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 0c}  //weight: 3, accuracy: High
        $x_1_2 = "WindowsApp12.pdb" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMBA_2147893945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMBA!MTB"
        threat_id = "2147893945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 16 9a 26 16 2d f9 00 28 ?? 00 00 06 72 ?? ?? 00 70 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMBA_2147893945_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMBA!MTB"
        threat_id = "2147893945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 14 0b 38 ?? 00 00 00 00 28 ?? 00 00 06 0b dd ?? 00 00 00 26 dd ?? 00 00 00 07 2c eb 07 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed 08 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {4c 6f 61 64 00 47 65 74 54 79 70 65 00 47 65 74 4d 65 74 68 6f 64 00 54 6f 49 6e 74 33 32}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMBA_2147893945_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMBA!MTB"
        threat_id = "2147893945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 03 2d 18 07 06 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 16 07 06 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a de 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0a 06 02 6f ?? 00 00 0a 06 03 6f ?? 00 00 0a 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAUL_2147894407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAUL!MTB"
        threat_id = "2147894407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 05 11 05 08 6f ?? 00 00 0a 11 05 04 6f ?? 00 00 0a 11 05 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a 06 02 16 02 8e b7 6f ?? 00 00 0a 13 04}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAD_2147894564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAD!MTB"
        threat_id = "2147894564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1a ec ff 23 1b ec ff 23 1a ea f9 23 1b db ef 1e 16 cd f9 1b 15 c2 ff 1a 13 bb ff 1b 16 b5 95}  //weight: 1, accuracy: High
        $x_1_2 = "Users\\Fransesco\\Desktop\\kk\\kl\\obj\\Debug\\kk.pdb" ascii //weight: 1
        $x_1_3 = "kk.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAF_2147894628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAF!MTB"
        threat_id = "2147894628"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 17 58 11 04 5d 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBKS_2147894716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBKS!MTB"
        threat_id = "2147894716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 65 00 73 00 74 00 31 00 32 00 2e 00 43 00 6c 00 61 00 73 00 73 00 31 00 00 13 46 00 69 00 6b 00 72 00 61 00 68 00 61 00 63 00 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBKS_2147894716_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBKS!MTB"
        threat_id = "2147894716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 09 07 09 8e 69 6a 5d d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 06 07 06 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 07 17 6a 58 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBKT_2147895045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBKT!MTB"
        threat_id = "2147895045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$7049e1ba-aed1-4dab-b104-0ce1c47d3ebc" ascii //weight: 1
        $x_1_2 = "LumberRacer.Properties.Resources.resource" ascii //weight: 1
        $x_1_3 = "LumberRacer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAVP_2147895476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAVP!MTB"
        threat_id = "2147895476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 0c 16 0d 2b 4e 08 09 6f ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 20 c8 00 00 00 da 20 96 00 00 00 da 20 9b 00 00 00 da 1f 78 da 20 c8 00 00 00 da 13 05 11 05 28 ?? 00 00 0a 28 ?? 00 00 0a 13 06 07 11 06 28 ?? 00 00 0a 0b 00 09 17 d6 0d 09 08 6f ?? 00 00 0a fe 04 13 07 11 07 2d a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMBB_2147895532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMBB!MTB"
        threat_id = "2147895532"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 02 11 00 11 02 93 20 ?? 00 00 00 61 02 61 d1 9d 20}  //weight: 1, accuracy: Low
        $x_1_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 47 65 6e 65 72 61 74 65 49 56}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTBB_2147895541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTBB!MTB"
        threat_id = "2147895541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 09 00 00 04 8c 23 00 00 01 28 ?? 00 00 0a 02 28 ?? 00 00 0a 6f 31 00 00 0a 0b 7e 05 00 00 04 6f 32 00 00 0a 80 04 00 00 04 7e 04 00 00 04 07 16 07 8e 69 6f 33 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTBL_2147895776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTBL!MTB"
        threat_id = "2147895776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 32 09 00 70 28 ?? 00 00 0a 7e 03 00 00 04 72 40 09 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 b4 05 00 70 28 ?? 00 00 0a 73 14 00 00 0a 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GNF_2147896351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GNF!MTB"
        threat_id = "2147896351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 11 0f 07 11 0f 91 6e 11 0e 6a 61 d2 9c 11 0f 17 58 13 0f 11 0f 07 8e 69 32 e5}  //weight: 10, accuracy: High
        $x_10_2 = {06 11 0e 06 11 0e 91 6e 11 0d 6a 61 d2 9c 11 0e 17 58 13 0e 11 0e 06 8e 69 32 e5}  //weight: 10, accuracy: High
        $x_10_3 = {09 11 11 09 11 11 91 6e 11 10 6a 61 d2 9c 11 11 17 58 13 11 11 11 09 8e 69 32 e5}  //weight: 10, accuracy: High
        $x_10_4 = {11 04 11 12 11 04 11 12 91 6e 11 11 6a 61 d2 9c 11 12 17 58 13 12 11 12 11 04 8e 69 32 e2}  //weight: 10, accuracy: High
        $x_1_5 = "Shellcode Process Hollowing.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Heracles_KAE_2147896395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAE!MTB"
        threat_id = "2147896395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0e 11 11 11 0e 11 11 91 1f 45 61 d2 9c 11 11 17 58 13 11 11 11 11 0e 8e 69 32 e4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAF_2147896425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAF!MTB"
        threat_id = "2147896425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5f 2b 1d 03 6f ?? 00 00 0a 0c 2b 17 08 06 08 06 93 02 7b ?? 00 00 04 07 91 04 60 61 d1 9d 2b 03 0b 2b e0 06 17 59 25 0a 16 2f 02 2b 05 2b dd 0a 2b c8}  //weight: 5, accuracy: Low
        $x_5_2 = {e8 53 e8 41 e8 04 e8 00 e8 01 1d 83 f8 a6 f8 b3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAWN_2147896545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAWN!MTB"
        threat_id = "2147896545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 0e 06 17 d6 20 00 01 00 00 5d 0a 08 11 08 06 94 d6 20 00 01 00 00 5d 0c 11 08 06 94 13 0e 11 08 06 11 08 08 94 9e 11 08 08 11 0e 9e 11 08 11 08 06 94 11 08 08 94 d6 20 00 01 00 00 5d 94 13 0f 03 07 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 11 11 11 28 ?? 00 00 0a 13 0e 11 0e 11 0f 61 13 10 09 11 10 28 ?? 00 00 0a 6f ?? 00 00 0a 26 12 01 28 ?? 00 00 0a 07 17 da 28 ?? 00 00 0a 26 00 07 03 6f ?? 00 00 0a fe 02 16 fe 01 13 12 11 12 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAWP_2147896790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAWP!MTB"
        threat_id = "2147896790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 06 7e 01 00 00 04 6f ?? 00 00 0a 06 7e ?? 00 00 04 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 16 73 ?? 00 00 0a 0d 09 73 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 13 05 de 2a 11 04 2c 07 11 04 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
        $x_1_2 = "GetTempPath" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "C:\\TEMP\\" wide //weight: 1
        $n_5_5 = "\\IWB\\packaging\\TpmInitializer\\TpmEKPublicKeyExporter\\TpmEKPublicKeyExporter\\obj\\Release\\TpmEKPublicKeyExporter.pdb" ascii //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAXF_2147897194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAXF!MTB"
        threat_id = "2147897194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 18 58 1b 58 1d 59 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 18 58 1b 58 1d 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c 08 6a 03 8e 69 17 59 6a 06 17 58 6e 5a 31 a3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTCP_2147897340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTCP!MTB"
        threat_id = "2147897340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 d9 01 00 70 28 ?? 00 00 0a 26 72 15 02 00 70 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ASGC_2147897398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ASGC!MTB"
        threat_id = "2147897398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 20 b0 01 00 00 93 20 78 a4 00 00 59 2b e9 11 07 20 c0 00 00 00 91 1f 69 59 2b dc 1e 0b 11 07 20 c8 00 00 00 91 13 05}  //weight: 1, accuracy: High
        $x_1_2 = {93 05 58 1f 6d 5f 9d 61 1f 11 59 06 61}  //weight: 1, accuracy: High
        $x_1_3 = "RFebBaClhEWIFvwxqU" ascii //weight: 1
        $x_1_4 = "F0RMc5TVuuJ8V5jg7e" ascii //weight: 1
        $x_1_5 = "fYjq7b0HR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAXR_2147897554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAXR!MTB"
        threat_id = "2147897554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 8e 69 8d ?? 00 00 01 0d 16 13 04 2b 18 09 11 04 08 11 04 91 06 11 04 06 8e 69 5d 91 61 d2 9c 11 04 17 58 13 04 11 04 08 8e 69 32 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PABY_2147897560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PABY!MTB"
        threat_id = "2147897560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "-Command \"Stop-Process -Name explorer -Force; Start-Process explorer\"" wide //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\runtimes" wide //weight: 1
        $x_1_4 = "Hack.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAYA_2147897728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAYA!MTB"
        threat_id = "2147897728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 5d 17 59 17 58 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 1e 58 1f 09 58 1f 11 59 91 61 28 ?? 00 00 0a 02 08 20 89 10 00 00 58 20 88 10 00 00 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAYA_2147897728_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAYA!MTB"
        threat_id = "2147897728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 1f 3c 28 ?? 00 00 0a 13 04 03 11 04 1f 34 58 28 ?? 00 00 0a 13 05 20 b3 00 00 00 8d ?? 00 00 01 13 06 11 06 16 20 02 00 01 00 9e 28 ?? 00 00 0a 1a 33 1b 7e ?? 00 00 04 12 03 7b ?? 00 00 04 11 06 6f ?? 00 00 06 2d 21}  //weight: 4, accuracy: Low
        $x_4_2 = {03 11 0d 1f 0c 58 28 ?? 00 00 0a 13 10 03 11 0d 1f 10 58 28 ?? 00 00 0a 13 11 03 11 0d 1f 14 58 28 ?? 00 00 0a 13 12 11 11 2c 3e 11 11 8d ?? 00 00 01 13 13 03 11 12 11 13 16 11 13 8e 69 28 ?? 00 00 0a 7e ?? 00 00 04 12 03 7b ?? 00 00 04 11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f ?? 00 00 06 2d 06 73 ?? 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84}  //weight: 4, accuracy: Low
        $x_1_3 = "a2VybmVsMzI=" wide //weight: 1
        $x_1_4 = "VmlydHVhbEFsbG9jRXg=" wide //weight: 1
        $x_1_5 = "Q3JlYXRlUHJvY2Vzc0E=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAI_2147898337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAI!MTB"
        threat_id = "2147898337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 07 07 11 07 91 20 ?? 00 00 00 61 d2 9c 11 07 17 58 13 07 11 07 07 8e 69 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTDU_2147898626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTDU!MTB"
        threat_id = "2147898626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 17 00 00 0a dc 28 ?? 00 00 0a 08 6f 39 00 00 0a 6f 3c 00 00 0a 13 04 de 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAK_2147898864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAK!MTB"
        threat_id = "2147898864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 2b 19 7e ?? 00 00 04 06 7e ?? 00 00 04 06 9a 1b 17 28 ?? 00 00 0a a2 06 17 58 0a 06 7e ?? 00 00 04 8e 69 32 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSIP_2147899376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSIP!MTB"
        threat_id = "2147899376"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 0a 7e 64 00 00 04 0c 12 04 08 28 82 00 00 06 06 fe 06 42 01 00 06 73 66 00 00 0a 73 63 00 00 0a 0b 07 28 64 00 00 0a 06 28 68 00 00 0a 12 04 28 80 00 00 06 07 28 65 00 00 0a de 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHE_2147899407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHE!MTB"
        threat_id = "2147899407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 19 15 28 ?? 00 00 0a 00 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0a 17 12 00 15 6a 16 28 ?? 00 00 0a 00 17 8d 4d 00 00 01 0d 09 16 17 9e 09 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHE_2147899407_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHE!MTB"
        threat_id = "2147899407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 07 16 08 6e 28 18 00 00 0a 07 8e 69 28 19 00 00 0a 7e 1a 00 00 0a 26 16 0d 7e 1a 00 00 0a 13 04 16 16 08 11 04 16 12 03 28}  //weight: 2, accuracy: High
        $x_1_2 = "shllcryptrunn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHE_2147899407_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHE!MTB"
        threat_id = "2147899407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 18 02 03 07 28 ?? ?? ?? 06 0a 06 2d 08 07 80 ?? 04 00 04 14 2a 07 17 58 0b 07 7e ?? 04 00 04 8e 69 32 de 02 14 51}  //weight: 1, accuracy: Low
        $x_1_2 = "NiceHashQuickMiner.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHE_2147899407_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHE!MTB"
        threat_id = "2147899407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 8e 69 8d 10 00 00 01 0c 16 0d 38 29 00 00 00 07 09 91 06 59 20 00 01 00 00 5d 13 04 11 04 16 3c 0a 00 00 00 11 04 20 00 01 00 00 58 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 8e 69 32 d1}  //weight: 1, accuracy: High
        $x_1_2 = {0b 06 8e 69 07 8e 69 59 8d ?? 00 00 01 0c 06 07 07 8e 69 28 ?? 00 00 0a 06 07 8e 69 08 16 08 8e 69 28 ?? 00 00 0a 28 ?? 00 00 0a 0d 09 20 80 00 00 00 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AHE_2147899407_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AHE!MTB"
        threat_id = "2147899407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 2b 1e 02 06 02 06 91 03 06 03 28 ?? 00 00 06 25 26 5d 28 ?? 01 00 06 25 26 61 d2 9c 06 17 58 0a 06 02 28 ?? 01 00 06 25 26 69 32 d6}  //weight: 2, accuracy: Low
        $x_1_2 = "ratTests.pdb" ascii //weight: 1
        $x_1_3 = "vMeJL4ytOJ" wide //weight: 1
        $x_1_4 = "a512756f-f909-43b8-a558-23c2be127d23" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAAD_2147899451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAAD!MTB"
        threat_id = "2147899451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 1f 0f 59 1f 0f 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 0a 58 1f 13 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAAS_2147899891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAAS!MTB"
        threat_id = "2147899891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 11 03 11 07 11 06 11 03 59 17 59 91 9c}  //weight: 2, accuracy: High
        $x_2_2 = {11 07 11 06 11 03 59 17 59 11 04 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBFR_2147899960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBFR!MTB"
        threat_id = "2147899960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 64 00 63 00 78 00 78 00 63 00 6b 00 6e 00 6e 00 00 0d 64 00 63 00 63 00 73 00 6e 00 78 00 00 11 64 00 63 00 63 00 73 00 78 00 73 00 63 00 79 00 00 13 64 00 63 00 63 00 73 00 63 00 77 00 73 00 63 00 62}  //weight: 1, accuracy: High
        $x_1_2 = "bxbdc.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAL_2147900002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAL!MTB"
        threat_id = "2147900002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 05 08 11 05 91 07 11 04 93 28 ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 05 17 58 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AAAZ_2147900085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AAAZ!MTB"
        threat_id = "2147900085"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 6f ?? 00 00 0a 02 11 05 6f ?? 00 00 0a fe 01 16 fe 01 13 07 11 07 2d 1d 00 06 02 11 05 07 58 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 2b 17 00 11 05 17 58 13 05 11 05 02 6f ?? 00 00 0a fe 04 13 07 11 07 2d b0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTFD_2147900425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTFD!MTB"
        threat_id = "2147900425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 2e 07 07 02 28 ?? 03 00 0a 07 28 ?? 3a 00 06 7e a2 00 00 0a 28 ?? 03 00 0a 0a de 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAA_2147900441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAA!MTB"
        threat_id = "2147900441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 05 11 05 08 6f ?? 00 00 0a 00 11 05 05 6f ?? 00 00 0a 00 11 05 0e 04 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 0a 06 03 16 03 8e b7 6f ?? 00 00 0a 13 04}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NBL_2147900442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NBL!MTB"
        threat_id = "2147900442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {fe 0c 01 00 fe 0c 16 00 fe 0c 01 00 fe 0c 16 00 91 20 8b 45 9f 04 20 92 aa 4d 16 61 65 20 3a c7 78 ef 58 66 20 6e dd 3d 04 61 20 01 00 00 00 63 20 01 00 00 00 62 65 20 03 00 00 00 63 20 7a 00 13 fb 61 61 d2 9c}  //weight: 3, accuracy: High
        $x_3_2 = {fe 0c 02 00 fe 0c 01 00 fe 0c 02 00 fe 0c 01 00 93 20 e7 b7 17 d2 20 47 0f 44 13 61 20 05 00 00 00 63 20 43 9d 0a fe 61 61 fe 09 00 00 61 d1 9d}  //weight: 3, accuracy: High
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "set_Key" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_RL_2147900444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.RL!MTB"
        threat_id = "2147900444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 02 09 6f 73 00 00 0a 03 09 ?? ?? ?? ?? ?? 61 60 0a 00 09 17 58 0d 09 02 6f 15 ?? ?? ?? fe 04 13 04 11 04 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTFO_2147900702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTFO!MTB"
        threat_id = "2147900702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 9c 00 00 00 2a 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 04 20 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTFV_2147900785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTFV!MTB"
        threat_id = "2147900785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 1a 01 00 00 fe 0e 2f 00 38 2d 35 00 00 3a 3f 12 00 00 fe 0c 2a 00 20 0b 00 00 00 fe 0c 2b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTGA_2147900845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTGA!MTB"
        threat_id = "2147900845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d f0 00 00 01 13 05 11 09 20 26 a0 ac 95 5a 20 a3 cd 1e 82 61 2b bb 09 11 04 11 04 8e 69 28 ?? 00 00 06 11 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GMZ_2147900954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GMZ!MTB"
        threat_id = "2147900954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 07 08 28 ?? ?? ?? 06 8c 2c 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 08 7e 3f 00 00 04 8e 69 17 59 2e 0c 06 72 2d 03 00 70 28 ?? ?? ?? 0a 0a 08 17 58 0c 08 7e 3f 00 00 04 8e 69 32 c2}  //weight: 10, accuracy: Low
        $x_1_2 = "Hipis_ConvFormat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NN_2147901182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NN!MTB"
        threat_id = "2147901182"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0b 08 17 58 0c 08 06 8e 69 17 59 fe 02 16 fe 01 13 06 11 06 2d dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ASGD_2147901191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ASGD!MTB"
        threat_id = "2147901191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 17 8d ?? 00 00 01 0d 09 16 1f 2c 9d 09 6f ?? 00 00 0a 0b 07 8e 69 18 2f 02 16 2a 07 16 9a 26 07 17 9a 28 ?? 00 00 0a 0c 08 16 32 02 17 2a 16 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "EngineDynamoConfig\\Config" wide //weight: 1
        $x_1_3 = "OverhaulTime.cfg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPCC_2147901464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPCC!MTB"
        threat_id = "2147901464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 18 d8 0a 06 1f ?? fe 02 13 ?? 11 ?? 2c 03 1f ?? 0a 00 06 1f ?? 5d 16 fe 03 13 ?? 11 ?? 2d e0 06 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMCC_2147901623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMCC!MTB"
        threat_id = "2147901623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 1f 16 5d 91 13 0b 07 11 09 91}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_CXAA_2147902016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.CXAA!MTB"
        threat_id = "2147902016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 09 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 06 73 ?? 00 00 0a 13 05 00 11 05 11 04 16 73 ?? 00 00 0a 13 06 00 73 ?? 00 00 0a 13 07 00 11 06 11 07 6f ?? 00 00 0a 00 11 07 6f ?? 00 00 0a 0b 00 de 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GZZ_2147902073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GZZ!MTB"
        threat_id = "2147902073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a d2 61 d2 81 09 00 00 01 08 17 58 0c 08 07 17 59 33 d3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NC_2147902274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NC!MTB"
        threat_id = "2147902274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 47 11 0c 11 10 11 0c 8e 69 5d 91 61 d2 52 00 11 10 17 58 13 10 11 10 11 0b 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPB_2147902299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPB!MTB"
        threat_id = "2147902299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 6f 06 00 00 0a 61 d2 52 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPPY_2147902308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPPY!MTB"
        threat_id = "2147902308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 1f 4d 5d 6f ?? ?? ?? 0a d2 61 d2 81 ?? ?? ?? 01 08 17 58 0c 08 07 17 59 33 d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBFT_2147902422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBFT!MTB"
        threat_id = "2147902422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 1f 0a 13 05 2b b6 05 0e 04 61 1f 3b 59 06 61}  //weight: 1, accuracy: High
        $x_1_2 = "pathologist.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPAA_2147902466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPAA!MTB"
        threat_id = "2147902466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 00 06 04 6f ?? ?? ?? 06 0d 09 61 73}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAM_2147902505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAM!MTB"
        threat_id = "2147902505"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {18 5a 94 02 11 05 18 5a 17 58 94 58 9e 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPFF_2147902614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPFF!MTB"
        threat_id = "2147902614"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {08 09 58 0c 09 17 58 0d 09 02 31 f4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAG_2147902767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAG!MTB"
        threat_id = "2147902767"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 [0-15] 61 [0-15] 17 58 08 5d 13 [0-15] 20 00 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPC_2147902864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPC!MTB"
        threat_id = "2147902864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 8e 69 8d 19 00 00 01 0a 16 0b 2b 15 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPNZ_2147902872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPNZ!MTB"
        threat_id = "2147902872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 5d 91 11 09 61 13 0a 07 11 07 08 5d 91 13 0b 11 0a 11 0b 20 00 01 00 00 58 59 13 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTIR_2147902887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTIR!MTB"
        threat_id = "2147902887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 4d 00 00 0a 25 18 6f 4e 00 00 0a 6f 4f 00 00 0a 07 16 07 8e 69 6f 50 00 00 0a 0c de 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EJAA_2147902904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EJAA!MTB"
        threat_id = "2147902904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 04 11 05 58 1b 2c e9 13 04 11 05 17 58 13 05 16 3a 52 ff ff ff 11 05 02 31 e5}  //weight: 4, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AKP_2147903014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AKP!MTB"
        threat_id = "2147903014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 24 01 00 06 17 8d ?? ?? ?? 01 25 16 08 75 a9 00 00 01 1f 10 6f ?? ?? ?? 0a a2 14 14 16 17}  //weight: 1, accuracy: Low
        $x_1_2 = {11 0c 74 ac 00 00 01 02 16 02 8e 69 6f ?? ?? ?? 0a 11 0c 75 ac 00 00 01 6f ?? ?? ?? 0a 1b 13 14 2b bf de 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_FHAA_2147903195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.FHAA!MTB"
        threat_id = "2147903195"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 10 58 1f 19 59 91 07 08 07 8e 69 5d 1f 09 58 1f 10 58 1f 19 59 91 61 ?? 08 20 8a 10 00 00 58 20 89 10 00 00 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPNV_2147903223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPNV!MTB"
        threat_id = "2147903223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d d4 91 61 28 ?? ?? ?? 0a 07 11 04 17 6a 58 07 8e 69 6a 5d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_FXAA_2147903707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.FXAA!MTB"
        threat_id = "2147903707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1b 11 13 6f ?? 00 00 0a 11 1b 11 14 6f ?? 00 00 0a 11 1b 11 1b 6f ?? 00 00 0a 11 1b 6f ?? 00 00 0a 6f ?? 00 00 0a 11 12 16 11 12 8e 69 6f ?? 00 00 0a 13 1c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPD_2147903828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPD!MTB"
        threat_id = "2147903828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 11 08 59 20 00 01 00 00 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAO_2147903842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAO!MTB"
        threat_id = "2147903842"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 0b 07 02 16 02 8e 69 6f ?? 00 00 0a 0c 07 6f ?? 00 00 0a 06 6f ?? 00 00 0a 08 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PTJQ_2147904075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PTJQ!MTB"
        threat_id = "2147904075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 9c 00 00 0a 17 59 28 ?? 00 00 0a 16 7e 73 00 00 04 02 1a 28 ?? 00 00 0a 11 05 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMMB_2147904116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMMB!MTB"
        threat_id = "2147904116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 2b 01 26 01 11 0f 28 ?? 00 00 06 11 0d 09 06 28 ?? 00 00 06 16 28 ?? 00 00 06 13 05}  //weight: 2, accuracy: Low
        $x_1_2 = {11 05 1b 5d 13 04 11 05 1b 5b 0c 16 0a 1f 09 13 06 2b a0}  //weight: 1, accuracy: High
        $x_2_3 = {b4 e8 3d 35 06 6b de ca c2 5f 47 37 e6 44 02 a5 e9 24 4e c8 81 8c 4b 04 9e 7d 15 dc 63 c6 ef 38 84}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GKAA_2147904124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GKAA!MTB"
        threat_id = "2147904124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1e 13 08 38 ?? ff ff ff 08 74 ?? 00 00 01 03 6f ?? 00 00 0a 08 74 ?? 00 00 01 6f ?? 00 00 0a 13 04}  //weight: 2, accuracy: Low
        $x_2_2 = {01 02 16 02 8e 69 6f ?? 00 00 0a de 49}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZB_2147904141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZB!MTB"
        threat_id = "2147904141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 5d 13 ?? 07 11 ?? 91 11 ?? 09 1f ?? 5d 91 61 13 ?? 1f ?? 13}  //weight: 1, accuracy: Low
        $x_1_2 = {09 11 06 91 11 08 11 04 1f 16 5d 91 61 13 0c 1f 0d 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Heracles_SPBP_2147904144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPBP!MTB"
        threat_id = "2147904144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZC_2147904268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZC!MTB"
        threat_id = "2147904268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NF_2147904794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NF!MTB"
        threat_id = "2147904794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 08 5d 13 08 07 11 08 91 11 04 09 1f 16 5d 91 61 13 09}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZQ_2147904933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZQ!MTB"
        threat_id = "2147904933"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 91 61 03 08 20 ?? ?? ?? ?? 58 20 ?? ?? ?? ?? 59 03 8e 69 5d 1f ?? 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAR_2147905001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAR!MTB"
        threat_id = "2147905001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 0d 07 09 06 08 18 5b 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 8c ?? 00 00 01 28 ?? 00 00 0a 0b 08 18 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NG_2147905148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NG!MTB"
        threat_id = "2147905148"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 91 08 11 05 08 8e 69 5d 91 61 d2 ?? ?? 00 00 0a 00 00 11 05 17 58 13 05 11 05 6a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZO_2147905487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZO!MTB"
        threat_id = "2147905487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "887aac006e01" ascii //weight: 1
        $x_1_3 = "Paradise.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PSOK_2147906118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PSOK!MTB"
        threat_id = "2147906118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 98 00 00 0a 0a 02 72 a3 05 00 70 6f ?? ?? ?? 0a 2c 3e 06 02 6f ?? ?? ?? 0a 0b 07 16 73 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 08 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPDO_2147906459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPDO!MTB"
        threat_id = "2147906459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 61 d2 13 ?? 11 ?? 07 11 ?? 17 58 09 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZV_2147906495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZV!MTB"
        threat_id = "2147906495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 4e 00 32 00 43 00 44 00 43 00 35 00 ?? 00 ?? 00 30 00 36 00}  //weight: 1, accuracy: Low
        $x_1_2 = "chromeNotEncode.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMMF_2147906575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMMF!MTB"
        threat_id = "2147906575"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 07 09 16 6f ?? 00 00 0a 13 ?? 12 ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_JRAA_2147906610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.JRAA!MTB"
        threat_id = "2147906610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 09 5d 91 07 06 1f 16 5d 6f ?? 00 00 0a 61 13 0d 11 0d 11 0c 59 20 00 01 00 00 58 20 00 01 00 00 5d 13 0e 08 06 09 5d 11 0e 28 ?? 00 00 0a d2 9c 06 17 58 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_JZAA_2147907027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.JZAA!MTB"
        threat_id = "2147907027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 38 16 00 00 00 11 05 11 06 e0 58 7e ?? 01 00 04 11 06 e0 91 52 11 06 17 58 13 06 11 06 6e 7e ?? 01 00 04 8e 69 6a 3f da ff ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {13 07 16 13 08 7e ?? 00 00 0a 13 09 16 16 09 11 09 16 12 08 28 ?? 00 00 06 13 07 11 07 15}  //weight: 2, accuracy: Low
        $x_1_3 = "VirtualAlloc" wide //weight: 1
        $x_1_4 = "CreateThread" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPFP_2147907259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPFP!MTB"
        threat_id = "2147907259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0b 11 09 16 73 ?? ?? ?? 0a 13 0c 11 0c 11 0a 6f ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 07 de 0f 16 2d 0b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPZO_2147907377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPZO!MTB"
        threat_id = "2147907377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0b 11 09 16 73 ?? ?? ?? 0a 13 0c 11 0c 11 0a 6f ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 07 de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZW_2147907391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZW!MTB"
        threat_id = "2147907391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 7b 0a 00 00 95 5f 11 28 20 4e 03 00 00 95 61 58 13 37 38 03 0f 00 00 11 37 11 28 20 10 04 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_HNA_2147907456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.HNA!MTB"
        threat_id = "2147907456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 ?? 6f ?? 00 00 0a a2 11 ?? 14 14 14 17 28 ?? ?? 00 0a 26 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 8e b7 32 c7 ?? 14 72 ?? ?? 00 70 17 8d 03 00 00 01 13 ?? 11 ?? 16 72 ?? ?? 00 70 a2 11 ?? 14 14 14 28 13 00 0a 13 ?? 16 13 ?? 2b 31 11 ?? 11 ?? 9a ?? ?? 14 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_HNB_2147907488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.HNB!MTB"
        threat_id = "2147907488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 00 6e 74 64 6c 6c 2e 64 6c 6c 00 00 00 00 00 00 00 4e 74 43 72 65 61 74 65 54 68 72 65 61 64 45 78 00 00 00 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {4b 33 32 45 6e 75 6d 50 72 6f 63 65 73 73 65 73 [0-4] 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 [0-4] 4b 33 32 45 6e 75 6d 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 73}  //weight: 1, accuracy: Low
        $x_2_3 = {48 8d ac 24 b8 fe ff ff 48 81 ec 48 02 00 00 bb 01 00 00 00 45 33 f6 89 9d a8 01 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Heracles_KOAA_2147907708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KOAA!MTB"
        threat_id = "2147907708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 11 04 28 ?? 00 00 0a 20 2e b8 3f 49 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0b 28 ?? 00 00 06 73 ?? 00 00 0a 0c 08 11 05 16 73 ?? 00 00 0a 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPOO_2147907834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPOO!MTB"
        threat_id = "2147907834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 61 07 11 ?? 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f 28 ?? ?? ?? 0a 9c 08 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_LJAA_2147908495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.LJAA!MTB"
        threat_id = "2147908495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 11 06 07 11 06 9a 1f 10 28 ?? 00 00 06 9c 00 11 06 17 58 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "AFEKJDFNSJKFAJKFSDNJKFJKL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPMC_2147909766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPMC!MTB"
        threat_id = "2147909766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 08 11 0e 91 59 13 0f 11 0f 20 00 01 00 00 58 13 10 08 07 11 10 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GZX_2147910215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GZX!MTB"
        threat_id = "2147910215"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 1b 6a 28 ?? ?? ?? 0a 1f 40 12 05 28 ?? ?? ?? 06 26 1c}  //weight: 5, accuracy: Low
        $x_5_2 = {72 4b 00 00 70 0c 28 ?? ?? ?? 0a 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 07 09 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NJAA_2147911203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NJAA!MTB"
        threat_id = "2147911203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0d 38 19 00 00 00 08 07 09 18 28 ?? 0e 00 06 1f 10 28 ?? 0e 00 06 28 ?? 0e 00 06 09 18 58 0d 09 07 28 ?? 0e 00 06 32 de}  //weight: 4, accuracy: Low
        $x_1_2 = "Qynewvwymc.Bridges.Server" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PBAA_2147912701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PBAA!MTB"
        threat_id = "2147912701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0c 19 13 09 38 ?? ff ff ff 07 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 11 04 12 05 28 ?? 00 00 0a 13 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NJ_2147913068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NJ!MTB"
        threat_id = "2147913068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54}  //weight: 5, accuracy: High
        $x_2_2 = "_crypted.exe" ascii //weight: 2
        $x_2_3 = "file_" ascii //weight: 2
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPJ_2147915013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPJ!MTB"
        threat_id = "2147915013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "78.111.67.189" ascii //weight: 5
        $x_2_2 = {47 65 74 42 79 74 65 41 72 72 61 79 41 73 79 6e 63 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMAJ_2147915058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMAJ!MTB"
        threat_id = "2147915058"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 d2 13 [0-10] 20 ff 00 00 00 5f d2 13 [0-20] 61 13 [0-20] 20 ff 00 00 00 5f d2 9c 00 11 ?? 17 6a 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAV_2147916029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAV!MTB"
        threat_id = "2147916029"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a2b3c4d5-e6f7-8901-abcd-34567ef89012" ascii //weight: 1
        $x_1_2 = "CosmoSphere Innovations" ascii //weight: 1
        $x_1_3 = "Harnessing the power of technology to drive global innovation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AWA_2147916559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AWA!MTB"
        threat_id = "2147916559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PrhsVpkxwzRLiHlcHaoQLNyac.dll" ascii //weight: 2
        $x_2_2 = "HApQgvjzSydrlmPbxPPnxed.dll" ascii //weight: 2
        $x_2_3 = "dmUGMjzEoLxlkevEKQLlrHeekpPDM.dll" ascii //weight: 2
        $x_2_4 = "sdoAWOqSmwIqhMGwxpFVuH.dll" ascii //weight: 2
        $x_2_5 = "fTYIGbpHodcBYFCGIuSynGK.dll" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NK_2147916582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NK!MTB"
        threat_id = "2147916582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 6e 08 8e 69 6a 5d d4 91 13 0d 11 04 11 0d 58 11 06 09 95 58}  //weight: 5, accuracy: High
        $x_4_2 = {5f d2 9c 00 11 0f 17 6a 58 13 0f 11 0f 11 07 8e 69 17 59 6a fe 02 16 fe 01}  //weight: 4, accuracy: High
        $x_3_3 = {5f 13 04 11 06 09 95 13 05 11 06 09 11 06 11 04 95 9e 11 06 11 04 11 05 9e 07}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MB_2147917207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MB!MTB"
        threat_id = "2147917207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0e 05 00 06 28 0c 05 00 06 72 b1 00 00 70 06 28 a7 02 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NM_2147917334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NM!MTB"
        threat_id = "2147917334"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 5d 08 58 08 5d 91 11 06 61 11 05 17 58 08 5d 08 58 08 5d}  //weight: 2, accuracy: High
        $x_1_2 = "HumansHandForm_Load" ascii //weight: 1
        $x_1_3 = "Blackjack3" ascii //weight: 1
        $x_1_4 = "Blackjack3.Scoreboard.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMBF_2147917715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMBF!MTB"
        threat_id = "2147917715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {43 00 6c 00 61 00 73 00 73 00 4c 00 69 00 62 00 72 00 61 00 72 00 79 00 31 00 2e 00 43 00 6c 00 61 00 73 00 73 00 31 00 00 07 52 00 75 00 6e}  //weight: 2, accuracy: High
        $x_1_2 = "StrReverse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBXP_2147918353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBXP!MTB"
        threat_id = "2147918353"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e b7 17 da 17 d6 8d ?? 00 00 01 0a 02 02 8e b7 17 da 91 0b}  //weight: 1, accuracy: Low
        $x_1_2 = {8e b7 5d 91 61 9c 09 17 d6 0d 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBXQ_2147918465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBXQ!MTB"
        threat_id = "2147918465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 09 91 9c 06 09 11 09 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 0a}  //weight: 1, accuracy: High
        $x_1_2 = "ef-382cfefa9adf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAX_2147919409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAX!MTB"
        threat_id = "2147919409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0d 11 0e 11 0d 11 0e 91 18 59 20 ff 00 00 00 5f d2 9c 11 0e 17 58 13 0e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_VIAA_2147920202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.VIAA!MTB"
        threat_id = "2147920202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 08 17 73 ?? 02 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 02 00 0a 09 6f ?? 02 00 0a 0a de 0f}  //weight: 3, accuracy: Low
        $x_2_2 = {07 2b a7 28 ?? 02 00 0a 2b a7 28 ?? 02 00 0a 2b a7 6f ?? 02 00 0a 2b a2}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_VOAA_2147920343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.VOAA!MTB"
        threat_id = "2147920343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 04 6f ?? 01 00 0a 06 06 6f ?? 01 00 0a 06 6f ?? 01 00 0a 6f ?? 01 00 0a 0b 73 ?? 01 00 0a 0c 08 07 17 73 ?? 01 00 0a 0d 09 02 16 02 8e 69 6f ?? 01 00 0a 09 6f ?? 01 00 0a 08 6f ?? 01 00 0a 13 04 de 28}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_CCJB_2147920403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.CCJB!MTB"
        threat_id = "2147920403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Tkz9VclMcuTOMs4B4I7IIA==" ascii //weight: 5
        $x_1_2 = "RPxiHFG6u5MP9B4+fz1mmQ==" ascii //weight: 1
        $x_1_3 = "hfpAqlEOQD4LfBs7K2sP4w==" ascii //weight: 1
        $x_1_4 = "h2Lxqd80TmuM9piiBtrlWQ==" ascii //weight: 1
        $x_1_5 = "fOO+8eUI0bFmDWyr5zqYFg==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBXT_2147920899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBXT!MTB"
        threat_id = "2147920899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "LvlEditor.AAAAAAAAAAA.resource" ascii //weight: 3
        $x_2_2 = "Rfc2898DeriveBytes" ascii //weight: 2
        $x_1_3 = "Aintac" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_WNAA_2147921062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.WNAA!MTB"
        threat_id = "2147921062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 20 [0-32] 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a de 0c}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_XIAA_2147921701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.XIAA!MTB"
        threat_id = "2147921701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 07 18 5a 6f ?? 00 00 0a 28 ?? 00 00 0a 1a 7e ?? 00 00 04 1f 34 7e ?? 00 00 04 1f 34 91 7e ?? 00 00 04 1f 11 91 61 20 f5 00 00 00 5f 9c 62 72 3d 04 00 70 03 07 18 5a 17 58 6f ?? 00 00 0a 28 ?? 00 00 0a 60 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_XLAA_2147921702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.XLAA!MTB"
        threat_id = "2147921702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 0a 16 0b 2b 16 00 06 07 a3 ?? 00 00 01 28 ?? 00 00 06 de 03 26 de 00 07 17 58 0b 07 06 28 ?? 00 00 2b 32 e1}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_XNAA_2147921704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.XNAA!MTB"
        threat_id = "2147921704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0a 72 15 00 00 70 28 ?? 00 00 06 72 47 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 09 20 02 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26}  //weight: 3, accuracy: Low
        $x_2_2 = {11 04 11 07 16 11 07 8e 69 28 ?? 00 00 06 20}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAY_2147921794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAY!MTB"
        threat_id = "2147921794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 7e 05 00 00 04 14 28 1a 00 00 0a 0b 16 2b 01 16 45 03 00 00 00 02 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {2b 00 00 00 2b 32 07 2c 26 72 01 00 00 70 d0 05 00 00 02 28}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAZ_2147921798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAZ!MTB"
        threat_id = "2147921798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 09 11 04 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 16 08 06 1a 28 ?? 00 00 0a 06 1a 58 0a 11 04 17 58 13 04 11 04 07 32 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MKZ_2147922554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MKZ!MTB"
        threat_id = "2147922554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 20 18 ae 29 2f 20 7e 75 6a 48 61 7e ?? ?? ?? 04 7b ?? ?? ?? 04 61 28 2f 00 00 06 28 ?? ?? ?? 0a 6f 21 00 00 0a 38 00 00 00 00 11 00 11 00 6f ?? ?? ?? 0a 11 00 6f 23 00 00 0a 6f 24 00 00 0a 13 01}  //weight: 4, accuracy: Low
        $x_5_2 = {11 02 6f 2a 00 00 0a 73 27 00 00 0a 13 06 38 ?? ?? ?? 00 00 1a 8d ?? ?? ?? 01 13 07 38 0f 00 00 00 11 06 16 73 ?? ?? ?? 0a 13 09 38 20 00 00 00 11 06 11 07 16 1a 6f ?? ?? ?? 0a 26 38 00 00 00 00 11 07 16 28 2d 00 00 0a 13 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_HNG_2147922846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.HNG!MTB"
        threat_id = "2147922846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 53 79 73 74 65 6d 2e 57 69 6e 64 6f 77 73 2e 46 6f 72 6d 73 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 24 37 66 32 38 34 63 64 66 2d 35 63 61 38 2d 34 38 34 37 2d 38 66 34 37 2d 34 31 62 36 64 65 62 37 32 66 62 33 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PPPZ_2147923248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PPPZ!MTB"
        threat_id = "2147923248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {73 21 00 00 0a 0c 08 06 07 6f ?? ?? ?? 0a 0d 73 23 00 00 0a 13 04 11 04 09 17 73 24 00 00 0a 13 05 11 05 7e 02 00 00 04 16 7e 02 00 00 04 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 80 02 00 00 04 dd 1e 00 00 00 11 05 39 07 00 00 00 11 05 6f ?? ?? ?? 0a dc 11 04 39 07 00 00 00 11 04 6f ?? ?? ?? 0a dc 7e 02 00 00 04 13 06 dd 0d 00 00 00 08 39 06 00 00 00 08 6f ?? ?? ?? 0a dc 11 06}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_Z_2147923448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.Z!MTB"
        threat_id = "2147923448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "https://getsolara.dev" ascii //weight: 1
        $x_1_2 = "https://gist.githubusercontent.com/furryman12" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "DISCORD" ascii //weight: 1
        $x_1_5 = "UploadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_Heracles_MBXU_2147923462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBXU!MTB"
        threat_id = "2147923462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 20 b3 15 00 00 28 ?? 00 00 0a 00 d0 ?? 00 00 01 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 06 72 01 00 00 70 6f ?? 00 00 0a 72 67 00 00 70 1f 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_DV_2147923703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.DV!MTB"
        threat_id = "2147923703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {20 08 00 00 00 64 d2 9c fe 0c 07 00 fe 0c 05 00 25 20 01 00 00 00 58 fe 0e 05 00 fe 0c 0b 00 20 10 00 00 00 64 d2 9c fe 0c 07 00 fe 0c 05 00 25 20 01 00 00 00 58 fe 0e 05 00 fe 0c 0b 00 20 18 00 00 00 64 d2 9c fe 0c 02 00 fe 0c 0a 00 8f 40 00 00 01 25 4b fe 0c 0b 00 61 54 fe 0c 0a 00 20 01 00 00 00 58 fe 0e 0a 00 fe 0c 0a 00 20 10 00 00 00 3f 4c ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZSAA_2147923740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZSAA!MTB"
        threat_id = "2147923740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 00 02 73 ?? 01 00 0a 0c 00 08 07 16 73 ?? 01 00 0a 0d 02 8e 69 17 d6 8d ?? 00 00 01 13 04 09 11 04 16 11 04 8e 69 6f ?? 01 00 0a 13 05 12 04 11 05 28 ?? 00 00 2b 00 11 04 0a de 24}  //weight: 4, accuracy: Low
        $x_1_2 = "zdgdz.drzdezdszodzudrzdcedszd" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAAB_2147924328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAAB!MTB"
        threat_id = "2147924328"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 18 11 09 11 27 11 22 61 19 11 1c 58 61 11 2a 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_KAAC_2147924570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.KAAC!MTB"
        threat_id = "2147924570"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 1e 5a 1e 6f ?? 00 00 0a 0d 09 18 28 ?? 00 00 0a 13 04 07 08 11 04 03 08 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 08 17 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ATBA_2147924682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ATBA!MTB"
        threat_id = "2147924682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 16 2d 16 2b 16 2b 18 16 2b 18 8e 69 1b 2d 16 26 26 26 26 2b 17 2b 18 2b 1d de 48 11 04 2b e6 06 2b e5 06 2b e5 6f ?? 00 00 0a 2b e7 09 2b e6 6f ?? 00 00 0a 2b e1 13 05 2b df}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AGCA_2147925063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AGCA!MTB"
        threat_id = "2147925063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0c 12 02 28 ?? 00 00 0a 75 ?? 00 00 1b 0d 12 02 28 ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 06 07 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 09 16 09 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 28 ?? 00 00 0a 13 08 de 24}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBXV_2147925165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBXV!MTB"
        threat_id = "2147925165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "MrPr6GwrjFjMiBun1V.x2GySIb5hluvgrkFIl" wide //weight: 3
        $x_2_2 = {61 58 64 6b 70 00 72 31 35 79 73 41 41 54 6e 78 44}  //weight: 2, accuracy: High
        $x_1_3 = {52 65 76 65 72 73 65 00 6c 4b 78 46 48 50}  //weight: 1, accuracy: High
        $x_1_4 = "nverter_default.ex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AYA_2147925311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AYA!MTB"
        threat_id = "2147925311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BypassETW.pdb" ascii //weight: 2
        $x_1_2 = "$691e28a4-2c6f-4f81-b87c-773dc5d0434b" ascii //weight: 1
        $x_1_3 = "StartPatch" ascii //weight: 1
        $x_1_4 = "MemoryPatch" ascii //weight: 1
        $x_1_5 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SZCF_2147925528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SZCF!MTB"
        threat_id = "2147925528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {63 d1 13 15 11 1f 11 09 91 13 25 11 1f 11 09 11 25 11 27 61 11 1d 19 58 61 11 33 61 d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NO_2147925560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NO!MTB"
        threat_id = "2147925560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Koeken buizen sedert ton zes ons. Ik eigendom na verbruik algemeen speurzin de strooien" ascii //weight: 2
        $x_1_2 = "Honderden afstanden ze bestreken diezelfde ik. Vijand hen kan invoer pompen" ascii //weight: 1
        $x_1_3 = "Op voordat sneller er tinmijn tinerts ketting bijgang er. Trouwens zuiniger" ascii //weight: 1
        $x_1_4 = "Initiatief verwijderd regelmatig tembunmijn ze hollanders uitgevoerd al" ascii //weight: 1
        $x_1_5 = "Tunnel of zooals metaal gebied gerust is schors. Tot pogingen loopbaan mogelijk dit talrijke kapitaal mei zou" ascii //weight: 1
        $x_1_6 = "Of de dergelijke primitieve in verzekeren onderwoeld.Men men opgebracht zes ten goudmijnen inspanning" ascii //weight: 1
        $x_1_7 = "Generaal gesloten wij minerale verrezen upasboom vlijtige het met per" ascii //weight: 1
        $x_1_8 = "Zoon mei meer weer zij wier zin drie. Nu omwonden af beroemde afkoopen in bordeaux" ascii //weight: 1
        $x_1_9 = "Dit gayah far wordt rijst men tin goten wonde. Water are spijt zoo als zal stuit" ascii //weight: 1
        $x_1_10 = "Nu voeren geheel dragen in dieper de bekend de. Koopers elk zou hiertoe haalden ver voordat zij wolfram bestuur" ascii //weight: 1
        $x_1_11 = "Ontdaan bezocht planter schijnt na plantte moesten nu. Ingezameld zou dergelijke bergachtig woekeraars" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ANCA_2147925630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ANCA!MTB"
        threat_id = "2147925630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 72 4f 00 00 70 28 ?? 00 00 0a 72 81 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PMLH_2147925862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PMLH!MTB"
        threat_id = "2147925862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_9_1 = {06 2c 67 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 07 20 ?? ?? ?? ?? 61 0c 08 1f 10 63 20 ff 00 00 00 5f d2 0d}  //weight: 9, accuracy: Low
        $x_1_2 = {4c 00 6f 00 61 00 64 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PPH_2147926250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PPH!MTB"
        threat_id = "2147926250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 17 58 20 ff 00 00 00 5f 0c 11 04 06 08 95 58 20 ff 00 00 00 5f 13 04 02 06 08 8f 5c 00 00 01 06 11 04 8f 5c 00 00 01 28 ?? 00 00 06 06 08 95 06 11 04 95 58 20 ff 00 00 00 5f 13 0b 11 06 09 11 05 09 91 06 11 0b 95 61 d2 9c 09 17 58 0d 09 11 05 8e 69 32 aa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ASDA_2147926486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ASDA!MTB"
        threat_id = "2147926486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 bb 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 10 00 00 0a 13 04 11 04 09 17 73 24 00 00 0a 13 05 11 05 07 16 07 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AZDA_2147926627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AZDA!MTB"
        threat_id = "2147926627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 08 02 8e 69 5d 1f 6a 59 1f 6a 58 02 08 02 8e 69 5d 1e 58 1f 13 58 1f 1b 59 91 07 08 07 8e 69 5d 1d 58 1f 10 58 1f 18 59 1f 19 58 1f 18 59 91 61 02 08 20 0a 02 00 00 58 20 09 02 00 00 59 1e 59 1e 58 02 8e 69 5d 1f 09 58 1f 0d 58 1f 16 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PPKH_2147926945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PPKH!MTB"
        threat_id = "2147926945"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 10 62 0f ?? 28 ?? ?? ?? ?? 1e 62 60 0f 01 28 ?? ?? ?? ?? 60 0b 02 07 1f 10 63 20 ff 00 00 00 5f d2 6f ?? ?? ?? ?? 00 02 07 1e 63}  //weight: 5, accuracy: Low
        $x_6_2 = {9c 25 18 0f 01 28 ?? ?? ?? ?? 9c 0d 02 09 04 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 09 16 91 09 17 91 60}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBWB_2147926971_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBWB!MTB"
        threat_id = "2147926971"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 30 00 46 63 32 30 00 57 67 32 30 00 48 69 32 30 00 5f 4c 61 62 65 6c 32 30 00 4d 6f 32 30 00 45 71 32 30 00 54 73 32 30 00 57 73 32 30 00 52 74 32 30}  //weight: 4, accuracy: High
        $x_1_2 = {6e 30 4a 4e 00 6f 32 4a 4e 00 78 33 4a 4e 00 70 30 4b 4e 00 6f 35}  //weight: 1, accuracy: High
        $x_1_3 = "Qn2r9JSd70Ygx1DHm53Aie4Z6Fys8P6WpMt" ascii //weight: 1
        $x_1_4 = "6d84bc9f105c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SWR_2147927259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SWR!MTB"
        threat_id = "2147927259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "del /F /Q \"%destination%\" >NUL 2>&1" ascii //weight: 3
        $x_2_2 = "taskkill /F /IM \"%destination%\" >NUL 2>&1" ascii //weight: 2
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Heracles_GTT_2147927266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GTT!MTB"
        threat_id = "2147927266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 04 05 28 ?? ?? ?? 06 0a 0e 04 03 6f 9a 00 00 0a 59 0b 12 00 28 ?? ?? ?? 0a 0c 08 07 61 0c 03 06 07 28 ?? ?? ?? 06 00 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMCO_2147927389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMCO!MTB"
        threat_id = "2147927389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "UXJZhw`\\sXuXhhqU|?KV=}UP<kK};}kO>u~`Qv6u9YtTwo|;KZ]" wide //weight: 3
        $x_1_2 = {79 00 60 00 3f 00 59 00 39 00 3e 00 60 00 80 00 4c 00 39 00 54 00 5b 00 4c 00 5b 00 3f 00 74 00 58 00 38 00 3c}  //weight: 1, accuracy: High
        $x_1_3 = "X|lqXkrQnPtWJ<I>" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SCXF_2147927415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SCXF!MTB"
        threat_id = "2147927415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {91 07 11 06 07 8e 69 5d 91 61 07 11 06 07 8e 69 5d 91 61 07 11 06 07 8e 69 5d 91 61 d2 9c 11 06 17 58 13 06}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMZ_2147927683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMZ!MTB"
        threat_id = "2147927683"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 11 00 6f ?? 00 00 0a 11 00 6f ?? 00 00 0a 6f ?? 00 00 0a 13 01 38}  //weight: 3, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PQEH_2147927773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PQEH!MTB"
        threat_id = "2147927773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 72 01 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 20 03 00 00 00 38 04 00 00 00 fe 0c 07 00}  //weight: 3, accuracy: Low
        $x_2_2 = {26 20 01 00 00 00 38 88 ff ff ff 11 04 6f ?? ?? ?? ?? 13 01 20 00 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {11 01 11 08 16 11 08 8e 69 6f ?? ?? ?? ?? 13 06}  //weight: 2, accuracy: Low
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PQFH_2147927856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PQFH!MTB"
        threat_id = "2147927856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 17 58 0b 07 02 28 ?? ?? ?? ?? 3c b0 00 00 00 03 6f ?? ?? ?? ?? 04 3c a4 00 00 00 02 06 07 6f ?? ?? ?? ?? 0c 04 03 6f ?? ?? ?? ?? 59 0d 09 13 05 11 05}  //weight: 5, accuracy: Low
        $x_4_2 = {03 19 8d 63 00 00 01 25 16 12 02 28 ?? ?? ?? ?? 9c 25 17 12 02 28 ?? ?? ?? ?? 9c 25 18 12 02 28 ?? ?? ?? ?? 9c 09}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EA_2147928346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EA!MTB"
        threat_id = "2147928346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {12 07 28 04 00 00 06 26 16 13 08 2b 14 11 06 11 08 11 04 11 08 91 28 12 00 00 0a 11 08 17 58 13 08 11 08 11 04 8e 69 32 e4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AOGA_2147928498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AOGA!MTB"
        threat_id = "2147928498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 17 73 ?? 00 00 0a 13 06 2b 19 00 73 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 0a 1c 2c ed de 03 26 de 00 1e 2c 03 06 2c e1 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0a de 1b}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EANT_2147928696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EANT!MTB"
        threat_id = "2147928696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 72 a5 01 00 70 7e 1d 00 00 04 16 72 a5 01 00 70 28 6e 00 00 0a 6f 6f 00 00 0a 28 70 00 00 0a 28 71 00 00 0a 6f 72 00 00 0a 08 17 58 0c 08 07 31 ce}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EANT_2147928696_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EANT!MTB"
        threat_id = "2147928696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 72 a5 01 00 70 7e 1d 00 00 04 16 72 a5 01 00 70 28 6f 00 00 0a 6f 70 00 00 0a 28 71 00 00 0a 28 72 00 00 0a 6f 73 00 00 0a 00 00 08 17 58 0c 08 07 fe 02 16 fe 01 0d 09 2d c4}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SIK_2147928834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SIK!MTB"
        threat_id = "2147928834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 06 00 00 0a 6f 29 00 00 0a 11 05 28 2a 00 00 0a 13 06 7e 01 00 00 04 02 1e 58 11 06 16 11 04 1a 59 28 28 00 00 0a 11 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SOJ_2147928837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SOJ!MTB"
        threat_id = "2147928837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DataLogs_keylog_offline.txt" wide //weight: 1
        $x_1_2 = "C://Temp//1.log" wide //weight: 1
        $x_1_3 = "VenomRATByVenom" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AVHA_2147929654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AVHA!MTB"
        threat_id = "2147929654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 16 59 91 61 ?? 08 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 ?? 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SDID_2147930190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SDID!MTB"
        threat_id = "2147930190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 06 02 11 05 8f 1b 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AWIA_2147930845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AWIA!MTB"
        threat_id = "2147930845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 2d 19 72 ?? ?? 00 70 28 ?? 00 00 0a 0b 16 2d 0b 72 ?? ?? 00 70 28 ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 16 2d 06 2b 22 2b 23 2b 24 2b 29 2b 2a 1c 2d 2a 26 26 16 2d f4 2b 2a 2b 2b 06 16 06 8e 69 6f ?? 00 00 0a 13 04 de 37 09 2b db 07 2b da 6f ?? 00 00 0a 2b d5 09 2b d4 08 2b d3 6f ?? 00 00 0a 2b d1 09 2b d3 6f ?? 00 00 0a 2b ce}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAHO_2147930876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAHO!MTB"
        threat_id = "2147930876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1a 8d 08 00 00 01 0a 02 06 16 1a 6f 06 00 00 0a 26 06 16 28 09 00 00 0a 0b 07 8d 08 00 00 01 0c 16 0d 2b 0e 09 02 08 09 07 09 59 6f 06 00 00 0a 58 0d 09 07 32 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SPCB_2147931109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SPCB!MTB"
        threat_id = "2147931109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_NITA_2147931299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.NITA!MTB"
        threat_id = "2147931299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 8d 02 00 00 01 25 16 72 23 03 00 70 7e 06 00 00 04 72 55 03 00 70 28 02 00 00 0a a2 28 4f 00 00 0a 73 50 00 00 0a 25 72 87 03 00 70 6f 51 00 00 0a 25 72 bf 03 00 70 72 01 03 00 70 28 4d 00 00 0a 72 0b 03 00 70 28 02 00 00 0a 6f 52 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPPA_2147931382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPPA!MTB"
        threat_id = "2147931382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ZXNzKQ0KJGQuUmVhZCgkYiwgMCwgODM5" ascii //weight: 3
        $x_2_2 = "U51bGwNCltSZWZsZWN0aW9uLkFzc2VtYmx" ascii //weight: 2
        $x_1_3 = "CltzdHViLlByb2dyYW1dOjpNYWlu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBWQ_2147931795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBWQ!MTB"
        threat_id = "2147931795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 6f ?? 00 00 0a 02 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 0b 72 01 00 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ARAZ_2147933091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ARAZ!MTB"
        threat_id = "2147933091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 0d 09 17 59 17 36 12 2b 00 09 19 2e 02 2b 14 07 19}  //weight: 2, accuracy: High
        $x_2_2 = {16 0b 2b 10 00 04 06 07 91 6f ?? ?? ?? 0a 00 00 07 17 58 0b 07 03 fe 04 0c 08 2d e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SKEA_2147934075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SKEA!MTB"
        threat_id = "2147934075"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 08 11 07 11 05 11 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 09 11 09 06 16 06 8e 69 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 13 0a de 3e}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ADMA_2147934152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ADMA!MTB"
        threat_id = "2147934152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f ?? 00 00 0a 2b dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAC_2147934267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAC!MTB"
        threat_id = "2147934267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {02 8e 69 8d 05 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AIMA_2147934485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AIMA!MTB"
        threat_id = "2147934485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 1b 58 1b 59 91 61 03 08 20 10 02 00 00 58 20 0f 02 00 00 59 19 59 19 58 03 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SEDA_2147934866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SEDA!MTB"
        threat_id = "2147934866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 01 00 0a 11}  //weight: 3, accuracy: Low
        $x_2_2 = {58 12 02 28 ?? 00 00 0a 58 20 88 13 00 00 5d 20 e8 03 00 00 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SEDA_2147934866_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SEDA!MTB"
        threat_id = "2147934866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00}  //weight: 3, accuracy: Low
        $x_1_2 = {09 1b 5a 11 08 19 5a 58 20 f4 01 00 00 5d 20 c8 00 00 00 58 13 09 11 08 1f 1e 5d 1f 0a 58 13 0a 09 1f 28 5d 1b 58 13 0b 02 09 11 08 6f ?? 00 00 0a 13 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_STI_2147935240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.STI!MTB"
        threat_id = "2147935240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1a 28 01 00 00 0a 72 ?? ?? ?? 70 28 02 00 00 0a 0a 06 72 ?? ?? ?? 70 28 02 00 00 0a 0b 73 03 00 00 0a 25 72 2f 00 00 70 6f 04 00 00 0a 25 72 ?? ?? ?? 70 6f 05 00 00 0a 25 17 6f 06 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAOE_2147935736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAOE!MTB"
        threat_id = "2147935736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 28 06 00 00 0a 06 6f 07 00 00 0a 28 08 00 00 0a 28 09 00 00 0a 0b 07 72 01 00 00 70 6f 0a 00 00 0a 0c 08 17 8d 10 00 00 01 13 04 11 04 16 d0 11 00 00 01 28 0b 00 00 0a a2 11 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAFL_2147936232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAFL!MTB"
        threat_id = "2147936232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 08 91 66 d2 0d 07 08 09 19 63 09 1b 62 60 d2 9c 00 08 17 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d dd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAEJ_2147936235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAEJ!MTB"
        threat_id = "2147936235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0a 17 0b 2b 08 06 07 58 0a 07 17 58 0b 07 1f 0a 31 f3 06 1f 0a 5b 26 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SEI_2147936790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SEI!MTB"
        threat_id = "2147936790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 13 01 00 70 6f 0e 00 00 06 6f 29 00 00 06 72 1f 01 00 70 6f 10 00 00 06 09 6f 17 00 00 06 16 6f 05 00 00 06 74 05 00 00 02 25 72 2d 01 00 70 6f 08 00 00 06 72 43 01 00 70 6f 0a 00 00 06 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAKR_2147937250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAKR!MTB"
        threat_id = "2147937250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 07 07 61 07 61 03 04 28 0a 00 00 06 00 07 17 58 0b 07 06 2f 0b 03 6f 4e 00 00 0a 04 fe 04 2b 01 16 0c 08 2d da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AOPA_2147937354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AOPA!MTB"
        threat_id = "2147937354"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 06 6f ?? 00 00 0a 00 07 06 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 2b 00 11 04}  //weight: 4, accuracy: Low
        $x_2_2 = "41 2 47 101 3 95 115 5 130 117 1 115 109 3 103 101 5 116 42 2 48 52 4 64 57 6 75 101 1 101 97 3 91 50 4 62" wide //weight: 2
        $x_2_3 = "43 2 49 105 3 103 57 4 69 58 6 76 117 1 115 97 3 91 54 4 66 65 5 80 54 2 60 54 4 66 111 5 126 99 1 97 69 3 63 60 4 72" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EAED_2147937890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EAED!MTB"
        threat_id = "2147937890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 06 02 28 45 00 00 06 06 02 28 45 00 00 06 8e 69 5d 91 03 06 91 61 d2 9c 06 17 58 0a 06 03 8e 69 32 dd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAD_2147938454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAD!MTB"
        threat_id = "2147938454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 8e 69 8d 04 00 00 01 0a 03 8e 69 0b 16 0c 2b 11 06 08 02 08 91 03 08 07 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e9 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SGDA_2147938957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SGDA!MTB"
        threat_id = "2147938957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 06 6f 14 00 00 0a 06 6f 15 00 00 0a 6f 16 00 00 0a 0b 73 17 00 00 0a 0c 20 ?? ?? ?? 00 8d 15 00 00 01 25 d0 04 00 00 04 28 18 00 00 0a 73 19 00 00 0a 0d 09 07 16 73 1a 00 00 0a 13 04 1f 10 8d 15 00 00 01 13 05 38 0b 00 00 00 08 11 05 16 11 06 6f 1b 00 00 0a 11 04 11 05 16 11 05 8e 69 6f 1c 00 00 0a 25 13 06 16 3d de ff ff ff}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SWA_2147939093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SWA!MTB"
        threat_id = "2147939093"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 a3 25 00 00 01 0c 08 6f 41 01 00 0a 72 48 1a 00 70 28 b5 00 00 0a 2c 14 08 72 94 1a 00 70 20 00 01 00 00 14 14 14 6f 42 01 00 0a 26 07 17 58 0b 07 06 8e 69 32 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AGRA_2147939280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AGRA!MTB"
        threat_id = "2147939280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 2b 36 8d ?? 00 00 01 2b 32 16 2b 33 2b 1c 2b 33 2b 34 2b 36 08 11 05 59 6f ?? 00 00 0a 13 06 11 06 2c 0c 11 05 11 06 58 13 05 11 05 08 32 df 1b 2c ed 11 04 13 07 de 36 08 2b c7 13 04 2b ca 13 05 2b c9 09 2b ca 11 04 2b c8 11 05 2b c6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZLW_2147940412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZLW!MTB"
        threat_id = "2147940412"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 16 06 8e 69 6f ?? 00 00 0a 0c de 47 07 2b d5 28 ?? 01 00 0a 2b d5 6f ?? 01 00 0a 2b d0 07 2b cf 28 ?? 01 00 0a 2b cf 6f ?? 01 00 0a 2b ca 07 2b cc 6f ?? 01 00 0a 2b c7}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SWT_2147940667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SWT!MTB"
        threat_id = "2147940667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 09 00 00 70 28 02 00 00 06 de 03 26 de 00 20 b8 0b 00 00 28 05 00 00 0a 1f ?? 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a 28 08 00 00 0a 1f 23 28 06 00 00 0a 72 ?? 00 00 70 28 07 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SHO_2147940775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SHO!MTB"
        threat_id = "2147940775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 15 00 00 0a 72 8e 01 00 70 28 16 00 00 0a 6f 17 00 00 0a 28 18 00 00 0a 0b 00 28 15 00 00 0a 72 a8 01 00 70 28 16 00 00 0a 6f 17 00 00 0a 0c 73 23 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MBZ_2147940853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MBZ!MTB"
        threat_id = "2147940853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2c 05 16 13 04 de 32 07 08 03 03 8e 69 12 03}  //weight: 2, accuracy: High
        $x_1_2 = "CreateRemoteThread" ascii //weight: 1
        $x_1_3 = "Corrupted payload" ascii //weight: 1
        $x_1_4 = "WaffleDecode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GPAL_2147940925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GPAL!MTB"
        threat_id = "2147940925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "apstori.ru/panel/uploads/" ascii //weight: 4
        $x_1_2 = "CompressedBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SLH_2147941422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SLH!MTB"
        threat_id = "2147941422"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 07 08 6f 29 00 00 06 16 6a 0d 16 13 06 2b 1d 06 6f 2f 00 00 0a 13 07 09 11 07 d2 6e 1e 11 06 5a 1f 3f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SLL_2147941722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SLL!MTB"
        threat_id = "2147941722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 28 07 00 00 0a 25 14 28 08 00 00 0a 39 06 00 00 00 73 06 00 00 0a 7a 72 01 00 00 70 6f 09 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AFVA_2147942205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AFVA!MTB"
        threat_id = "2147942205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 1b 58 1b 59 91 07 08 07 8e 69 5d 1c 58 1b 59 17 59 91 61 03 08 1c 58 1b 59 03 8e 69 5d 1c 58 1b 59 17 59 91 59 20 fc 00 00 00 58 1a 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AIVA_2147942268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AIVA!MTB"
        threat_id = "2147942268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 11 06 72 ?? ?? 00 70 03 28 ?? ?? 00 06 05 72 ?? ?? 00 70 6f ?? 00 00 0a 17 0b dd ?? 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PRE_2147942524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PRE!MTB"
        threat_id = "2147942524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 11 04 28 a1 00 00 0a 20 e6 3a 5d b5 28 4d 00 00 0a 6f ?? 00 00 0a 6f ?? 02 00 0a 11 04 1f 10 8d 07 00 00 01 6f ?? 02 00 0a 11 04 17 6f ?? 02 00 0a 73 5d 02 00 0a 13 05 11 05 11 04 6f ?? 02 00 0a 17 73 89 02 00 0a 13 06 11 06 09 16 09 8e 69 6f c6 00 00 0a 11 06 6f 8a 02 00 0a 11 05 6f 2f 01 00 0a 0d 11 05 6f 8b 02 00 0a 11 06 6f 8b 02 00 0a 73 5d 02 00 0a 13 07 09 73 02 01 00 0a 16 73 8c 02 00 0a 13 0b 20 00 04 00 00 13 0c 11 0c 8d 07 00 00 01 13 0e 11 0b 11 0e 16 11 0c 6f ?? 01 00 0a 13 0d 2b 1a 11 07 11 0e 16 11 0d 6f ?? 00 00 0a 11 0b 11 0e 16 11 0c 6f ?? 01 00 0a 13 0d 11 0d 16 30 e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MCB_2147942756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MCB!MTB"
        threat_id = "2147942756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "_PECHHNNQ" ascii //weight: 3
        $x_3_2 = "FDYOMMAG" ascii //weight: 3
        $x_3_3 = "System.Threading.Thread" ascii //weight: 3
        $x_3_4 = "A9319798" ascii //weight: 3
        $x_2_5 = {53 00 75 00 62 00 73 00 74 00 72 00 69 00 6e 00 67}  //weight: 2, accuracy: High
        $x_2_6 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 43 00 6f 00 6e 00 76 00 65 00 72 00 74}  //weight: 2, accuracy: High
        $x_2_7 = {49 00 6e 00 76 00 6f 00 6b 00 65}  //weight: 2, accuracy: High
        $x_2_8 = {53 00 70 00 6c 00 69 00 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZJT_2147943340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZJT!MTB"
        threat_id = "2147943340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {02 07 8f 27 00 00 01 25 47 03 07 03 8e 69 5d 91 61 d2 52 16 0c 2b 1a 00 02 07 02 07 91 03 08 91 06 1f 1f 5f 62 08 61 07 58 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d dc}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMWA_2147943492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMWA!MTB"
        threat_id = "2147943492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 17 17 28 ?? 00 00 0a 5a 06 17 16 28 ?? 00 00 0a 26 16 58 06 17 18 28 ?? 00 00 0a 26 16 58 13 21 1b 8d ?? 00 00 01 25 16 72 ?? ?? 00 70 a2 25 17 12 17 28 ?? 00 00 0a a2 25 18 72 ?? ?? 00 70 a2 25 19 12 21 28 ?? 00 00 0a a2 25 1a 72 ?? ?? 00 70 a2 28}  //weight: 5, accuracy: Low
        $x_2_2 = {19 8d 78 00 00 01 25 16 11 25 9c 25 17 11 26 9c 25 18 11 27 9c 13 32 11 3e}  //weight: 2, accuracy: High
        $x_2_3 = {1b 8d 75 00 00 01 25 16 12 25 28 ?? 00 00 0a a2 25 17 72 ?? ?? 00 70 a2 25 18 12 26 28 ?? 00 00 0a a2 25 19 72 ?? ?? 00 70 a2 25 1a 12 27 28 ?? 00 00 0a a2 28 ?? 00 00 06 13 28 11 28 28 ?? 00 00 06 13 29 11 3e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SLCD_2147943696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SLCD!MTB"
        threat_id = "2147943696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 6f 29 00 00 0a 25 26 0c 1f 61 6a 08 28 41 00 00 06 25 26 0d 09 28 2a 00 00 0a 25 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZCS_2147944168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZCS!MTB"
        threat_id = "2147944168"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 2a 72 01 00 00 70 28 ?? 00 00 0a 13 00 38 19 01 00 00 28 ?? 00 00 0a 13 02 38 00 00 00 00 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 0e 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 1c 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 01}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ACXA_2147944261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ACXA!MTB"
        threat_id = "2147944261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 02 11 03 11 00 11 03 91 11 01 11 03 11 01 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 5, accuracy: Low
        $x_2_2 = {11 03 17 58 13 03 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_APXA_2147944589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.APXA!MTB"
        threat_id = "2147944589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 1f 3c 28 ?? 00 00 0a 13 08 03 11 08 1f 34 58 28 ?? 00 00 0a 13 09 20 b3 00 00 00 8d ?? 00 00 01 13 0a 16 13 0b 2b 0f 11 0a 11 0b 11 0b 06 61 9e 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 32 e9 11 0a 16 20 02 00 01 00 9e 28 ?? 00 00 0a 1a 33 1b}  //weight: 4, accuracy: Low
        $x_2_2 = {03 11 12 1f 0c 58 28 ?? 00 00 0a 13 16 03 11 12 1f 10 58 28 ?? 00 00 0a 13 17 03 11 12 1f 14 58 28 ?? 00 00 0a 13 18 11 17 2c 3e 11 17 8d ?? 00 00 01 13 19 03 11 18 11 19 16 11 19 8e 69 28 ?? 00 00 0a 7e ?? 00 00 04 12 07 7b ?? 00 00 04 11 11 11 16 58 11 19 11 19 8e 69 12 05 6f ?? 00 00 06 2d 06 73 ?? 00 00 0a 7a 11 12 1f 28 58 13 12 11 15 17 58 13 15 11 15 11 13 32 84}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ASXA_2147944664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ASXA!MTB"
        threat_id = "2147944664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 11 11 1f 0c 58 28 ?? 00 00 0a 13 14 03 11 11 1f 10 58 28 ?? 00 00 0a 13 15 03 11 11 1f 14 58 28 ?? 00 00 0a 13 16 11 15 2c 3e 11 15 8d ?? 00 00 01 13 17 03 11 16 11 17 16 11 17 8e 69 28 ?? 00 00 0a 7e ?? 00 00 04 12 07 7b ?? 00 00 04 11 10 11 14 58 11 17 11 17 8e 69 12 05 6f ?? 00 00 06 2d 06 73 ?? 00 00 0a 7a 11 11 1f 28 58 13 11 11 13 17 58 13 13 11 13 11 12 32 84}  //weight: 4, accuracy: Low
        $x_2_2 = {03 1f 3c 28 ?? 00 00 0a 13 08 03 11 08 1f 34 58 28 ?? 00 00 0a 13 09 20 b3 00 00 00 8d ?? 00 00 01 13 0a 11 0a 16 20 02 00 01 00 9e 28 ?? 00 00 0a 1a 33 1b 7e ?? 00 00 04 12 07 7b ?? 00 00 04 11 0a 6f ?? 00 00 06 2d 21}  //weight: 2, accuracy: Low
        $x_1_3 = "a2VybmVsMzI=" wide //weight: 1
        $x_1_4 = "VmlydHVhbEFsbG9jRXg=" wide //weight: 1
        $x_1_5 = "Q3JlYXRlUHJvY2Vzc0E=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AE_2147944988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AE!MTB"
        threat_id = "2147944988"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 0c 06 07 02 07 91 08 61 07 1f 28 28 24 00 00 06 5a 1f 2c 28 24 00 00 06 5f 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EOXE_2147945210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EOXE!MTB"
        threat_id = "2147945210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 02 08 91 03 08 07 5d ?? ?? ?? ?? ?? 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GVA_2147945397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GVA!MTB"
        threat_id = "2147945397"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 18 5d 2c 04 02 ?? ?? 2a 02 18 58 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {02 18 5d 2c 04 02 18 5a 2a 02 18 5b 2a}  //weight: 2, accuracy: High
        $x_2_3 = {02 03 5a 03 2c 03 03 2b 01 17 5b 2a}  //weight: 2, accuracy: High
        $x_2_4 = {03 17 31 0d 03 6a 02 03 17 59 28 ?? ?? ?? ?? 5a 2a 17 6a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Heracles_A_2147945964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.A!MTB"
        threat_id = "2147945964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 13 08 11 0d 20 ea 3e 8b f7 5a 20 95 f0 0e 96 61 38 09 ff ff ff 11 07 1f 0e 11 07 1f 0e 95 09 1f 0e 95 61}  //weight: 2, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SLYO_2147946814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SLYO!MTB"
        threat_id = "2147946814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 16 9a 28 1b 00 00 06 0a 02 7b ?? 00 00 04 26 02 06 28 14 00 00 06 02 7b ?? 00 00 04 26 02 02 7b ?? 00 00 04 2d 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZAQ_2147947265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZAQ!MTB"
        threat_id = "2147947265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 06 28 ?? 00 00 0a 07 28 ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 02 28 ?? 00 00 06 75 ?? 00 00 1b 13 06 11 05 11 06 16 11 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 07 de 22}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_EHHK_2147947295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.EHHK!MTB"
        threat_id = "2147947295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 40 07 09 0f 02 ?? ?? ?? ?? ?? 05 0e 04 09 6b 06 5a 58 6c ?? ?? ?? ?? ?? 6b 5a 58 0f 02 ?? ?? ?? ?? ?? 05 0e 04 09 6b 06 5a 58 6c ?? ?? ?? ?? ?? 6b 5a 58 73 2b 00 00 0a a4 15 00 00 01 09 17 58 0d 09 19 32 bc}  //weight: 2, accuracy: Low
        $x_2_2 = {1f 19 18 11 04 5a 59 13 05 11 05 20 ff 00 00 00 16 16 ?? ?? ?? ?? ?? 73 32 00 00 0a 13 06 05 11 04 18 5a 6b 58 13 07 03 11 06 0f 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZDQ_2147947383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZDQ!MTB"
        threat_id = "2147947383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 02 16 28 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 03 16 3c ?? ff ff ff 38 ?? ff ff ff 11 00 11 02 16 1a 6f ?? 00 00 0a 1a 3b ?? ff ff ff 38 ?? ff ff ff 00 20 00 10 00 00 8d ?? 00 00 01 13 05}  //weight: 6, accuracy: Low
        $x_4_2 = {11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d ?? 00 00 00 38 ?? 00 00 00 38 ?? ff ff ff 38 ?? 00 00 00 11 01 11 05 16 11 06 6f ?? 00 00 0a 38}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GVB_2147947416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GVB!MTB"
        threat_id = "2147947416"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 28 5a 00 00 0a 02 7b 11 01 00 04 6f 84 04 00 06 2d 22 02 7b 11 01 00 04 28 da 03 00 06 80 f5 00 00 04 02 28 08 03 00 06 02 7b 11 01 00 04 17 6f 85 04 00 06 de 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SLYP_2147947478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SLYP!MTB"
        threat_id = "2147947478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 16 9a 28 1b 00 00 06 0a 02 7b ?? 00 00 04 26 02 06 28 15 00 00 06 02 02 7b ?? 00 00 04 2d 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZGQ_2147947598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZGQ!MTB"
        threat_id = "2147947598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 02 16 28 ?? 00 00 0a 13 03 38 ?? 00 00 00 11 03 16 3c ?? 00 00 00 38 ?? 00 00 00 11 00 11 02 16 1a 6f ?? 00 00 0a 1a 3b d3}  //weight: 6, accuracy: Low
        $x_5_2 = {11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d ?? 00 00 00 38 ?? 00 00 00 11 01 11 05 16 11 06 6f ?? 00 00 0a 38 d3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZKQ_2147947862_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZKQ!MTB"
        threat_id = "2147947862"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {7a 11 0a 16 28 ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 02 00 00 00 38 ?? ff ff ff 00 20 00 10 00 00 8d ?? 00 00 01 13 05}  //weight: 6, accuracy: Low
        $x_5_2 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 ?? 00 00 00 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_ZRQ_2147948111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.ZRQ!MTB"
        threat_id = "2147948111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 26 0b 20 0a 16 0a 00 28 ?? 00 00 06 28 ?? 00 00 0a 25 26 0c 28 ?? 00 00 0a 25 26 0d 00 09 07 6f ?? 00 00 0a 00 09 08 6f ?? 00 00 0a 00 09 1f 0c 28 ?? 00 00 06 6f ?? 00 00 0a 00 09 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 00 11 04 06 1f 14 28 ?? 00 00 06 06 8e 69 6f ?? 00 00 0a 25 26 13 05 de 63}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_AMX_2147948874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.AMX!MTB"
        threat_id = "2147948874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 03 11 04 6f 3d 00 00 0a 6f 3e 00 00 0a 11 04 17 58 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_GTB_2147948940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.GTB!MTB"
        threat_id = "2147948940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 11 04 61 19 5d 17 33 18 07 1f 41 11 04 58 d1 13 1d 12 1d 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 2b 10 08 11 04 6c 23 ?? ?? ?? ?? ?? ?? ?? ?? 5a 58 0c 11 04 17 58 13 04 11 04 1a 32 c4 06 1f 2a 61 0a 16 13 05 12 06}  //weight: 10, accuracy: Low
        $x_1_2 = "VmlydHVhbEFsbG9jRXg=" ascii //weight: 1
        $x_1_3 = "UmVhZFByb2Nlc3NNZW1vcnk=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_HB_2147949003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.HB!MTB"
        threat_id = "2147949003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 02 20 00 01 00 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 0e 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 0e 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 e4 ff ff ff 00 02 73 13 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 19 00 00 0a 13 05 38 00 00 00 00 00 73 0a 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07}  //weight: 4, accuracy: Low
        $x_2_2 = {11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d ?? 00 00 00 38 [0-20] 11 01 11 05 16 11 06 6f ?? 00 00 0a 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PPN_2147949670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PPN!MTB"
        threat_id = "2147949670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 02 38 03 00 00 00 11 07 2a 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 0e 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 0e 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 e4 ff ff ff 11 02 6f ?? 00 00 0a 13 03 38 00 00 00 00 00 02 73 0b 00 00 0a}  //weight: 3, accuracy: Low
        $x_3_2 = {13 04 38 00 00 00 00 00 11 04 11 03 16 73 19 00 00 0a 13 05 38 00 00 00 00 00 73 0c 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07 38}  //weight: 3, accuracy: Low
        $x_2_3 = {11 01 11 05 16 11 06 6f ?? 00 00 0a 38 0a 00 00 00 38 05 00 00 00 38 e5 ff ff ff 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 25 13 06 16 3d ce ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PCW_2147949784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PCW!MTB"
        threat_id = "2147949784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 08 74 07 00 00 1b 17 7e 0e 00 00 04 a2 08 74 07 00 00 1b 18 1f 17 20 ef 77 38 35 17 28 fd 00 00 06 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_MZB_2147951018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.MZB!MTB"
        threat_id = "2147951018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 61 2b ?? 08 17 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 20 cd ff d6 c3 13 0b 11 08 20 4e fb f6 ff 5a 11 0b 61 38 6b ff ff ff 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 20 87 3b ec ab 13 0c 11 08 20 b6 19 f7 ff 5a 11 0c 61 38 41 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_BAH_2147951027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.BAH!MTB"
        threat_id = "2147951027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 20 a5 00 00 00 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_PPCB_2147951171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.PPCB!MTB"
        threat_id = "2147951171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0b 2b 20 02 07 6f b6 00 00 0a 03 07 03 6f b5 00 00 0a 5d 6f b6 00 00 0a 61 0c 06 07 08 d2 9c 07 17 58 0b 07 02 6f b5 00 00 0a 32 d7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Heracles_SM_2147951292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Heracles.SM!MTB"
        threat_id = "2147951292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Heracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {04 6f 2a 00 00 06 04 6f 2c 00 00 06 17 16 6f 10 00 00 0a 04 6f 2e 00 00 06 1f 38 6f 11 00 00 0a 25 14}  //weight: 10, accuracy: High
        $x_5_2 = {02 20 00 00 00 01 7d 21 00 00 04 38 00 00 00 00 02 1a 7d 22 00 00 04 38 00 00 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

