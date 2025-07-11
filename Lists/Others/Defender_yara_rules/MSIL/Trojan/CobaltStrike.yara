rule Trojan_MSIL_CobaltStrike_SB_2147781181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.SB!MTB"
        threat_id = "2147781181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0x48, 0x6f, 0x73, 0x74, 0x3a, 0x20, 0x73, 0x74, 0x61, 0x74, 0x69, 0x63" wide //weight: 1
        $x_1_2 = "0x2e, 0x74, 0x76, 0x2e, 0x73, 0x6f, 0x68, 0x75, 0x2e, 0x63, 0x6f, 0x6d" wide //weight: 1
        $x_1_3 = "0x31,0x31, 0x32, 0x34, 0x62, 0x2e, 0x6d, 0x69, 0x6e, 0x2e, 0x6a, 0x73," wide //weight: 1
        $x_1_4 = "0x61, 0x6c, 0x69, 0x63, 0x64, 0x6e" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_CobaltStrike_STR_2147808926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.STR!MTB"
        threat_id = "2147808926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_2 = "WebServices" ascii //weight: 1
        $x_1_3 = "ContainsKey" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
        $x_1_5 = "get_ResourceManager" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "$0ceb3a27-1cf9-4510-86d1-2ac97f66e38e" ascii //weight: 1
        $x_1_8 = "MJwUgcokQv" ascii //weight: 1
        $x_1_9 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_10 = "pokemon_Load" ascii //weight: 1
        $x_1_11 = "ToCharArray" ascii //weight: 1
        $x_1_12 = "Array" ascii //weight: 1
        $x_1_13 = "Reverse" ascii //weight: 1
        $x_1_14 = "Convert" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_PJ_2147817138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.PJ!MTB"
        threat_id = "2147817138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DASDSADSADSADASDAS" wide //weight: 1
        $x_1_2 = {08 94 9e 11 ?? 08 11 ?? 9e 11 ?? 11 ?? 06 94 11 ?? 08 94 58 20 00 01 00 00 5d 94 0d 11 ?? 07 03 07 91 09 61 d2 9c 00 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_PP_2147817773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.PP!MTB"
        threat_id = "2147817773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-48] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "sdafasfwqfwqfgdfsfsdgds" wide //weight: 1
        $x_1_3 = "\\HRM_SUB\\HRM_SUB\\img\\User Photo\\default.png" wide //weight: 1
        $x_1_4 = {5c 53 4c 4e 5c 48 52 4d 5f 53 55 42 5c [0-32] 5c 48 52 4d 5f 53 55 42 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_PC_2147823636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.PC!MTB"
        threat_id = "2147823636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 09 94 58 20 00 01 00 00 5d 94 13 04 11 08 08 ?? 08 91 11 04 61 d2 9c 00 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_AG_2147824172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.AG!MSR"
        threat_id = "2147824172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UwBlAHQALQBTAHQAcgBpAGMAdABNAG8AZABlACAALQBWAGUAcgBzAGkAbwBuACAAMgAKAG" ascii //weight: 2
        $x_2_2 = "dAByAHkAIAB7AA0ACgAgACAAaQBmACAAKABbAEUAbgB2AGkAcgBvAG4AbQBlAG4AdABdAD" ascii //weight: 2
        $x_1_3 = "set_UseShellExecute" ascii //weight: 1
        $x_1_4 = "set-item -path \"function:global:" ascii //weight: 1
        $x_1_5 = "Aborting..." ascii //weight: 1
        $x_1_6 = "$x='{0}';$y='{1}';" ascii //weight: 1
        $x_1_7 = "-sta -noprofile -executionpolicy bypass -encodedcommand" ascii //weight: 1
        $x_1_8 = "Press any key..." ascii //weight: 1
        $x_1_9 = "Unable to launch application:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ST_2147827153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ST!MTB"
        threat_id = "2147827153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://144.48.240.85/18.exe" ascii //weight: 1
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "get_Password" ascii //weight: 1
        $x_1_4 = "set_Password" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "SeedData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_SS_2147829969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.SS!MTB"
        threat_id = "2147829969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 a8 9a b2 71 a8 e2 b2 71 a8 da b2 71 88 aa b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ABHM_2147838443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ABHM!MTB"
        threat_id = "2147838443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 06 09 06 9a 1f 10 28 ?? ?? ?? 0a 9c 06 17 d6 0a 06 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d e1}  //weight: 4, accuracy: Low
        $x_1_2 = "PolicyPlus.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_RDC_2147843065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.RDC!MTB"
        threat_id = "2147843065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0b 91 13 0c 7e ?? ?? ?? ?? 11 0b 11 0c 07 59 d2 9c 06 7e ?? ?? ?? ?? 11 0b 91 6f ?? ?? ?? ?? 11 0b 17 58 13 0b 11 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_CSZ_2147845016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.CSZ!MTB"
        threat_id = "2147845016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 07 08 9a 1f 10 28 19 00 00 0a 9c 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d}  //weight: 1, accuracy: High
        $x_1_2 = "VirtualProtectEx [Set to 0x40 (RWX mode)" wide //weight: 1
        $x_1_3 = "NativePayload_PE2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_AST_2147845474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.AST!MTB"
        threat_id = "2147845474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 11 00 00 0a 0c 00 73 12 00 00 0a 0d 00 09 20 00 01 00 00 6f 13 00 00 0a 00 09 20 80 00 00 00 6f 14 00 00 0a 00 04 07 20 e8 03 00 00 73 15 00 00 0a 13 04 09 11 04 09 6f 16 00 00 0a 1e 5b 6f 17 00 00 0a 6f 18 00 00 0a 00 09 11 04 09 6f 19 00 00 0a 1e 5b 6f 17 00 00 0a 6f 1a 00 00 0a 00 09 17 6f 1b 00 00 0a 00 09 18 6f 1c 00 00 0a 00 08 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_NCB_2147845664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.NCB!MTB"
        threat_id = "2147845664"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 80 00 00 0a 20 ?? ?? ?? 00 28 ?? ?? ?? 06 20 ?? ?? ?? 00 14 14 18 8d ?? ?? ?? 01 25 16 11 02 17 8d ?? ?? ?? 01 25 16 11 04 8c ?? ?? ?? 01 a2 14 28 ?? ?? ?? 0a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "1yoXqE7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZD_2147846516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZD!MTB"
        threat_id = "2147846516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "JGZpbGVQYXRoID0gIkM6XFVzZXJzXFB1YmxpY1xNdXNpY1wiDQo" wide //weight: 2
        $x_2_2 = "LUV4ZWN1dGlvblBvbGljeSBCeXBhc3MgLUZpbGUgJGRvd25sb2FkUGF0aCINClN0YXJ0LVByb2Nlc3MgImNtZCIgLUF" wide //weight: 2
        $x_2_3 = "yZ3VtZW50TGlzdCAiL2MgJGJhdGNoRmlsZSIgLVdhaXQgLVdpbmRvd1N0eWxlIEhpZGRlbg" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZG_2147847915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZG!MTB"
        threat_id = "2147847915"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 28 13 00 00 0a 03 6f ?? ?? ?? 0a 0a 7e ?? ?? ?? 04 0b 02 28 ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 73 ?? ?? ?? 0a 13 04 11 04 09 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 05 11 05 08 16 08 8e 69 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 06 dd ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = "EncryptionKey" ascii //weight: 1
        $x_1_3 = "RunScript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MAAL_2147848046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MAAL!MTB"
        threat_id = "2147848046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 13 0e 11 0e 07 8e 69 32 de}  //weight: 1, accuracy: High
        $x_1_2 = {16 13 0e 2b 1b 07 11 0e 8f 35 00 00 01 25 47 06 11 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MB_2147848083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MB!MTB"
        threat_id = "2147848083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 40 28 02 00 00 06 0b 06 16 07 06 8e 69 28 09 00 00 0a 07 d0 03 00 00 02 28 0a 00 00 0a 28 0b 00 00 0a 75 03 00 00 02 0c 08 6f 0c 00 00 06 26 de 0e 07 16 20 00 80 00 00 28 03 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MB_2147848083_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MB!MTB"
        threat_id = "2147848083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 04 11 0a 9a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 0a 17 d6 13 0a 11 0a 11 09 31 df}  //weight: 2, accuracy: Low
        $x_2_2 = {da 04 d6 1f 1a 5d 13 07 07 11 06 28 ?? ?? ?? 0a 11 07 d6}  //weight: 2, accuracy: Low
        $x_2_3 = "PoolAndSpaDepot.My.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_C_2147849813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.C!MTB"
        threat_id = "2147849813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 08 07 02 09 6f ?? 00 00 0a 28 ?? 00 00 0a 1f ?? 59 94 1a 62 07 02 09 17 58}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 0a 0b 07 d4 8d ?? 00 00 01 0c 06 08 16 07 69 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_CXF_2147851173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.CXF!MTB"
        threat_id = "2147851173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 00 70 00 69 00 2e 00 67 00 6f 00 67 00 6c 00 65 00 61 00 70 00 69 00 2e 00 63 00 6c 00 69 00 63 00 6b 00 2f 00 66 00 69 00 6c 00 65 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d}  //weight: 1, accuracy: High
        $x_1_2 = "api.gogleapi.click/file/System/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_CobaltStrike_CXIQ_2147888280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.CXIQ!MTB"
        threat_id = "2147888280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 08 8f ?? ?? ?? ?? 25 47 11 07 16 91 61 d2 52 00 11 08 17 58 13 08 11 08 11 06 8e 69 fe 04 13 09 11 09 2d d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_AAMI_2147888655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.AAMI!MTB"
        threat_id = "2147888655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 25 17 6f ?? 00 00 0a 00 25 18 6f ?? 00 00 0a 00 0d 09 6f ?? 00 00 0a 13 04 11 04 08 16 08 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 0a de 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ACO_2147892466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ACO!MTB"
        threat_id = "2147892466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 06 16 09 06 8e 69 28 13 00 00 0a 00 09 16 16 28 03 00 00 06 13 04 11 04 08 7e 12 00 00 0a 28 04 00 00 06 00 08 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MBJP_2147892497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MBJP!MTB"
        threat_id = "2147892497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58 13 0e 11 0e 07 8e 69 32 de}  //weight: 1, accuracy: High
        $x_1_2 = "$3e7538e0-56e8-1c35-a985-d9061381b4d8" ascii //weight: 1
        $x_1_3 = "ConsoleApp1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ASEQ_2147892965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ASEQ!MTB"
        threat_id = "2147892965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 7a 02 28 ?? 00 00 0a 0a 73 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 04 6f ?? 00 00 0a 6f ?? 00 00 0a 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 07 17 6f ?? 00 00 0a 07 18 6f ?? 00 00 0a 07 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0c de}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 06 07 28 ?? 00 00 06 0c 08 25 13 04 2c 06 11 04 8e 69 2d 05 16 e0 0d 2b 0a 11 04 16 8f ?? 00 00 01 e0 0d 09 28 ?? 00 00 0a 25 08 8e 69 6a 28 ?? 00 00 0a 1f 40 12 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZL_2147893322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZL!MTB"
        threat_id = "2147893322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 08 8f 0f 00 00 01 25 71 ?? ?? ?? 01 20 ?? ?? ?? 00 61 d2 81 ?? ?? ?? 01 00 08 17 58 0c 08 07 8e 69 fe 04 13 06 11 06 2d d5}  //weight: 1, accuracy: Low
        $x_1_2 = "VirtualAllocEx" ascii //weight: 1
        $x_1_3 = "DrawStateA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZM_2147893336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZM!MTB"
        threat_id = "2147893336"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 12 00 00 0a 11 06 28 ?? ?? ?? 0a 26 7e ?? ?? ?? 0a 11 06 28 ?? ?? ?? 0a 13 07 11 07 08 09 28 ?? ?? ?? 06 13 08 11 08 28 03 00 00 0a 73 17 00 00 0a 13 09 11 05 11 09 6f 18 00 00 0a 26 11 04 28 03 00 00 0a 73 17 00 00 0a 13 0a 11 05 11 0a 6f 18 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "encryptedText" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DecryptAES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZQ_2147895301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZQ!MTB"
        threat_id = "2147895301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 1f 24 61 d2 9c 07 17 58 0b 07 02 8e 69 32 ec}  //weight: 1, accuracy: High
        $x_1_2 = "exclusiveOR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ZQ_2147895301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ZQ!MTB"
        threat_id = "2147895301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 6f 1e 00 00 0a 13 06 00 06 7e 1f 00 00 04 11 06 6f 1f 00 00 0a d2 6f 20 00 00 0a 00 00 11 04 6f 21 00 00 0a 2d d8}  //weight: 1, accuracy: High
        $x_1_2 = "GEMS\\GEMS\\obj\\Release\\GEMS.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_ACR_2147895586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.ACR!MTB"
        threat_id = "2147895586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 20 00 30 00 00 1f 40 16 28 ?? 00 00 06 0a 00 02 25 13 05 2c 06 11 05 8e 69 2d 05 16 e0 0b 2b 09 11 05 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MBFA_2147896934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MBFA!MTB"
        threat_id = "2147896934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 00 47 00 64 00 49 00 52 00 6e 00 70 00 5a 00 51 00 6b 00 39 00 45 00 51 00 6c 00 6c 00 43 00 62 00 33 00 4d 00 79 00 54 00 44 00 45 00 7a 00 51 00 6c 00 68 00 78 00 61 00 58}  //weight: 1, accuracy: High
        $x_1_2 = {44 00 31 00 46 00 5a 00 6e 00 64 00 44 00 5a 00 30 00 46 00 6b 00 5a 00 48 00 4e 00 68 00 5a 00 47 00 5a 00 68 00 63 00 32 00 52 00 68 00 5a 00 6d 00 46 00 6b 00 5a 00 6d 00 46}  //weight: 1, accuracy: High
        $x_1_3 = {67 67 62 63 61 68 65 6a 74 6c 00 44 65 66 6c 61 74 65 53 74 72 65 61 6d 00 43 72 79 70 74 6f 53 74 72 65 61 6d 00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00 6d 6d 74 6a 68 78 64 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_E_2147901003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.E!MTB"
        threat_id = "2147901003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 06 06 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 0c 73}  //weight: 2, accuracy: Low
        $x_2_2 = {09 08 17 73 ?? 00 00 0a 13 04 11 04 07 16 07 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_MA_2147901378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.MA!MTB"
        threat_id = "2147901378"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 08 25 11 07 11 08 11 08 8e 69 12 06 28 ?? ?? ?? 06 26 11 08 1f 3c 28 15 00 00 0a 1f 28 ?? ?? ?? 11 08 11 09}  //weight: 2, accuracy: Low
        $x_5_2 = "http://182.92.67.97" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_G_2147903552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.G!MTB"
        threat_id = "2147903552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 18 5b 07 58 91 02 07 91 61 d2 0c}  //weight: 2, accuracy: High
        $x_2_2 = {04 8e 69 b8 20 00 30 00 00 1f 40 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_H_2147903689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.H!MTB"
        threat_id = "2147903689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 16 07 7e ?? 00 00 04 8e 69 28 ?? 00 00 06 07 d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_SPVX_2147904948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.SPVX!MTB"
        threat_id = "2147904948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 06 04 6f ?? ?? ?? 0a 00 06 06 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 73 28 00 00 0a 0c 00 08 07 17 73 29 00 00 0a 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_GD_2147911717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.GD!MTB"
        threat_id = "2147911717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 28 00 00 01 0b 16 0c 2b 13 07 08 02 08 91 06 08 06 8e 69 5d 91 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_AI_2147915248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.AI!MTB"
        threat_id = "2147915248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 11 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 07 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a d2 61 d2 81 ?? 00 00 01 00 11 07 17 58 13 07 11 07 09 8e 69 fe 04 13 09 11 09 2d}  //weight: 4, accuracy: Low
        $x_1_2 = "rgZaI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_KAH_2147919574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.KAH!MTB"
        threat_id = "2147919574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 04 2b 09 de 0d 28 ?? 00 00 06 2b f5 0a 2b f4 26 de ec 2b 01 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_NIT_2147925281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.NIT!MTB"
        threat_id = "2147925281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 02 8e 69 20 00 10 00 00 1f 40 28 ?? 00 00 06 0a 02 16 06 6e 28 ?? 00 00 0a 02 8e 69 28 ?? 00 00 0a 7e 1c 00 00 0a 06 6e 28 ?? 00 00 0a 7e 1c 00 00 0a 28 ?? 00 00 06 26 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {18 5b 0b 07 8d 1b 00 00 01 0c 16 0d 2b 1d 02 09 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 08 09 11 04 d2 9c 09 17 58 0d 09 07 32 df}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_SPCB_2147927901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.SPCB!MTB"
        threat_id = "2147927901"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {03 07 06 5d 6f ?? 00 00 0a d2 61 d2 52 00 07 17 58 0b 07 02 50 8e 69 fe 04 0c 08 2d d8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_SDID_2147932395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.SDID!MTB"
        threat_id = "2147932395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 08 a2 25 17 09 8c 11 00 00 01 a2 11 0e 28 ?? 00 00 2b 26 09 11 0e 8e 69 58 0d 14 13 0c 11 08 17 58 13 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CobaltStrike_GVA_2147946060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CobaltStrike.GVA!MTB"
        threat_id = "2147946060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 7e 07 00 06 0a 02 2d 0c 03 2d 09 07 28 ef 03 00 06 26 2b 11 07 02 03 28 ee 03 00 06 26 2b 06 20 01 40 00 80 0a 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

