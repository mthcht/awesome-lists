rule Trojan_MSIL_Nanocore_B_2147741473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.B"
        threat_id = "2147741473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "TVqQAAMAAAAEAAAA__8AALgA" wide //weight: 4
        $x_1_2 = "HZlcnNpb249IjEuMCIgZW5jb" wide //weight: 1
        $x_1_3 = "SIxLjAiIGVuY29kaW5nP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Nanocore_SA_2147752350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.SA!MSR"
        threat_id = "2147752350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 43 6c 69 65 6e 74 5c 54 65 6d 70 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 43 53 50 41 52 4d 50 72 69 63 69 6e 67 43 61 6c 4f 70 73 5c 6f 62 6a 5c 44 65 62 75 67 5c [0-18] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_2 = "CSPARMPricingCalOps.Properties.Resources" wide //weight: 1
        $x_1_3 = "0.4.7.2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PR_2147752393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PR!MTB"
        threat_id = "2147752393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KurdishCoderProducts" ascii //weight: 1
        $x_1_2 = "Best Notepad" wide //weight: 1
        $x_1_3 = "SpeechBOx Start.." wide //weight: 1
        $x_1_4 = "Best_Notepad.Properties.Resources" wide //weight: 1
        $x_1_5 = "allice9554.000webhostapp.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NA_2147771297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NA!MTB"
        threat_id = "2147771297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {62 60 0c 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 ?? ?? ?? 1b 0b 11 07 20 e2}  //weight: 5, accuracy: Low
        $x_1_2 = "CinemaManagement.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RG_2147773578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RG!MTB"
        threat_id = "2147773578"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "liVsxbcBvRWgXgezBEzScYtcuwOVNC" ascii //weight: 1
        $x_1_2 = "$e9f18a30-57c0-43f0-91b6-0796b6810190" ascii //weight: 1
        $x_1_3 = "ConfuserEx v1.0.0-38-g7889971" ascii //weight: 1
        $x_1_4 = "ComputeHash" ascii //weight: 1
        $x_1_5 = "set_Key" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_Nanocore_AC_2147779430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AC!MTB"
        threat_id = "2147779430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 67 65 74 5f 52 65 74 75 72 6e 4d 65 73 73 61 67 65 00 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 52 65 74 75 72 6e 4d 65 73 73 61 67 65}  //weight: 1, accuracy: High
        $x_1_2 = {67 65 74 5f 54 65 78 74 00 73 65 74 5f 54 65 78 74}  //weight: 1, accuracy: High
        $x_1_3 = {73 73 73 73 73 00 52 65 76 65 72 73 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AD_2147779977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AD!MTB"
        threat_id = "2147779977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 67 65 74 5f 52 65 74 75 72 6e 4d 65 73 73 61 67 65 00 4f 66 66 73 65 74 4d 61 72 73 68 61 6c 65 72 00 52 65 74 75 72 6e 4d 65 73 73 61 67 65}  //weight: 1, accuracy: High
        $x_1_2 = {67 65 74 5f 50 69 78 65 6c 73 00 73 65 74 5f 50 69 78 65 6c 73}  //weight: 1, accuracy: High
        $x_1_3 = {4c 6f 63 6b 42 69 74 73 00 55 6e 6c 6f 63 6b 42 69 74 73}  //weight: 1, accuracy: High
        $x_1_4 = {73 73 73 73 73 00 52 65 76 65 72 73 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RM_2147783053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RM!MTB"
        threat_id = "2147783053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetHashCode" ascii //weight: 1
        $x_1_2 = "resourceCulture" ascii //weight: 1
        $x_1_3 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "get_InnerException" ascii //weight: 1
        $x_1_6 = "get_Computer" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "ComputeHash" ascii //weight: 1
        $x_1_9 = "get_ExecutablePath" ascii //weight: 1
        $x_1_10 = "HashAlgorithm" ascii //weight: 1
        $x_1_11 = "ICryptoTransform" ascii //weight: 1
        $x_1_12 = "*/*G*/*e*/*t*/*M*/*e*/*t*/*h*/*o*/*d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MFP_2147787472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MFP!MTB"
        threat_id = "2147787472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "$c16a528a-4ce8-4a58-94e1-f75d69f94cb9" ascii //weight: 20
        $x_20_2 = "$ced89fb5-e4b2-4207-8b40-324b6d3b2709" ascii //weight: 20
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "SuspendLayout" ascii //weight: 1
        $x_1_5 = "get_ResourceManager" ascii //weight: 1
        $x_1_6 = "get_Assembly" ascii //weight: 1
        $x_1_7 = "MemoryStreamx" ascii //weight: 1
        $x_1_8 = "DeflateStream" ascii //weight: 1
        $x_1_9 = "get_WebServices" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "VirtualProtect" ascii //weight: 1
        $x_1_12 = "GetHashCode" ascii //weight: 1
        $x_1_13 = "SpecialFolder" ascii //weight: 1
        $x_1_14 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 8 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Nanocore_SDSD_2147787477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.SDSD!MTB"
        threat_id = "2147787477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 06 16 73 ?? ?? ?? 0a 0d 08 8d ?? ?? ?? 01 13 04 09 11 04 16 08 6f ?? ?? ?? 0a 26 11}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0a 06 02 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_FEGA_2147810535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.FEGA!MTB"
        threat_id = "2147810535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {19 8d 13 00 00 01 13 09 11 09 16 02 a2 11 09 17 16 8c 05 00 00 01 a2 11 09 18 02 8e b7 8c 05 00 00 01 a2 11 09 13 0a 11 0a 14 14 19 8d 01 00 00 01 13 0b 11 0b 16 17 9c 11 0b 17 16 9c 11 0b 18 16 9c 11 0b 17}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_LTD_2147820113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.LTD!MTB"
        threat_id = "2147820113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 38 21 00 00 00 7e 30 00 00 04 07 9a 06 28 ?? ?? ?? 0a 39 0b 00 00 00 7e 31 00 00 04 74 19 00 00 01 2a 07 17 58 0b 07 7e 30 00 00 04 8e 69 3f d2 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_GZO_2147822402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.GZO!MTB"
        threat_id = "2147822402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 08 92 08 20 29 0e 00 00 5d 61 d2 6f ?? ?? ?? 0a 00 00 08 17 58 0c 08 07 8e 69 fe 04 0d 09 2d dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PPQ_2147822403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PPQ!MTB"
        threat_id = "2147822403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 07 08 91 03 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_BMN_2147824710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.BMN!MTB"
        threat_id = "2147824710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 02 07 8f 04 00 00 01 25 47 03 06 04 6f ?? ?? ?? 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 96 00 00 00 5f d2 61 d2 52 06 17 58 0a 06 02 8e 69 32 cc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_WGN_2147824711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.WGN!MTB"
        threat_id = "2147824711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 8e 69 5d 91 61 02}  //weight: 1, accuracy: High
        $x_1_2 = {17 d6 02 8e 69 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ZQWF_2147824712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ZQWF!MTB"
        threat_id = "2147824712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 6f ?? ?? ?? 0a 00 09 08 6f ?? ?? ?? 0a 00 09 18 6f ?? ?? ?? 0a 00 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 16 13 05 2b 00 16 13 06 2b 00 16 13 07 2b 00 16 13 08 2b 00 16 13 09 2b 00 16 13 0a 2b 00 16 13 0b 2b 00 16 13 0c 2b 00 11 04 28 ?? ?? ?? 06 74 36 00 00 01 6f ?? ?? ?? 0a 17 9a 80 02 00 00 04 23 66 66 66 66 66 66 28 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_COER_2147825957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.COER!MTB"
        threat_id = "2147825957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 11 00 00 04 73 be 00 00 0a 72 ad 03 00 70 6f ?? ?? ?? 0a 74 0f 00 00 1b 0a 06 28 ?? ?? ?? 06 0b 07 72 dd 03 00 70 28 ?? ?? ?? 06 74 4d 00 00 01 6f ?? ?? ?? 0a 1a 9a 80 10 00 00 04 23 d1 37 b7 3b 43 62 20 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABH_2147827393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABH!MTB"
        threat_id = "2147827393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 09 17 7e ?? ?? ?? 0a a2 09 18 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a a2 09 13 04 08}  //weight: 2, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "CAccPropServicesClass.IAccPropServer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABH_2147827393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABH!MTB"
        threat_id = "2147827393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 2a d0 2b ?? ?? 06 26 2a 30 00 28 0f ?? ?? 06 6f 3f ?? ?? 0a 07 75 24 ?? ?? 01 08 75 03 ?? ?? 1b 16 6f 40 ?? ?? 0a 07 75 24 ?? ?? 01 28 41 ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "ShutdownMode" ascii //weight: 1
        $x_1_3 = "get_CurrentDomain" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "DeflateStream" ascii //weight: 1
        $x_1_6 = "CompressionMode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AGO_2147827639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AGO!MTB"
        threat_id = "2147827639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 16 20 00 10 00 00 6f d2 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f d3 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb}  //weight: 1, accuracy: High
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "CompressionMode" ascii //weight: 1
        $x_1_4 = "YUG54G5EA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABV_2147827750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABV!MTB"
        threat_id = "2147827750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {07 d8 b4 6f b0 ?? ?? 0a 00 2b 00 00 07 17 d6 0b 07 1f 0f 31 cc 02 74 0b ?? ?? 1b 06 6f b1 ?? ?? 0a 20 ff ?? ?? 00 28 a5 ?? ?? 06 00 2a 45 00 06 16 6f b0 ?? ?? 0a 00 2b 19 00 06 07 19 32 07 20 ff ?? ?? 00 2b 03 03}  //weight: 6, accuracy: Low
        $x_1_2 = "OleDbCommand" ascii //weight: 1
        $x_1_3 = "GetResourceString" ascii //weight: 1
        $x_1_4 = "DateTimePicker" ascii //weight: 1
        $x_1_5 = "ReadBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_CEZ_2147828737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.CEZ!MTB"
        threat_id = "2147828737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 09 1f 21 fe 04 16 fe 01 09 1f 7e fe 02 16 fe 01 5f 13 06 11 06 2c 20 11 04 1f 21 09 1f 0e d6 1f 5e 5d d6 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RIYF_2147828798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RIYF!MTB"
        threat_id = "2147828798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 07 1f 16 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 73 ?? ?? ?? 0a 0d 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "ComputeHash" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABF_2147829926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABF!MTB"
        threat_id = "2147829926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 9d a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 01 00 00 00 96 00 00 00 51 00 00 00 48 02 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "$912efa92-610b-40f2-a282-22d1b6f64e01" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NEC_2147829996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NEC!MTB"
        threat_id = "2147829996"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 17 00 00 70 28 ?? 00 00 06 0b 07 16 07 8e 69 28 ?? 00 00 0a 00 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NLY_2147830016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NLY!MTB"
        threat_id = "2147830016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "p0.jO" ascii //weight: 1
        $x_1_2 = "SHA256CryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "LogSwitch" ascii //weight: 1
        $x_1_4 = "XCCVV" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "UIPermission" ascii //weight: 1
        $x_1_7 = "ComputeHash" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABC_2147830425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABC!MTB"
        threat_id = "2147830425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 b7 b6 3f 09 1f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 fa 00 00 00 4c 00 00 00 c1 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "Clipboard" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "TransformBlock" ascii //weight: 1
        $x_1_7 = "CreateEncryptor" ascii //weight: 1
        $x_1_8 = "RS55Q74D7H7GH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABL_2147830993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABL!MTB"
        threat_id = "2147830993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 5d a2 df 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 c5 00 00 00 1f 00 00 00 86 01 00 00 76 02 00 00 e0 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "PoKeMapV6" ascii //weight: 1
        $x_1_4 = "$f346e55f-46d3-43a8-91e9-50f87e0cd5cb" ascii //weight: 1
        $x_1_5 = "PoKeMapV6.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABL_2147830993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABL!MTB"
        threat_id = "2147830993"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateInstance" ascii //weight: 1
        $x_1_2 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_3 = "e6D0.Resources.resources" ascii //weight: 1
        $x_1_4 = "849ccca2dbaa.Resources.resources" ascii //weight: 1
        $x_1_5 = "6240b06f90.res" ascii //weight: 1
        $x_1_6 = "$5de54877-24a9-4309-940e-a706f33533e8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABW_2147831801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABW!MTB"
        threat_id = "2147831801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 1f 10 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 28 ?? ?? ?? 06 06 28 ?? ?? ?? 06 0d 28 ?? ?? ?? 06 09 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "TransformBlock" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABD_2147832232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABD!MTB"
        threat_id = "2147832232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 07 02 08 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 0d 08 09 58 0c 09 20 ?? ?? ?? 00 2f d8 0f 00 08 28 ?? ?? ?? 2b 07 6f ?? ?? ?? 0a dd ?? ?? ?? 00 07 39 ?? ?? ?? 00 07 6f ?? ?? ?? 0a dc 48 00 0f 00 08 20 ?? ?? ?? 00 58 28 01}  //weight: 2, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "ControlDomainPolicy" ascii //weight: 1
        $x_1_5 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NEE_2147832380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NEE!MTB"
        threat_id = "2147832380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 6a 00 00 0a 28 22 00 00 06 0b 07 28 24 00 00 06 28 2e 00 00 0a 0c 72 8c fb 03 70 28 6b 00 00 0a 6f 6c 00 00 0a 16 9a 14}  //weight: 5, accuracy: High
        $x_5_2 = "Religion_Jeopardy" wide //weight: 5
        $x_5_3 = "ncviewer.exe" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABT_2147832740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABT!MTB"
        threat_id = "2147832740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {91 61 d2 6f ?? ?? ?? 0a 07 1d 2c 04 17 58 0b 07 02 8e 69 32 db 06 6f ?? ?? ?? 0a 25 2d 02 26 14 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "WebRequest" ascii //weight: 1
        $x_1_3 = "GetResponseStream" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABT_2147832740_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABT!MTB"
        threat_id = "2147832740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0d 2b 31 00 07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 d2 9c 00 09 17 58 0d 09 17 fe 04 13 04 11 04 2d c5 06 17 58 0a 00 08 17 58 0c 08 20 ?? ?? ?? 00 fe 04 13 05 11 05 2d a9 28 ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 80 ?? ?? ?? 04 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
        $x_1_3 = "Grey" wide //weight: 1
        $x_1_4 = "Hierarchy.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABO_2147832741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABO!MTB"
        threat_id = "2147832741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 55 a2 cb 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9b 00 00 00 14 00 00 00 37 01 00 00 d1 02 00 00 c8 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "Guarderia.Resources" wide //weight: 1
        $x_1_4 = "download" wide //weight: 1
        $x_1_5 = "red_love" wide //weight: 1
        $x_1_6 = "$55d1056d-ef79-4736-a141-0e3632843054" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABAH_2147833554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABAH!MTB"
        threat_id = "2147833554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 9a 0a 06 6f ?? ?? ?? 0a 19 9a 0b 07 16 8c ?? ?? ?? 01 19 8d ?? ?? ?? 01 25 16 28 ?? ?? ?? 06 6f ?? ?? ?? 06 6f ?? ?? ?? 06 a2 25 17 28 ?? ?? ?? 06 6f ?? ?? ?? 06 6f ?? ?? ?? 06 a2 25 18 72 ?? ?? ?? 70 a2 6f ?? ?? ?? 0a 26 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Instagram_Takeout_Parser.Resources" wide //weight: 1
        $x_1_3 = "download" wide //weight: 1
        $x_1_4 = "red_love" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABAP_2147833561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABAP!MTB"
        threat_id = "2147833561"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 11 0b 09 18 6f ?? ?? ?? 0a 11 0b 09 18 6f ?? ?? ?? 0a 8e 69 5d 91 09 17 6f ?? ?? ?? 0a 11 0b 91 61 9c 11 0b 17 d6 13 0b 11 0b 11 0a 31 cb}  //weight: 1, accuracy: Low
        $x_1_2 = "SGBITPlacementManagementSystem.Resources" wide //weight: 1
        $x_1_3 = "KenPhasFuckedksajd44" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABAV_2147833563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABAV!MTB"
        threat_id = "2147833563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 12 11 0e 8f ?? ?? ?? 01 25 47 7e ?? ?? ?? 04 19 11 0e 5f 19 62 1f 1f 5f 63 d2 61 d2 52 11 0e 17 58 13 0e 11 0e 11 12 8e 69 33 d4}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_4 = "$9103aa03-a299-4876-8a14-c21188e09ab9" ascii //weight: 1
        $x_1_5 = "Advanced_Html_Editor.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AEOCG_2147833821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AEOCG!MTB"
        threat_id = "2147833821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0b 11 04 11 06 11 0a 58 11 09 11 0a 91 11 0b 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d8}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABCG_2147834858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABCG!MTB"
        threat_id = "2147834858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "EcoBoost" wide //weight: 1
        $x_1_3 = "745445BJ5CHO8980FGGAZ7" wide //weight: 1
        $x_1_4 = "NewPaint.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABCK_2147835239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABCK!MTB"
        threat_id = "2147835239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 00 07 15 58 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "UsersDataCore.AboutBox1" wide //weight: 1
        $x_1_3 = "D774Z478V4S7392GGBH54G" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABCL_2147835240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABCL!MTB"
        threat_id = "2147835240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 09 1b 59 1c 58 0d 09 17 fe 04 13 09 11 09 2d c3}  //weight: 5, accuracy: Low
        $x_1_2 = "MyGame.Properties.Resources" wide //weight: 1
        $x_1_3 = "Aeeee" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABCW_2147835245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABCW!MTB"
        threat_id = "2147835245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 20 ?? ?? ?? 00 fe 04 0c 08 2d da}  //weight: 5, accuracy: Low
        $x_1_2 = "WinFormsPersianDatePicker.CO2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABCX_2147835246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABCX!MTB"
        threat_id = "2147835246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "InvokeMember" ascii //weight: 1
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_2_3 = "fbG8hJWgUpXZSSZuDe.MFQ20B6PCiegbDUUgn" wide //weight: 2
        $x_2_4 = "Savannah.Properties.Resources" wide //weight: 2
        $x_2_5 = "Savannah" wide //weight: 2
        $x_2_6 = "P53YSCYRBVHHUP8G47B75Y" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDD_2147835712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDD!MTB"
        threat_id = "2147835712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 00 07 17 58 0b 07 20 ?? ?? ?? 00 fe 04 0c 08 2d da 06 28 ?? ?? ?? 06 26 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "TrafficSimulation.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDF_2147835714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDF!MTB"
        threat_id = "2147835714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 28 56 00 00 0a 28 ?? ?? ?? 0a 0a 2b 00 06 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {11 04 16 91 2d 02 2b 09 09 16 9a 28 ?? ?? ?? 0a 0c 74 ?? ?? ?? 01 28 ?? ?? ?? 06 00 06 2a}  //weight: 2, accuracy: Low
        $x_1_3 = "EbooksManager.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDG_2147835715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDG!MTB"
        threat_id = "2147835715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? 0a 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 ?? ?? ?? 00 58 20 ?? ?? ?? 00 5d d2 9c 00 07 15 58 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "P53YSCYRBVHHUP8G47B75Y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDR_2147835776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDR!MTB"
        threat_id = "2147835776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 06 08 06 8e 69 5d 91 7e ?? ?? ?? 04 08 91 61 d2 6f ?? ?? ?? 0a 08 17 58 0c 08 7e ?? ?? ?? 04 8e 69 32 dc 07 6f ?? ?? ?? 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDW_2147835934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDW!MTB"
        threat_id = "2147835934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0a 2b 00 06 2a 10 00 02 28 ?? ?? ?? 0a 28}  //weight: 2, accuracy: Low
        $x_2_2 = {01 25 16 08 a2 25 0d 14 14 17 8d ?? ?? ?? 01 25 16 17 9c 25 13 04 33 00 0b 07 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 14 72 ?? ?? ?? 70 17 8d}  //weight: 2, accuracy: Low
        $x_1_3 = "SystemManager.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABEN_2147836113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABEN!MTB"
        threat_id = "2147836113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 07 16 73 19 00 00 0a 73 1a 00 00 0a 0d 09 08 6f 1b 00 00 0a de 0a 09 2c 06 09 6f 1c 00 00 0a dc 08 6f 1d 00 00 0a 13 04 de 14}  //weight: 2, accuracy: High
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "InvokeMember" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABFF_2147837167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABFF!MTB"
        threat_id = "2147837167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 06 11 07 9a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 07 17 58 13 07 11 07 20 ?? ?? ?? 00 fe 04 13 08 11 08 2d d9 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABGB_2147837426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABGB!MTB"
        threat_id = "2147837426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VVAVVsVVsVVeVVmVVbVVlVVyVV" wide //weight: 1
        $x_1_2 = "VVRVVeVVfVVlVVeVVcVVtVViVVoVVnVV" wide //weight: 1
        $x_1_3 = "VVSVVyVVsVVtVVeVVmVV" wide //weight: 1
        $x_1_4 = "VoooodKaaaa" wide //weight: 1
        $x_1_5 = "11M11e1t1111h111o1d111011" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABGT_2147837958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABGT!MTB"
        threat_id = "2147837958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 08 07 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 07 8e 69 fe 04 13 09 11 09 2d de}  //weight: 5, accuracy: Low
        $x_1_2 = "HoqueLtd.ResO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABHB_2147837961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABHB!MTB"
        threat_id = "2147837961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00 14 14 18 8d ?? ?? ?? 01 25 16 07 11 09 9a a2 25 17 1f 10 8c ?? ?? ?? 01 a2 6f ?? ?? ?? 0a a5 ?? ?? ?? 01 9c 11 09 17 58 13 09 11 09 07 8e 69 fe 04 13 0a 11 0a 2d b2}  //weight: 5, accuracy: Low
        $x_1_2 = "App.Aplicattion.ReCS" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABJW_2147839042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABJW!MTB"
        threat_id = "2147839042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 06 11 06 9a 1f 10 28 ?? ?? ?? 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de}  //weight: 5, accuracy: Low
        $x_1_2 = "WFA_Yacht_Dice.DSSDWE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABKQ_2147839359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABKQ!MTB"
        threat_id = "2147839359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 06 16 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 07 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 13 04 de 1e 08 2c 06 08 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "UrlTokenDecode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NEAA_2147840316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NEAA!MTB"
        threat_id = "2147840316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "$de153293-5de8-46cc-99ec-e12a283ea103" ascii //weight: 5
        $x_4_2 = "aa9FZxDinAnwWXPJclh" ascii //weight: 4
        $x_2_3 = "AHdhEgDv4FIOxsf9Qwp" ascii //weight: 2
        $x_2_4 = "Ldc_I4_M1" ascii //weight: 2
        $x_1_5 = "nW4lBacjpc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RDA_2147840519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RDA!MTB"
        threat_id = "2147840519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "5d107376-033b-4af4-a413-7114cde92fb3" ascii //weight: 1
        $x_1_2 = "nm5ebx0ydzq" wide //weight: 1
        $x_1_3 = "Controlios" ascii //weight: 1
        $x_1_4 = "--Qdj$;a:9pDsb@ =} k|u9g\\&." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NCE_2147840803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NCE!MTB"
        threat_id = "2147840803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 57 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "WriteProcessMemory" ascii //weight: 1
        $x_1_3 = "qtjiZSSiWlGAf3SavB.FJr54K84g6drqE3j0u" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_CAJ_2147841120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.CAJ!MTB"
        threat_id = "2147841120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {26 2b 32 11 04 11 05 02 11 05 91 06 61 08 09 91 61 b4 9c 09 16 2d 12 03 6f ?? 00 00 0a 17 da 33 07 16 16 2c 59 26 2b 07 09 17 25 2c c0 d6 0d 11 05 17 d6 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABLZ_2147841278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABLZ!MTB"
        threat_id = "2147841278"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 06 07 11 06 9a 1f 10 28 ?? 00 00 0a d2 9c 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dd}  //weight: 5, accuracy: Low
        $x_1_2 = "TryaAgain.Chunks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMA_2147841279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMA!MTB"
        threat_id = "2147841279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 06 11 04 9a 1f 10 28 ?? 00 00 0a d2 9c 11 04 17 58 13 04 11 04 06 8e 69 fe 04 13 05 11 05 2d dd}  //weight: 5, accuracy: Low
        $x_1_2 = "NSC.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMD_2147841280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMD!MTB"
        threat_id = "2147841280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 08 5d 91 28 ?? ?? ?? 0a 59 06 58 06 5d d2 0d 2b 00 09 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "kbWar.Lego" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMF_2147841281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMF!MTB"
        threat_id = "2147841281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 05 08 5d 91 07 05 03 5d 91 61 28 ?? 00 00 0a 04 05 17 58 08 5d 91 28 ?? 00 00 0a 59 06 58 06 5d d2 0d 2b 00 09 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "Nth.Eindhoven.Fontys.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NC_2147842250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NC!MTB"
        threat_id = "2147842250"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 05 07 11 05 9a 1f 10 28 ?? ?? ?? 0a d2 9c 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dd}  //weight: 5, accuracy: Low
        $x_1_2 = "zUKC.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ANO_2147842894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ANO!MTB"
        threat_id = "2147842894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 16 0d 2b 17 07 09 09 d2 9c 08 09 06 09 06 16 6f ?? ?? ?? 0a 5d 91 9c 09 17 58 0d 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ANO_2147842894_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ANO!MTB"
        threat_id = "2147842894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 0b 2b 49 16 0c 2b 2c 09 07 08 6f ?? 00 00 0a 26 09 07 08 6f ?? 00 00 0a 13 08 11 08 28 ?? 00 00 0a 13 09 11 05 11 04 11 09 28 ?? 00 00 0a 9c 08 17 58 0c 08 09 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ANO_2147842894_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ANO!MTB"
        threat_id = "2147842894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0a 2b 0e 02 03 06 04 05 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 04 6f ?? 00 00 0a 05 32 e0}  //weight: 3, accuracy: Low
        $x_2_2 = {16 0a 2b 0d 02 06 03 04 28 ?? 00 00 06 06 17 58 0a 06 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 e1}  //weight: 2, accuracy: Low
        $x_1_3 = "TemperatureConverter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABPW_2147843317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABPW!MTB"
        threat_id = "2147843317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {01 0b 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 16 07 16 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 16 07 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 00 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 16 07 20 ?? ?? ?? 00 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 00 02}  //weight: 5, accuracy: Low
        $x_1_2 = "Cache_Simulation.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABLQ_2147843437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABLQ!MTB"
        threat_id = "2147843437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 03 04 03 8e 69 5d 91 07 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 03 8e 69 5d 91 28 ?? ?? ?? 0a 59 06 58 06 5d d2 0c 08 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABLR_2147843438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABLR!MTB"
        threat_id = "2147843438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 08 16 73 ?? 00 00 0a 73 ?? 00 00 0a 13 04 11 04 09 6f ?? 00 00 0a de 0c 11 04 2c 07 11 04 6f ?? 00 00 0a dc 09 6f ?? 00 00 0a 13 05 de 25 09 2c 06 09 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "BufferedStream" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABLV_2147843440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABLV!MTB"
        threat_id = "2147843440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 03 8e 69 0c 03 04 08 5d 91 07 04 1f 16 5d 91 61 28 ?? ?? ?? 0a 03 04 17 58 08 5d 91 28 ?? ?? ?? 0a 59 06 58 06 5d d2 0d 09 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMS_2147843708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMS!MTB"
        threat_id = "2147843708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df}  //weight: 5, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMM_2147844698_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMM!MTB"
        threat_id = "2147844698"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "VolvoS60.PDOControls.resources" ascii //weight: 3
        $x_3_2 = {56 00 6f 00 6c 00 76 00 6f 00 53 00 36 00 30 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMQ_2147845130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMQ!MTB"
        threat_id = "2147845130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c de 0d 26 de 00 06 17 58 0a 06 1b 32 cc 33 00 28 ?? ?? ?? 06 0b 28 ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABMR_2147845131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABMR!MTB"
        threat_id = "2147845131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 13 01 38 ?? ?? ?? 00 28 ?? ?? ?? 0a 11 01 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 02 38 ?? ?? ?? 00 dd ?? ?? ?? ff 26}  //weight: 4, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABRU_2147845553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABRU!MTB"
        threat_id = "2147845553"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "SpringPendulum.SpringPendulum.resources" ascii //weight: 3
        $x_2_2 = "HelloWPFApp.Properties.Resources.resources" ascii //weight: 2
        $x_1_3 = "HelloWPFApp.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABRB_2147845864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABRB!MTB"
        threat_id = "2147845864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 06 74 ?? ?? ?? 01 28 ?? ?? ?? 06 74 ?? ?? ?? 1b 28 ?? ?? ?? 06 0a dd ?? ?? ?? 00 26 de d3 06 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABSY_2147846103_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABSY!MTB"
        threat_id = "2147846103"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 06 15 2d 03 26 de 06 0a 2b fb 26 de 00 06 2c e6}  //weight: 2, accuracy: Low
        $x_2_2 = {32 00 30 00 38 00 2e 00 36 00 37 00 2e 00 31 00 30 00 37 00 2e 00 31 00 34 00 36}  //weight: 2, accuracy: High
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABTA_2147846104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABTA!MTB"
        threat_id = "2147846104"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 33 00 33 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {41 00 62 00 75 00 68 00 62 00 66 00 6b 00 75 00 79 00 67 00 67 00 6e 00 70 00 6e 00 66 00 76}  //weight: 2, accuracy: High
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABVM_2147846880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABVM!MTB"
        threat_id = "2147846880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 14 17 8d ?? 00 00 01 25 16 07 a2 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 75 ?? 00 00 1b 0d 16 13 04 38 ?? 00 00 00 09 11 04 91 13 05 08 11 05 6f ?? 00 00 0a 11 04 17 58 13 04 11 04 09 8e 69 32 e5 08 28 ?? 00 00 2b 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABVY_2147847208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABVY!MTB"
        threat_id = "2147847208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 09 8e 69 8d ?? 00 00 01 13 04 07 08 08 6f ?? 00 00 0a 13 05 09 73 ?? 00 00 0a 13 06 00 11 06 11 05 16 73 ?? 00 00 0a 13 07 00 11 07 11 04 16 11 04 8e 69 6f ?? 00 00 0a 26 11 07 6f ?? 00 00 0a 00 11 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABXE_2147847268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABXE!MTB"
        threat_id = "2147847268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 8e 69 8d ?? 00 00 01 0d 16 13 07 2b 15 09 11 07 08 11 07 9a 1f 10 28 ?? ?? 00 0a 9c 11 07 17 58 13 07 11 07 08 8e 69 fe 04 13 08 11 08 2d de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABVD_2147847374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABVD!MTB"
        threat_id = "2147847374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AlgorithmSimulator.Properties.Resources.resources" ascii //weight: 2
        $x_1_2 = "39f35d17-2c86-48a1-a280-f77fb3e5248e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NAC_2147847507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NAC!MTB"
        threat_id = "2147847507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 08 7e 55 00 00 04 11 05 20 ?? ?? ?? 00 58 61 80 ?? ?? ?? 04 11 08 2c 0e 7e ?? ?? ?? 04 11 08 28 ?? ?? ?? 06 2b 01}  //weight: 5, accuracy: Low
        $x_1_2 = "add_ResourceResolve" ascii //weight: 1
        $x_1_3 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABXF_2147847609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABXF!MTB"
        threat_id = "2147847609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 04 2b 34 16 13 05 2b 1f 07 11 04 11 05 6f ?? 00 00 0a 13 06 08 12 06 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 17 58 13 05 11 05 07 6f ?? 00 00 0a 32 d7}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MAAJ_2147848149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MAAJ!MTB"
        threat_id = "2147848149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 16 73 ?? 00 00 0a 0b 16 13 04 16 0c 06 74 ?? 00 00 01 08 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0a 07 06 11 04 1f 64}  //weight: 1, accuracy: Low
        $x_1_2 = {00 0a 13 06 11 06 16 2e 0e 11 04 11 06 d6 13 04 08 11 06 d6 0c 2b c4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_GAM_2147848225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.GAM!MTB"
        threat_id = "2147848225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 00 64 00 59 00 44 00 41 00 67 00 44 00 4d 00 73 00 38 00 48 00 4b 00 67 00 41 00 41 00 53 00 67 00 4a 00 7a 00 48 00 41 00 41 00 41 00 43 00 6e 00 30 00 42 00 41 00 41 00 41 00 45 00 41 00 69 00 67 00 64 00 41 00 41 00 41 00 4b 00 4b 00 67 00 41 00 62 00 4d 00 41}  //weight: 1, accuracy: High
        $x_1_2 = {41 00 4b 00 46 00 67 00 67 00 48 00 4b 00 44 00 6b 00 41 00 41 00 41 00 59 00 71 00 41 00 41 00 41 00 41 00 47 00 7a 00 41 00 45 00 41 00 45 00 38 00 41 00 41 00 41 00 41 00 44 00 41 00 41 00 41 00 52 00 63 00 77 00 6b 00 41 00 41 00 41 00 6f 00 4b 00 63 00 67 00 45 00 41 00 41 00 48 00 41 00 6f}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 78 00 65 00 4e 00 45 00 77 00 41 00 41 00 41 00 52 00 4d 00 47 00 45 00 51 00 59 00 57 00 48 00 31 00 79 00 64 00 45 00 51 00 5a 00 76 00 48 00 67 00 41 00 41 00 43 00 67 00 4d 00 58 00 6a 00 52 00 4d 00 41 00 41 00 41 00 45 00 54 00 42 00 78 00 45 00 48 00 46 00 68 00 39 00 63 00 6e}  //weight: 1, accuracy: High
        $x_1_4 = {54 00 42 00 78 00 45 00 48 00 46 00 32 00 38 00 6b 00 41 00 41 00 41 00 4b 00 45 00 51 00 63 00 6f 00 51 00 41 00 41 00 41 00 43 00 69 00 43 00 73 00 44 00 51 00 41 00 41 00 62 00 30 00 45 00 41 00 41 00 41 00 6f 00 6d 00 42 00 69 00 78 00 33 00 45 00 67 00 6a}  //weight: 1, accuracy: High
        $x_1_5 = {63 00 45 00 47 00 6a 00 49 00 56 00 41 00 77 00 4a 00 4c 00 56 00 41 00 4d 00 61 00 30 00 31 00 67 00 51 00 41 00 51 00 49 00 61 00 30 00 31 00 67 00 51 00 41 00 41 00 51 00 61 00 57 00 52 00 41 00 43 00 42 00 42 00 67 00 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABYL_2147848243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABYL!MTB"
        threat_id = "2147848243"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 2b 2b 30 1b 2c f9 1e 2c f6 2b 2b 2b 30 2b 31 2b 36 75 ?? 00 00 1b 2b 36 19 2c 0f 16 2d e1 2b 31 16 2b 31 8e 69 28 ?? 00 00 0a 07 2a 28 ?? 00 00 06 2b ce 0a 2b cd 28 ?? 00 00 0a 2b ce 06 2b cd 6f ?? 00 00 0a 2b c8 28 ?? 00 00 06 2b c3 0b 2b c7 07 2b cc 07 2b cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NCA_2147848257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NCA!MTB"
        threat_id = "2147848257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {18 72 ad 33 00 70 14 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 18 8d ?? ?? ?? 01 25 16 17 14 28 ?? ?? ?? 0a a2 25 17 16 14 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "QuanLyBangDiaCD.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABXR_2147848551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABXR!MTB"
        threat_id = "2147848551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0c 16 0d 38 ?? 00 00 00 00 07 09 18 7e ?? 02 00 04 28 ?? 01 00 06 1f 10 7e ?? 02 00 04 28 ?? 01 00 06 7e ?? 02 00 04 28 ?? 01 00 06 16 91 13 05 08 17 8d ?? 00 00 01 25 16 11 05 9c 6f ?? 00 00 0a 00 09 18 58 0d 00 09 07 7e ?? 02 00 04 28 ?? 01 00 06 fe 04 13 06 11 06}  //weight: 3, accuracy: Low
        $x_1_2 = "4D5A90" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABZZ_2147848839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABZZ!MTB"
        threat_id = "2147848839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 0a 11 09 6f ?? 00 00 0a 13 0b 16 13 0c 11 05 11 08 9a 13 0e 11 0e 13 0d 11 0d 72 b7 09 00 70 28 ?? 00 00 0a 2d 1e 11 0d 72 bb 09 00 70 28 ?? 00 00 0a 2d 1b 11 0d 72 bf 09 00 70 28 ?? 00 00 0a 2d 18 2b 21 12 0b 28 ?? 00 00 0a 13 0c 2b 16 12 0b 28 ?? 00 00 0a 13 0c 2b 0b 12 0b 28 ?? 00 00 0a 13 0c 2b 00 07 11 0c 6f ?? 00 00 0a 00 00 11 0a 17 58 13 0a 11 0a 09 fe 04 13 0f 11 0f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABZV_2147849001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABZV!MTB"
        threat_id = "2147849001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "DataBasePracticalJob" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NN_2147849601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NN!MTB"
        threat_id = "2147849601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 06 04 11 07 25 17 58 13 07 91 61 20 ?? 00 00 00 5f e0 95 11 06 1e 64 61 13 06 11 08 17 59 25 13 08 16 2f d9}  //weight: 5, accuracy: Low
        $x_1_2 = "fsdgsrxd.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MBEW_2147849633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MBEW!MTB"
        threat_id = "2147849633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 b0 08 00 00 13 0b 72 ?? ?? ?? 70 13 06 02 09 02 8e b7 5d 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = "Afy3iJ3h6MWYXN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AADC_2147849649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AADC!MTB"
        threat_id = "2147849649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 05 17 8d ?? 00 00 01 25 16 1f 2d 9d 6f ?? 00 00 0a 0c 08 8e 69 8d ?? 00 00 01 0d 16 0a 2b 11 09 06 08 06 9a 1f 10 28 ?? 00 00 0a 9c 06 17 58 0a 06 08 8e 69 fe 04 13 09 11 09 2d e3}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PSQW_2147849905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PSQW!MTB"
        threat_id = "2147849905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f d2 00 00 0a 6f d3 00 00 0a 28 21 02 00 06 38 1e 00 00 00 00 11 03 11 02 16 11 07 6f d4 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AACL_2147849943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AACL!MTB"
        threat_id = "2147849943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 07 8c ?? 00 00 01 a2 25 17 11 04 1e 61 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 1a 13 07 38 ?? fe ff ff 1f 0c 13 07 38 ?? fe ff ff 07 17 d6 0b 16 13 07 38 ?? fe ff ff 07 08 fe 04 13 05 11 05 2d 08 18 13 07 38 ?? fe ff ff 1c 2b f6 02}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAEF_2147850209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAEF!MTB"
        threat_id = "2147850209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 01 02 8e 69 5d 02 11 01 02 8e 69 5d 91 11 00 11 01 11 00 8e 69 5d 91 61 28 ?? 00 00 06 02 11 01 17 58 02 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RDB_2147850260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RDB!MTB"
        threat_id = "2147850260"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fef9abff-f04b-4d0a-9be9-039aebd112d5" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31" ascii //weight: 1
        $x_1_3 = "lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
        $x_1_4 = "HHHgVPL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NNC_2147850313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NNC!MTB"
        threat_id = "2147850313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 14 17 8d 03 00 00 01 0b 07 16 16 8d ?? 00 00 01 a2 00 07 6f ?? 00 00 0a 26 2b 0a 00 06 14 14 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Klepassfile" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NR_2147850314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NR!MTB"
        threat_id = "2147850314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 20 81 31 b5 b5 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 28 ?? ?? ?? 06 07 20 ?? ?? ?? c8 5a 20 ?? ?? ?? 35 61 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "BBNMK873" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NRN_2147850315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NRN!MTB"
        threat_id = "2147850315"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 6f 2c 00 00 0a 13 05 7e ?? 00 00 04 11 05 6f ?? 00 00 0a 7e ?? 00 00 04 02 6f ?? 00 00 0a 7e ?? 00 00 04 6f ?? 00 00 0a 17 59 28 ?? 00 00 0a 16 7e ?? 00 00 04 02 1a 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "BBNMK873" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAER_2147850708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAER!MTB"
        threat_id = "2147850708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 06 7e ?? 00 00 04 16 6f ?? 00 00 0a 20 39 05 00 00 59 7d ?? 00 00 04 7e ?? 00 00 04 17 6f ?? 00 00 0a 06 fe ?? ?? 03 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 73 ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAFA_2147850717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAFA!MTB"
        threat_id = "2147850717"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 16 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "Main_Project" wide //weight: 1
        $x_1_3 = "ISDnkRJZgkB5BF3N" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NNE_2147851267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NNE!MTB"
        threat_id = "2147851267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 5b 00 00 70 0a 06 28 ?? 00 00 0a 25 26 0b 28 ?? 00 00 0a 25 26 07 16 07 8e 69 6f ?? 00 00 0a 25 26 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "NNnH76" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NCC_2147851391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NCC!MTB"
        threat_id = "2147851391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 09 11 03 28 2e 00 00 06 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 39 ?? ?? ?? 00 26 20 ?? ?? ?? 00 38 ?? ?? ?? 00 fe ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Cmuvk.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAIK_2147852106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAIK!MTB"
        threat_id = "2147852106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 8e 69 8d ?? 00 00 01 0d 16 13 04 38 ?? 00 00 00 09 11 04 07 11 04 91 06 11 04 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAKD_2147852964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAKD!MTB"
        threat_id = "2147852964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 08 8e 69 5d 13 06 08 11 06 91 13 07 09 11 05 1f 16 5d 6f ?? 00 00 0a d2 13 08 08 11 05 17 58 08 8e 69 5d 91 13 09 11 07 11 08 61 11 09 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 0a 08 11 06 11 0a d2 9c 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 0b 11 0b 2d a5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AALX_2147888477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AALX!MTB"
        threat_id = "2147888477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 08 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 28 ?? 00 00 06 07 09 17 58 07 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 06 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MBID_2147888931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MBID!MTB"
        threat_id = "2147888931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AAAEK9KAAgAABCvUgAMAAAQr1gAAABMwAQ" wide //weight: 1
        $x_1_2 = "GS0KJgwrUQor5gsr7RMGK/MHCJp0qwA" wide //weight: 1
        $x_1_3 = {fa 25 33 00 16 00 00 01 00 00 00 0b 00 00 00 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PSWE_2147889171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PSWE!MTB"
        threat_id = "2147889171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 ad 02 00 70 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 1f 7b 28 ?? 00 00 0a 00 28 04 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ad 02 00 70 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 26 1f 7b 28 ?? 00 00 0a 00 de 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAPH_2147891331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAPH!MTB"
        threat_id = "2147891331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 05 03 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "$$$$$$$$$$C$$$$$$$$$$$$reat$$$$$$$eIn$$$$$$$$$$stan$$$$$$$$$$$ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAPN_2147891702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAPN!MTB"
        threat_id = "2147891702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Questions.Properties.Resources.resources" ascii //weight: 1
        $x_1_2 = "1a2f2329-7bc5-461d-b9e2-3d8a5f080819" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AASS_2147893072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AASS!MTB"
        threat_id = "2147893072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d de}  //weight: 3, accuracy: Low
        $x_1_2 = "Gl.L9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AAVF_2147895184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AAVF!MTB"
        threat_id = "2147895184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 11 02 11 07 91 20 e7 ad e7 fa 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 20 0e 00 00 00 38 ?? fe ff ff 11 07 17 58 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABOQ_2147896335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABOQ!MTB"
        threat_id = "2147896335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 07 11 04 9a 1f 10 28 ?? ?? ?? 0a 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc}  //weight: 5, accuracy: Low
        $x_1_2 = "FormSimVille" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABOV_2147896337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABOV!MTB"
        threat_id = "2147896337"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 1c 2c a1 09 02 16 02 8e 69 6f ?? ?? ?? 0a 2a 0a 38 ?? ?? ?? ff 0b 38 ?? ?? ?? ff 0c 2b aa 28 ?? ?? ?? 0a 2b b4 28 ?? ?? ?? 0a 2b bc 33 00 06 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "SymmetricAlgorithm" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABOW_2147896338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABOW!MTB"
        threat_id = "2147896338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 04 07 11 04 9a 1f 10 28 ?? ?? ?? 06 9c 00 11 04 17 58 13 04 11 04 07 8e 69 fe 04 13 05 11 05 2d dc}  //weight: 5, accuracy: Low
        $x_1_2 = "Split" ascii //weight: 1
        $x_1_3 = "WebsiteReviewSimulation.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABLP_2147896450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABLP!MTB"
        threat_id = "2147896450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 16 02 8e 69 6f ?? ?? ?? 0a 0a 2b 00 06 2a 19 00 7e ?? ?? ?? 04 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "hkyxDpEhpQxOiEshQCrDp" wide //weight: 1
        $x_1_3 = "PCMBinBuilder.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABDB_2147896489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABDB!MTB"
        threat_id = "2147896489"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0b 06 07 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 07 08 14 6f ?? ?? ?? 0a 26 2a 33 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABBB_2147896520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABBB!MTB"
        threat_id = "2147896520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 2d 09 11 06 6f ?? ?? ?? 06 13 04 07 17 58 d2 0b 07 1f 20 33 02 16 0b 02 08 8f ?? ?? ?? 01 25 47 11 04 06 08 18 63 19 5f 91 61 06 07 19 5f 91 61 d2 61 d2 52 08 17 58 0c 08 11 07 33 c2 02 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "$ab53df07-7683-4d5f-9a87-72d4c546868b" ascii //weight: 1
        $x_1_4 = "35e0983c16574f9a9933f6a0d62fd656" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABBV_2147896523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABBV!MTB"
        threat_id = "2147896523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateInstance" ascii //weight: 1
        $x_1_2 = "ColorTranslator" ascii //weight: 1
        $x_1_3 = "GetPixel" ascii //weight: 1
        $x_1_4 = "$8bd95c6c-f324-4305-90e1-a7fcbd262df3" ascii //weight: 1
        $x_1_5 = "Canvas.Image" wide //weight: 1
        $x_1_6 = "Tumas" wide //weight: 1
        $x_1_7 = "Tuma.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ABQB_2147896715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ABQB!MTB"
        threat_id = "2147896715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 0c 07 08 6f ?? ?? ?? 0a 00 07 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 07 06 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 6f ?? ?? ?? 0a 00 02}  //weight: 5, accuracy: Low
        $x_1_2 = "UniverseSimulator.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PTEI_2147899427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PTEI!MTB"
        threat_id = "2147899427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 03 00 00 06 0d 09 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 13 05 07 11 05 6f 4b 00 00 0a 00 07 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ARA_2147899449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ARA!MTB"
        threat_id = "2147899449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3d 00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? ?? 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 07 15 58 0b 07 16 fe 04 16 fe 01 0c 08 2d b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_CGAA_2147901539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.CGAA!MTB"
        threat_id = "2147901539"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 28 ?? ?? 00 06 ?? 08 20 88 10 00 00 58 20 87 10 00 00 59 ?? 8e 69 5d 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_GPA_2147902467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.GPA!MTB"
        threat_id = "2147902467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {05 0e 08 02 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00}  //weight: 5, accuracy: Low
        $x_5_2 = "wmWLWYvtUaqfWil" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_EXAA_2147903185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.EXAA!MTB"
        threat_id = "2147903185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 11 0a 11 10 11 08 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {11 0c 11 0d 61 13 0f}  //weight: 1, accuracy: High
        $x_1_3 = {11 01 11 0b 91 11 08 58 13 0e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_FBAA_2147903189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.FBAA!MTB"
        threat_id = "2147903189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 04 0e 05 0e 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_RDC_2147908437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.RDC!MTB"
        threat_id = "2147908437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 75 02 00 00 1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 11 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AMAM_2147915695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AMAM!MTB"
        threat_id = "2147915695"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 13 [0-15] 61 [0-30] 17 58 08 5d [0-50] 59 20 00 01 00 00 58 20 ff 00 00 00 5f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AMA_2147921784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AMA!MTB"
        threat_id = "2147921784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 13 04 11 04 06 11 04 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 06 11 04 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 08 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 06 de 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ZPAA_2147924274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ZPAA!MTB"
        threat_id = "2147924274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 25 26 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? 00 00 0a 32 b2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_NH_2147927401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.NH!MTB"
        threat_id = "2147927401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {73 0a 00 00 0a 0a 06 74 16 00 00 01 73 0b 00 00 0a 0b 17 13 04 2b bf 07 74 19 00 00 01 02 7b 04 00 00 04 20 b8 03 00 00 20 98 03 00 00 28 05 00 00 2b 20 0f 03 00 00 20 40 03 00 00 28}  //weight: 3, accuracy: High
        $x_1_2 = "sZIp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_AMAF_2147927684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.AMAF!MTB"
        threat_id = "2147927684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 19 11 0a 11 29 11 22 61 11 1e 19 58 61 11 2c 61 d2 9c 11 22 13 1e 17 11 0a 58 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MX_2147933714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MX!MTB"
        threat_id = "2147933714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MeshPods.exe" ascii //weight: 1
        $x_1_2 = "7a4427c2-4773-477e-8f1b-69ac01ffa85a" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_ATRA_2147939796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.ATRA!MTB"
        threat_id = "2147939796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 15 00 11 15 17 6f ?? 00 00 0a 00 11 15 18 6f ?? 00 00 0a 00 11 15 09 6f ?? 00 00 0a 00 11 15 11 09 6f ?? 00 00 0a 00 11 15 6f ?? 00 00 0a 11 0a 16 11 0a 8e 69 6f ?? 00 00 0a 13 0c 00 de 0d}  //weight: 5, accuracy: Low
        $x_2_2 = {06 11 0f 7e ?? 00 00 04 11 0f 91 7e ?? 00 00 04 61 d2 9c 11 0f 17 58 13 0f 11 0f 7e ?? 00 00 04 8e 69 fe 04 13 10 11 10 2d d6}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_PP_2147949923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.PP!MTB"
        threat_id = "2147949923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 08 8d 0d 00 00 01 13 0a 7e ?? ?? ?? 04 02 1a 58 11 0a 16 11 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 13 0b 7e ?? ?? ?? 04 11 0b 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 02 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 17 59 28 ?? ?? ?? 0a 16 7e ?? ?? ?? 04 02 1a 28 ?? ?? ?? 0a 11 0b 13 09 dd}  //weight: 2, accuracy: Low
        $x_1_2 = "gljNUSsHFDwliDattkBofEezfcXtD" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Nanocore_MZV_2147951077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nanocore.MZV!MTB"
        threat_id = "2147951077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nanocore"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 08 8e b7 17 59 13 0e 13 0d 2b 15 08 11 0d 08 11 0d 91 02 11 0d 03 5d 91 61 9c 11 0d 17 58 13 0d 11 0d 11 0e 31 e5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

