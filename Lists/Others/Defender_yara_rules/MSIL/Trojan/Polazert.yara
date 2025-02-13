rule Trojan_MSIL_Polazert_ADF_2147779588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.ADF!MTB"
        threat_id = "2147779588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {16 0c 16 0d 2b 27 00 07 08 07 08 91 06 09 91 61 d2 9c 09 17 58 06 8e 69 fe 04 13 05 11 05 2d 04 16 0d 2b 04 09 17 58 0d 08 17 58 0c 00 08 07 8e 69 fe 04 13 05 11 05 2d cd}  //weight: 11, accuracy: High
        $x_5_2 = "Win32_ComputerSystem.Name='{0}'" ascii //weight: 5
        $x_2_3 = "IsAdmin" ascii //weight: 2
        $x_2_4 = "GetWinVersion" ascii //weight: 2
        $x_2_5 = "GetUserName" ascii //weight: 2
        $x_2_6 = "GetComputerName" ascii //weight: 2
        $x_2_7 = "EncryptXor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_2147795859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert!MTB"
        threat_id = "2147795859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DelegateResumeThread" ascii //weight: 1
        $x_1_2 = "DelegateWow64SetThreadContext" ascii //weight: 1
        $x_1_3 = "DelegateSetThreadContext" ascii //weight: 1
        $x_1_4 = "DelegateWow64GetThreadContext" ascii //weight: 1
        $x_1_5 = "DelegateGetThreadContext" ascii //weight: 1
        $x_1_6 = "DelegateVirtualAllocEx" ascii //weight: 1
        $x_1_7 = "DelegateWriteProcessMemory" ascii //weight: 1
        $x_1_8 = "DelegateReadProcessMemory" ascii //weight: 1
        $x_1_9 = "DelegateZwUnmapViewOfSection" ascii //weight: 1
        $x_1_10 = "DelegateCreateProcessA" ascii //weight: 1
        $x_1_11 = "ProcessInformation" ascii //weight: 1
        $x_1_12 = "StartupInformation" ascii //weight: 1
        $x_1_13 = "temp" wide //weight: 1
        $x_1_14 = ".exe" wide //weight: 1
        $x_1_15 = ".ps1" wide //weight: 1
        $x_1_16 = "powershell" wide //weight: 1
        $x_1_17 = "-ExecutionPolicy bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_M_2147814744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.M!MTB"
        threat_id = "2147814744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "deimos.dll" ascii //weight: 3
        $x_3_2 = "HttpWebResponse" ascii //weight: 3
        $x_3_3 = "HttpStatusCode" ascii //weight: 3
        $x_3_4 = "RandomNumberGenerator" ascii //weight: 3
        $x_3_5 = "mjEdL1E3KmSlrkWx" ascii //weight: 3
        $x_3_6 = "RSACryptoServiceProvider" ascii //weight: 3
        $x_3_7 = "IjmW0zvWjgKIQNRFbZkg" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_NL_2147822003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.NL!MTB"
        threat_id = "2147822003"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 06 08 91 07 08 91 61 d2 9c 00 08 17 58 0c 08 20 ?? 01 00 00 fe 04 13 04 11 04 2d e1}  //weight: 1, accuracy: Low
        $x_1_2 = {57 9f a2 3d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {4e 45 00 52 65 67 4f 70 65 6e 4b 65 79 45 78 00 53 79 73 74 65 6d 2e 54 65 78 74 00 53 74 72 69 6e 67 42 75 69 6c 64 65 72 00 52 65 67 51 75 65 72 79 56 61 6c 75 65 45}  //weight: 1, accuracy: High
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "RSACryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_NM_2147822847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.NM!MTB"
        threat_id = "2147822847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 c9 09 0a 00 00 00 fa 25 33 00 16 00 00 57 00 00 00 3b 00 00 00 04 00 00 00 15 00 00 00 21 00 00 00 1d 00 00 00 6f 00 00 00 03 00 00 00 1a 00 00 00 12 00 00 00 01 00 00 00 03 00 00 00 03 00 00 00 06}  //weight: 1, accuracy: High
        $x_1_2 = "SbygmWjfiwehybpml" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_NU_2147823620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.NU!MTB"
        threat_id = "2147823620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9f a2 3d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 3b 00 00 00 27 00 00 00 ce 00 00 00 f4 00 00 00 5b 00 00 00 03 00 00 00 77 00 00 00 17 00 00 00 04 00 00 00 14 00 00 00 55 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {57 1f a2 09 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 44 00 00 00 14 00 00 00 dc 00 00 00 f0 00 00 00 95 00 00 00 03 00 00 00 8c 00 00 00 16 00 00 00 32 01 00 00 34 00 00 00 01 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_3 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 13 00 00 00 2d 01 00 00 e3 01 00 00 af 00 00 00 04 00 00 00 87 00 00 00 16 00 00 00 dc 01 00 00 8c 00 00 00 01 00 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_Polazert_ARA_2147836781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.ARA!MTB"
        threat_id = "2147836781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 47 06 09 91 61 d2 52 09 17 58 06 8e 69 32 04 16 0d 2b 04 09 17 58 0d 08 17 58 0c 08 07 8e 69 32 d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_ARA_2147836781_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.ARA!MTB"
        threat_id = "2147836781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 0c 17 0d 2b 1c 00 07 08 5d 16 6a fe 01 16 fe 01 13 04 11 04 2d 05 00 16 0d 2b 15 08 17 6a 58 0c 00 08 08 5a 07 fe 02 16 fe 01 13 04 11 04 2d d5 08 17 6a fe 04 16 fe 01 13 04 11 04 2d 02 2b 0b 07 17 6a 58 0b 00 17 13 04 2b 95}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_DA_2147837053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.DA!MTB"
        threat_id = "2147837053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_40_1 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 13 00 00 00 36 01 00 00}  //weight: 40, accuracy: High
        $x_40_2 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 48 00 00 00 13 00 00 00 31 01 00 00}  //weight: 40, accuracy: High
        $x_40_3 = {57 1f a2 1d 09 02 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 47 00 00 00 13 00 00 00 35 01 00 00}  //weight: 40, accuracy: High
        $x_1_4 = "GetRequestStream" ascii //weight: 1
        $x_1_5 = "GetResponseStream" ascii //weight: 1
        $x_1_6 = "WebException" ascii //weight: 1
        $x_1_7 = "FromXmlString" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "get_MachineName" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "QueueUserWorkItem" ascii //weight: 1
        $x_1_12 = "Convert" ascii //weight: 1
        $x_1_13 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_40_*) and 10 of ($x_1_*))) or
            ((2 of ($x_40_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Polazert_RS_2147837787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.RS!MTB"
        threat_id = "2147837787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "zkabsr" wide //weight: 4
        $x_1_2 = "GetEnvironmentVariable" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "GetEnumerator" ascii //weight: 1
        $x_1_5 = "KeyValuePair" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "get_MachineName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Polazert_RSD_2147839939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.RSD!MTB"
        threat_id = "2147839939"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "A+Aa+A" wide //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "KeyValuePair" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "ReadByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Polazert_A_2147889118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polazert.A!MTB"
        threat_id = "2147889118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polazert"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "W1JlZmxlY3Rpb24uQXNzZW1ibHldOjpMb2FkK" wide //weight: 2
        $x_2_2 = "kNyZWF0ZURlY3J5cHRvci" wide //weight: 2
        $x_2_3 = "lRyYW5zZm9ybUZpbmFsQmxvY2s" wide //weight: 2
        $x_2_4 = "1bTWF0aF06OlJvdW5kKChHZXQtRGF0ZSkuVG9GaWxlVGltZVVUQygp" wide //weight: 2
        $x_2_5 = "i5MZW5ndGg" wide //weight: 2
        $x_2_6 = "soTmV3LU9iamVjdCBTeXN0ZW0uTmV0LldlYkNsaWVudCkuRG93bmxvYWRGaWxlKC" wide //weight: 2
        $x_2_7 = "7U3RhcnQtUHJvY2Vzcy" wide //weight: 2
        $x_2_8 = "1OZXctT2JqZWN0IFN5c3RlbS5TZWN1cml0eS5DcnlwdG9ncmFwaHkuQWVzQ3J5cHRvU2VydmljZVByb3ZpZGVy" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

