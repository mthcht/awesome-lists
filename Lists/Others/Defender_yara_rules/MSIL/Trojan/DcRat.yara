rule Trojan_MSIL_DcRat_NE_2147828115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NE!MTB"
        threat_id = "2147828115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 91 13 05 08 12 05 72 3b 19 00 70 28 c5 00 00 0a 6f c6 00 00 0a 26 11 04 17 58 13 04 11 04 09 8e 69 32 da}  //weight: 1, accuracy: High
        $x_1_2 = "VmlydHVhbFByb3RlY3Q=" wide //weight: 1
        $x_1_3 = "YW1zaS5kbGw=" wide //weight: 1
        $x_1_4 = "QW1zaVNjYW5CdWZmZXI=" wide //weight: 1
        $x_1_5 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" wide //weight: 1
        $x_1_6 = "timeout 3 > NUL" wide //weight: 1
        $x_1_7 = "DcRatByqwqdanchun" wide //weight: 1
        $x_1_8 = "ms-settings" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEA_2147828743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEA!MTB"
        threat_id = "2147828743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ppEnumMoniker" ascii //weight: 1
        $x_1_2 = "6595b64144ccf1df" ascii //weight: 1
        $x_1_3 = "ConfuserEx v1.0.0" ascii //weight: 1
        $x_1_4 = "UmVjZWl2ZWQ=" wide //weight: 1
        $x_1_5 = "YW1zaS5kbGw=" wide //weight: 1
        $x_1_6 = "MSASCui.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEB_2147830088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEB!MTB"
        threat_id = "2147830088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 06 91 20 ad 02 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEC_2147832563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEC!MTB"
        threat_id = "2147832563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f e8 00 00 0a 74 07 00 00 01 1a 1b 1f 16 73 98 01 00 0a 6f 09 00 00 0a 28 2a 04 00 06 00 02}  //weight: 5, accuracy: High
        $x_3_2 = "kLjw4iIsCLsZtxc4lksN0j" ascii //weight: 3
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "get_ProcessName" ascii //weight: 1
        $x_1_5 = "$$method0x600005f-1" ascii //weight: 1
        $x_1_6 = "get_Is64BitOperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NED_2147833503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NED!MTB"
        threat_id = "2147833503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QMYwDxuLTu" ascii //weight: 2
        $x_2_2 = "WRLV1lXIsW" ascii //weight: 2
        $x_2_3 = "WjIxKjbeN0" ascii //weight: 2
        $x_2_4 = "CAaUAAkey5" ascii //weight: 2
        $x_2_5 = "pHRtte0RL5" ascii //weight: 2
        $x_1_6 = "get_ProcessorCount" ascii //weight: 1
        $x_1_7 = "ProcessWindowStyle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAA_2147835726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAA!MTB"
        threat_id = "2147835726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {12 02 28 25 01 00 0a 0d 02 12 03 28 27 01 00 0a 12 03 28 26 01 00 0a 6f c5 00 00 0a 10 00 12 02 28 28 01 00 0a 3a d6 ff ff ff}  //weight: 10, accuracy: High
        $x_5_2 = "r8l9sJLpsKxKbG121Ze" ascii //weight: 5
        $x_5_3 = "pDAdB3l3wA3XugWFNdq" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAB_2147838572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAB!MTB"
        threat_id = "2147838572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 38 00 00 0a 25 28 0a 33 00 06 28 39 00 00 0a 73 3a 00 00 0a 28 3b 00 00 0a 26 2a}  //weight: 5, accuracy: High
        $x_2_2 = "https://transfer.sh/get" wide //weight: 2
        $x_2_3 = "ExecuteBytes.txt" wide //weight: 2
        $x_2_4 = "nazaMW487.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAC_2147838650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAC!MTB"
        threat_id = "2147838650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 45 2b 47 2b 48 2b 4a 2b 4f 18 6f ?? 00 00 0a 28 07 00 00 06 25 26 13 05 08 6f ?? 00 00 0a 11 05 16 11 05 28 56 00 00 06 25 26 69 6f ?? 00 00 0a 13 06 dd 71 00 00 00 09 2b c1 07 2b c0}  //weight: 10, accuracy: Low
        $x_5_2 = "http://45.93.201.62" wide //weight: 5
        $x_2_3 = "Powered by SmartAssembly 8.1.2.4975" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAD_2147838734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAD!MTB"
        threat_id = "2147838734"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "1643789f-17b9-43e6-8773-54154fbeacbb" ascii //weight: 5
        $x_5_2 = "media.exe" ascii //weight: 5
        $x_2_3 = "telkom_preview" ascii //weight: 2
        $x_2_4 = "Media Payment" ascii //weight: 2
        $x_2_5 = "salah_nontaglis_kolektif_ara" ascii //weight: 2
        $x_2_6 = "pemakaian" ascii //weight: 2
        $x_2_7 = "txtpassword" ascii //weight: 2
        $x_2_8 = "WriteRawDataToTxtFile2_RPI_epos" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_RD_2147839881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.RD!MTB"
        threat_id = "2147839881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 1a 72 37 03 00 70 a2 25 1b 7e c2 00 00 04 28 dc 00 00 0a 28 07 02 00 06 a2 25 1c 72 9e 09 00 70 a2 25 1d 06 a2 25 1e 72 71 00 00 70 a2 28 f8 00 00 0a 0b 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAF_2147841309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAF!MTB"
        threat_id = "2147841309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 5
        $x_2_2 = "NETSecure, a .NET obfuscation program" ascii //weight: 2
        $x_2_3 = "ProtectedWithCryptoObfuscatorAttribute" ascii //weight: 2
        $x_2_4 = "ObfuscatedByAgileDotNetAttribute" ascii //weight: 2
        $x_2_5 = "BabelObfuscatorAttribute" ascii //weight: 2
        $x_2_6 = "AICustomPropertyProviderProxy" ascii //weight: 2
        $x_2_7 = "GetDynamicILInfo" ascii //weight: 2
        $x_2_8 = "System.Reflection.Emit" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAG_2147842566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAG!MTB"
        threat_id = "2147842566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 02 11 04 09 6f ?? 00 00 0a 13 05 06 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 11 04 17 58 13 04 11 04 07 fe 02 16 fe 01 13 06 11 06 2d d1 00 09 17 58 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAE_2147843322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAE!MTB"
        threat_id = "2147843322"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 3c 00 00 01 25 d0 0a 06 00 04 28 78 01 00 0a 6f dd 01 00 0a 06 07 6f de 01 00 0a 17 73 8a 01 00 0a}  //weight: 5, accuracy: High
        $x_2_2 = "System.Reflection.RuntimeModule" wide //weight: 2
        $x_2_3 = "Eziriz's \".NET Reactor\"" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NEAH_2147844544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NEAH!MTB"
        threat_id = "2147844544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 28 1b 00 00 06 0a 28 12 00 00 0a 06 6f 13 00 00 0a 28 14 00 00 0a 28 0f 00 00 06 0b dd 03 00 00 00 26 de db 07 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_NZA_2147928807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.NZA!MTB"
        threat_id = "2147928807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "U09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVuXA==" ascii //weight: 2
        $x_1_2 = "L2Mgc2NodGFza3MgL2NyZWF0ZSAvZiAvc2Mgb25sb2dvbiAvcmwgaGlnaGVzdCAvdG4g" ascii //weight: 1
        $x_1_3 = "VmlydHVhbFByb3RlY3Q=" ascii //weight: 1
        $x_1_4 = "QW1zaVNjYW5CdWZmZXI=" ascii //weight: 1
        $x_1_5 = "DcRatByqwqdanchun" ascii //weight: 1
        $x_1_6 = "Anti_virus" ascii //weight: 1
        $x_1_7 = "ProcessHacker.exe" ascii //weight: 1
        $x_1_8 = "procexp.exe" ascii //weight: 1
        $x_1_9 = "ConfigSecurityPolicy.exe" ascii //weight: 1
        $x_1_10 = "Select * from AntivirusProduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_PLLBH_2147929808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.PLLBH!MTB"
        threat_id = "2147929808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 09 02 09 91 06 08 91 61 09 20 00 01 00 00 5d 61 d2 9c 08 07 09 91 06 8e 69 5d 58 06 8e 69 5d 0c 09 17 58 0d 09 02 8e 69 32 d5}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_ZTY_2147941595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.ZTY!MTB"
        threat_id = "2147941595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 09 18 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 04 07 73 ?? 00 00 0a 11 04 16 73 ?? 00 00 0a 28 ?? 00 00 0a 73 ?? 00 00 0a 6f ?? 00 00 0a 13 05}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DcRat_ZNR_2147946241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DcRat.ZNR!MTB"
        threat_id = "2147946241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DcRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 11 06 11 05 6f ?? 00 00 0a 13 07 09 11 04 20 ff 00 00 00 12 07 28 ?? 00 00 0a 59 1f 72 61 d2 9c 11 06 17 58 13 06 11 04 17 58 13 04 11 06 07 2f 07 11 04 09 8e 69 32 c7 11 05 17 58 13 05 11 05 08 32 b7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

