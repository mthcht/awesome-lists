rule Trojan_MSIL_SmokeLoader_RPM_2147821961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.RPM!MTB"
        threat_id = "2147821961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 28 73 00 00 06 0c 02 28 69 00 00 06 08 02 7e 05 00 00 04 20 17 01 00 00 28 af 00 00 06 28 61 00 00 06 0c 14}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_NEA_2147828313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.NEA!MTB"
        threat_id = "2147828313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PortableApps.com" ascii //weight: 1
        $x_1_2 = "DOSBox Portable" ascii //weight: 1
        $x_1_3 = "2.2.1.0" ascii //weight: 1
        $x_1_4 = "Rare Ideas" ascii //weight: 1
        $x_1_5 = "Bqiai9hPj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_EA_2147831391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.EA!MTB"
        threat_id = "2147831391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 03 17 58 13 03 38 a3 ff ff ff 11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 03 11 03 91 61 d2 9c}  //weight: 3, accuracy: High
        $x_3_2 = "Nvcxtw" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GJ_2147834302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GJ!MTB"
        threat_id = "2147834302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 19 1a 2d 16 26 03 1a 1d 2d 13 26 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 2b 06 26 2b e8 26 2b eb 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "filifilm.com.br/images/" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_NEAA_2147834394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.NEAA!MTB"
        threat_id = "2147834394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 12 03 28 1e 00 00 0a 06 07 02 07 18 6f 1f 00 00 0a 1f 10 28 20 00 00 0a 6f 21 00 00 0a de 0a}  //weight: 10, accuracy: High
        $x_5_2 = "filifilm.com.br" wide //weight: 5
        $x_2_3 = "Soccer" ascii //weight: 2
        $x_2_4 = "Basketball" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GBI_2147836952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GBI!MTB"
        threat_id = "2147836952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 04 17 58 13 04 11 04 20 00 01 00 00 5d 13 04 11 06 11 0a 11 04 94 58 13 06 11 06 20 00 01 00 00 5d 13 06 11 0a 11 04 94 13 08 11 0a 11 04 11 0a 11 06 94 9e 11 0a 11 06 11 08 9e 11 0a 11 0a 11 04 94 11 0a 11 06 94 58 20 00 01 00 00 5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95}  //weight: 10, accuracy: High
        $x_1_2 = "Program_Playing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_RS_2147837259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.RS!MTB"
        threat_id = "2147837259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 02 13 04 38 1e 00 00 00 38 45 00 00 00 38 8f 00 00 00 11 01 8e 69 17 da 17 d6 8d 7e 00 00 01 13 02 38 73}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_AM_2147838080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.AM!MTB"
        threat_id = "2147838080"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 44 2b 45 2b 4a 2b 4b 18 5b 1e 2c 24 8d 2a 00 00 01 2b 42 16 2b 42 2b 1e 2b 41 2b 42 18 5b 2b 41 08 18 6f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GDI_2147839258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GDI!MTB"
        threat_id = "2147839258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iccoperadora.com.br/erros_OLD" ascii //weight: 1
        $x_1_2 = "m8DAF7628E17C685" ascii //weight: 1
        $x_1_3 = "f8DAF7628E17ADA5" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GEG_2147840461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GEG!MTB"
        threat_id = "2147840461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V2FpdEZvclNpbmdsZU9iamVjdA==" ascii //weight: 1
        $x_1_2 = "XzAwN1N0dWIuUHJvcGVydGllcy5SZXNvdXJjZXM=" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GFM_2147842978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GFM!MTB"
        threat_id = "2147842978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 01 00 00 70 2b 14 2b 19 2b 1e 1e 2d 06 26 16 2d ee de 22 2b 1a 1d 2c f6 2b f4 28 ?? ?? ?? 06 2b e5 28 ?? ?? ?? 2b 2b e0 28 ?? ?? ?? 2b 2b db 0a 2b e3}  //weight: 10, accuracy: Low
        $x_1_2 = "192.3.27.140" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_GFT_2147843172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.GFT!MTB"
        threat_id = "2147843172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 1d 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 19 2d 06 26 de 09 0a 2b e2 0b 2b f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_RDG_2147847339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.RDG!MTB"
        threat_id = "2147847339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 07 11 07 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 07 17 d6 13 07 11 07 11 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_RDR_2147897741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.RDR!MTB"
        threat_id = "2147897741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 2f 00 00 0a 6f 30 00 00 0a 1f 0a 0d 11 04 6f 31 00 00 0a 13 05 1f 0b 0d 11 05 02 16 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_LL_2147901430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.LL!MTB"
        threat_id = "2147901430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 58 4a 61 d2 61 d2 52 ?? ?? ?? ?? fe 0c 05 00 ?? ?? ?? ?? ?? 25 47 fe 0c ?? ?? ?? ?? ?? ?? 91 61 d2 52}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_LA_2147901433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.LA!MTB"
        threat_id = "2147901433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 ?? ?? ?? ?? ?? 0e 06 17 59 95 58 0e 05 28 cb 0d ?? ?? 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_RDAB_2147917072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.RDAB!MTB"
        threat_id = "2147917072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 08 17 73 08 00 00 0a 13 03 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_ZVT_2147943885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.ZVT!MTB"
        threat_id = "2147943885"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 11 11 11 18 6f ?? 00 00 0a 13 19 11 08 1f 64 6a 5d 16 6a fe 01 13 25 11 25 39 8c 00 00 00 00 72 75 14 00 70 1d 8d 10 00 00 01 25 16 11 11}  //weight: 6, accuracy: Low
        $x_5_2 = {a2 25 18 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 19 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 1a 12 19 28 ?? 00 00 0a 8c 57 00 00 01 a2 25 1b 11 04 8c 51 00 00 01 a2 25}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SmokeLoader_EM_2147952171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SmokeLoader.EM!MTB"
        threat_id = "2147952171"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 16 11 17 11 18 61 58 13 16 11 18 17 58 13 18 11 18 18 32 eb}  //weight: 1, accuracy: High
        $x_1_2 = "CreateFileMapping" ascii //weight: 1
        $x_1_3 = "MapViewOfFile" ascii //weight: 1
        $x_1_4 = "VirtualProtect" ascii //weight: 1
        $x_1_5 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

