rule Trojan_MSIL_Tedy_EM_2147828900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.EM!MTB"
        threat_id = "2147828900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 0c 1a 11 0c 1a 95 11 0d 1a 95 5a 9e 11 0c 1b 11 0c 1b 95 11 0d 1b 95 58 9e 11 17}  //weight: 4, accuracy: High
        $x_1_2 = "WinMedia" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NEAA_2147835619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NEAA!MTB"
        threat_id = "2147835619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 2d f0 16 2d cd 1b 2c ea 2a 28 5f 00 00 0a 2b d4 28 41 00 00 0a 2b d9 28 0d 00 00 0a 2b d6 6f 60 00 00 0a 2b d1 6f 61 00 00 0a 2b ce}  //weight: 10, accuracy: High
        $x_5_2 = "OnStealer" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NEB_2147835900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NEB!MTB"
        threat_id = "2147835900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "ZosZaposlenNaRadnomMjestuColumn" ascii //weight: 5
        $x_5_2 = "get_iznosBezPDVColumn" ascii //weight: 5
        $x_5_3 = "ZirsLocal.exe" ascii //weight: 5
        $x_5_4 = "HouseOfCards" ascii //weight: 5
        $x_4_5 = "aspnet_wp.exe" wide //weight: 4
        $x_4_6 = "w3wp.exe" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NEAB_2147837968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NEAB!MTB"
        threat_id = "2147837968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 07 1f 0f 1f 10 28 5b 01 00 06 7e 08 01 00 04 06 07 28 3a 01 00 06 7e 26 01 00 04 06 18 28 5e 01 00 06 7e 0c 01 00 04 06 28 3d 01 00 06 0d 7e 28 01 00 04 09 03 16 03 8e 69}  //weight: 5, accuracy: High
        $x_2_2 = "somerandomfile" wide //weight: 2
        $x_2_3 = "dfagnmbhbSbma" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NCY_2147838210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NCY!MTB"
        threat_id = "2147838210"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 15 00 00 0a 0d 08 19 18 73 ?? ?? ?? 0a 0a 09 07 16 07 8e 69 6f ?? ?? ?? 0a 00 06 09 6f ?? ?? ?? 0a 16 09 6f ?? ?? ?? 0a 8e 69 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "FreeWayPhantom" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NTD_2147839726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NTD!MTB"
        threat_id = "2147839726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0a 6f 2d 00 00 0a 11 15 16 11 13 6f ?? 00 00 0a 13 14 11 16 11 15 16 11 14 6f ?? 00 00 0a 00 00 11 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 1a 11 1a 2d cc}  //weight: 5, accuracy: Low
        $x_1_2 = "z0FSAmmz" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NEAC_2147839968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NEAC!MTB"
        threat_id = "2147839968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 fe 0c 00 00 20 01 00 00 00 fe 01 39 24 00 00 00 00 28 33 00 00 0a 72 37 05 00 70 28 34 00 00 0a 6f 35 00 00 0a 28 40 00 00 0a 26}  //weight: 10, accuracy: High
        $x_5_2 = "aHR0cHM6Ly90Lm1lL1JlcnVsbG8=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AT_2147840275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AT!MTB"
        threat_id = "2147840275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 6a 0a 2b 05 06 17 6a 58 0a 06 04 34 0c 02 06 58 02 06 58 47 03 61 52 2b eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AT_2147840275_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AT!MTB"
        threat_id = "2147840275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 06 91 1f 48 33 1d 03 06 17 58 91 1f 43 33 14 03 06 18 58 91 1f 46 33 0b 03 06 19 58 91 1f 47 33 02 06 2a 06 1a 59 0a 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AT_2147840275_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AT!MTB"
        threat_id = "2147840275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 16 03 02 73 ?? 00 00 0a a2 73 ?? 00 00 0a 28 ?? ?? ?? 0a 0d 08 09 6f ?? ?? ?? 0a 00 00 de 0b 08 2c 07 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AT_2147840275_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AT!MTB"
        threat_id = "2147840275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 14 00 00 0a 25 72 20 01 00 70 04 6f 15 00 00 0a 00 25 72 32 01 00 70 03 6f 15 00 00 0a 00 28 01 00 00 06 26 2a}  //weight: 2, accuracy: High
        $x_1_2 = "sendWebHook" ascii //weight: 1
        $x_1_3 = "Web Dropper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AT_2147840275_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AT!MTB"
        threat_id = "2147840275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 00 07 0c 16 0d 2b 32 08 09 9a 13 04 00 11 04 25 2d 04 26 14 2b 05 6f 23 00 00 0a 72 a9 a0 00 70 28 36 00 00 0a 0a 06 28 2c 00 00 0a 13 05 11 05 2c 02 2b 0b 00 09 17 58 0d 09 08 8e 69 32 c8}  //weight: 2, accuracy: High
        $x_1_2 = "lloosstt" wide //weight: 1
        $x_1_3 = "iomDome.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ND_2147840343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ND!MTB"
        threat_id = "2147840343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 47 06 11 0e 06 8e 69 5d 91 61 d2 52 11 0e 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ND_2147840343_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ND!MTB"
        threat_id = "2147840343"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f c3 00 00 0a 07 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08}  //weight: 5, accuracy: Low
        $x_1_2 = "add_ResourceResolve" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "wifi.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NCD_2147840801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NCD!MTB"
        threat_id = "2147840801"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 6f 32 00 00 0a 0d 06 09 28 ?? ?? 00 0a 13 04 12 04 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 26 08 17 58 0c 08 07 6f ?? ?? 00 0a 32 d0}  //weight: 5, accuracy: Low
        $x_1_2 = "Login Page Design UI" ascii //weight: 1
        $x_1_3 = "13.228.77.79" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NYE_2147841231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NYE!MTB"
        threat_id = "2147841231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 04 28 ?? 00 00 06 00 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 08 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "TFA.Data.FormSecret.resources" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_CXQ_2147843366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.CXQ!MTB"
        threat_id = "2147843366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 28 12 00 00 0a 02 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 00 08 06 6f ?? ?? ?? ?? 00 08 08 6f ?? ?? ?? ?? 08 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 07 73 ?? ?? ?? ?? 13 04}  //weight: 5, accuracy: Low
        $x_1_2 = "http://178.20.46.149" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NTY_2147843464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NTY!MTB"
        threat_id = "2147843464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 07 1e 02 8e 69 59 02 8e 69 28 ?? 00 00 0a 07 16 07 8e 69 1a 5b 1a 5a 03}  //weight: 5, accuracy: Low
        $x_1_2 = "Novaline Installer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NTY_2147843464_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NTY!MTB"
        threat_id = "2147843464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 6f ?? ?? ?? 0a 0a 02 7b ?? ?? ?? 04 06 6f ?? ?? ?? 0a 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 1e 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 26 72 ?? ?? ?? 70}  //weight: 5, accuracy: Low
        $x_1_2 = "bigballsvirus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NTY_2147843464_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NTY!MTB"
        threat_id = "2147843464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7b 02 00 00 0a 0a 12 00 25 71 ?? 00 00 1b 8c ?? 00 00 1b 3a ?? 00 00 00 26 14 38 ?? 00 00 00 fe ?? ?? ?? ?? 1b 6f ?? 00 00 0a a2 25 17 02 7b ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "cruzza28Gvfix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSII_2147843938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSII!MTB"
        threat_id = "2147843938"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 28 19 00 00 0a 0a 06 02 7b 01 00 00 04 02 28 01 00 00 06 0b 28 1a 00 00 0a 07 6f 1b 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSKD_2147844065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSKD!MTB"
        threat_id = "2147844065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 df 00 00 0a 1a 3b 0a 00 00 00 7e ae 00 00 04 38 05 00 00 00 7e ad 00 00 04 0b 7e e2 00 00 0a 07 8e 69 73 f7 00 00 0a 20 00 30 00 00 1f 40 28 80 01 00 06 0a 07 16 06 07 8e 69 28 f8 00 00 0a 06 d0 2d 00 00 02 28 63 00 00 0a 28 f9 00 00 0a 74 2d 00 00 02 0c 12 03 fe 15 94 00 00 01 1a 8d 7b 00 00 01 13 04 11 04 19 28 fa 00 00 0a 0d 08 02 11 04 6f 9b 01 00 06 dd 1d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 1f 0c 13 07 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 17 28 13 00 00 0a a2 25 18 72 e5 00 00 70 a2 25 19 28 14 00 00 0a a2 25 1a 72 fb 00 00 70 a2 25 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 11 04 13 05 11 05 13 06 16 13 07 2b 19 00 09 06 07 11 07 91 06 8e 69 5d 93 6f 6d 00 00 0a 26 00 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 08 06 1a 06 8e b7 1a da 6f 3a 00 00 0a 11 04 17 da 17 d6 8d 2f 00 00 01 0d 08 16 6a 6f 3b 00 00 0a 08 16 73 3c 00 00 0a 13 05 11 05 09 16 09 8e b7}  //weight: 2, accuracy: High
        $x_1_2 = "loveInvokehappy" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 61 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd 03 00 00 00 26 de d6}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATD_2147844445_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATD!MTB"
        threat_id = "2147844445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 28 00 06 28 ?? ?? ?? 06 0b 07 20 01 80 00 00 fe 01 0c 08 2c 0f 00 7e ?? ?? ?? 04 06 d1 6f ?? ?? ?? 0a 26 00 00 06 17 58}  //weight: 2, accuracy: Low
        $x_1_2 = "CaptureAndSaveScreenshot" ascii //weight: 1
        $x_1_3 = "Nueva carpeta\\logs.txt" wide //weight: 1
        $x_1_4 = "Nueva carpeta\\screenshot.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ADY_2147844446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ADY!MTB"
        threat_id = "2147844446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 73 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd 03 00 00 00 26 de d6}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_CSWK_2147845687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.CSWK!MTB"
        threat_id = "2147845687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 72 9d 00 00 70 28 ?? ?? ?? ?? 00 02 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 20 ?? ?? ?? ?? 28 ?? ?? ?? ?? 00 06 0c 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0d 72 45 01 00 70 13 04 72 77 01 00 70 13 05 1d}  //weight: 5, accuracy: Low
        $x_1_2 = "taskkill.exe /F /IM \"chrome.exe\"" wide //weight: 1
        $x_1_3 = "taskkill.exe /F /IM \"chromedriver.exe\"" wide //weight: 1
        $x_1_4 = "/System/109" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATE_2147845844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATE!MTB"
        threat_id = "2147845844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 6b 00 00 70 28 ?? ?? ?? 06 0a 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 0b dd 03 00 00 00 26 de d6}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0a 02 8e 69 17 59 0b 38 16 00 00 00 02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATE_2147845844_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATE!MTB"
        threat_id = "2147845844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 12 04 28 ?? ?? ?? 0a 0d 1e 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 25 17 09 a2 25 18 72 ?? ?? ?? 70 a2 25 19 07 a2 25 1a 72 ?? ?? ?? 70 a2 25 1b 08 a2 25 1c 72 ?? ?? ?? 70 a2 25 1d 06 a2}  //weight: 2, accuracy: Low
        $x_1_2 = "vt_test\\obj\\Release\\vt_test.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATE_2147845844_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATE!MTB"
        threat_id = "2147845844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f 0a fe 02 13 08 11 08 2c 1c 00 72 01 00 00 70 7e 01 00 00 04 28 19 00 00 0a 00 72 1d 00 00 70 80 01 00 00 04 00 00 06 1f 20 fe 01 13 09 11 09 2c 1a}  //weight: 2, accuracy: High
        $x_1_2 = "KeyLoggerDemo\\KeyLoggerDemo\\obj\\Debug\\KeyLoggerDemo.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSMP_2147846150_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSMP!MTB"
        threat_id = "2147846150"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0c 2b 15 02 28 13 00 00 0a 0a 28 14 00 00 0a 06 6f 15 00 00 0a 0c 2b 00 08 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSMJ_2147846246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSMJ!MTB"
        threat_id = "2147846246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 13 00 00 0a 72 01 00 00 70 28 03 00 00 06 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 04 2b 30 11 04 6f ?? ?? ?? 0a 74 1e 00 00 01 72 63 00 00 70 28 03 00 00 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 1b 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_SPH_2147846381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.SPH!MTB"
        threat_id = "2147846381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SvnTcpnNet.lib" ascii //weight: 1
        $x_1_2 = "SvnTcpnNet.jsonModels.SSH" ascii //weight: 1
        $x_1_3 = "SvnTcpnNet.jsonModels.FTP" ascii //weight: 1
        $x_1_4 = "SvnTcpnNet.jsonModels.Screenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSMK_2147846443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSMK!MTB"
        threat_id = "2147846443"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 0f 00 00 0a 0a 06 72 01 00 00 70 6f ?? ?? ?? 0a 00 06 72 1f 00 00 70 6f ?? ?? ?? 0a 00 06 17 6f ?? ?? ?? 0a 00 06 16 6f 13 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSNB_2147847076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSNB!MTB"
        threat_id = "2147847076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 72 89 02 00 70 28 10 00 00 06 06 72 bb 02 00 70 72 07 03 00 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 02 72 0f 03 00 70 28 10 00 00 06 08 16 20 62 03 00 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 25 07 17 28 0b 00 00 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ARA_2147847477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ARA!MTB"
        threat_id = "2147847477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 91 0d 06 07 06 08 91 9c 06 08 09 d2 9c 07 17 58 0b 08 17 59 0c 07 08 32 e5}  //weight: 2, accuracy: High
        $x_2_2 = "Ehjioger" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ARA_2147847477_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ARA!MTB"
        threat_id = "2147847477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Keylogger started, see keyloggs at http://{vicitm IP}:8080/keylogger/keylogg.txt" ascii //weight: 2
        $x_2_2 = "\\ransomware.bat" ascii //weight: 2
        $x_2_3 = "\\output_firefox.txt" ascii //weight: 2
        $x_2_4 = "Usage: steal_pwd <firefox/google>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NBA_2147847500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NBA!MTB"
        threat_id = "2147847500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 26 00 00 0a 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 04 28 ?? 00 00 06 16 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 06 07 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "CTools.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSOY_2147847872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSOY!MTB"
        threat_id = "2147847872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 6f 6e 00 00 0a 72 87 0a 00 70 72 9f 00 00 70 6f 6f 00 00 0a 17 8d 40 00 00 01 25 16 1f 2c 9d 6f 70 00 00 0a 0a 20 ff 00 00 00 06 16 9a 28 71 00 00 0a 06 17 9a 28 71 00 00 0a 06 18 9a 28 71 00 00 0a 28 5e 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATY_2147848084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATY!MTB"
        threat_id = "2147848084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 7e ?? 00 00 04 a2 25 17 7e ?? 00 00 04 a2 0b 06 14 28 ?? 00 00 0a 2c 12 06 14 17 8d ?? ?? ?? 01 25 16 07 a2}  //weight: 2, accuracy: Low
        $x_1_2 = "Bonosua" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATY_2147848084_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATY!MTB"
        threat_id = "2147848084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 0d 02 06 02 06 91 03 61 d2 9c 06 17 58 0a 06 02 28 ?? 00 00 06 25 26 69 32 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0c 2b 1c 07 08 18 5b 02 08 18 28 63 00 00 06 25 26 1f 10 28 ac 00 00 06 25 26 9c 08 18 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ATY_2147848084_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ATY!MTB"
        threat_id = "2147848084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 6f ?? ?? ?? 0a 06 72 1f 00 00 70 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 16 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 73 16 00 00 0a 25 06}  //weight: 2, accuracy: Low
        $x_1_2 = "defender iskl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NED_2147848982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NED!MTB"
        threat_id = "2147848982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 0c 08 2d 4b 00 72 ?? 00 00 70 72 ?? 00 00 70 1a 1f 20 28 ?? 00 00 0a 1c fe 01 16 fe 01 0c 08}  //weight: 5, accuracy: Low
        $x_1_2 = "UpdateDemo.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSFX_2147849089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSFX!MTB"
        threat_id = "2147849089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 48 07 28 ?? ?? ?? 06 0c 08 17 2e 08 08 20 ?? ?? ?? ff 33 31 02 7b ?? ?? ?? 04 17 73 ?? ?? ?? 0a 0d 02 7b ?? ?? ?? 04 18 28 ?? ?? ?? 0a 07 28 ?? ?? ?? 06 13 04 09 11 04 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2b b8 07 17 58 0b 07 20 ?? ?? ?? 00 32 b0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSPN_2147849357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSPN!MTB"
        threat_id = "2147849357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 72 01 00 00 70 72 57 00 00 70 6f 16 00 00 0a de 0a 06 2c 06 06 6f 17 00 00 0a dc 72 8d 00 00 70 28 02 00 00 06 26 02 28 18 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSQN_2147849519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSQN!MTB"
        threat_id = "2147849519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 01 00 00 70 7e 14 00 00 0a 7e 14 00 00 0a 16 1a 7e 14 00 00 0a 14 12 02 12 03 28 02 00 00 06 13 04 72 41 00 00 70 09 7b 06 00 00 04 8c 1a 00 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSQP_2147849520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSQP!MTB"
        threat_id = "2147849520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 17 8d 01 00 00 1b 25 16 72 41 00 00 70 04 73 2a 00 00 0a a4 01 00 00 1b 73 2b 00 00 0a 0b 06 03 07 6f 2c 00 00 0a 6f 2d 00 00 0a 0c 00 de 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSQX_2147849906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSQX!MTB"
        threat_id = "2147849906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0d 01 00 0a 6f 0e 01 00 0a 28 0f 01 00 0a 72 39 5d 00 70 28 10 01 00 0a 28 b3 00 00 0a 26 02 28 b4 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_GNC_2147850659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.GNC!MTB"
        threat_id = "2147850659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Program Files\\mana break\\" ascii //weight: 1
        $x_1_2 = "505\\505\\obj\\Release\\fuckyouware.pdb" ascii //weight: 1
        $x_1_3 = "fuckyouware.exe" ascii //weight: 1
        $x_1_4 = "cz56954.tw1.ru/ICSharpCode.SharpZipLib.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSRP_2147850752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSRP!MTB"
        threat_id = "2147850752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 72 01 00 00 70 72 f6 00 00 70 28 05 00 00 06 28 13 00 00 0a 72 22 01 00 70 28 04 00 00 06 00 16 28 14 00 00 0a 00 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSRX_2147850759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSRX!MTB"
        threat_id = "2147850759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 6f 1c 00 00 0a 28 ?? 00 00 0a 0d 73 1d 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 0d 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSSD_2147850764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSSD!MTB"
        threat_id = "2147850764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 06 6f 1a 00 00 0a 07 16 07 8e 69 6f 1b 00 00 0a 0c 08 28 33 00 00 0a 72 99 00 00 70 6f 22 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSSM_2147851114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSSM!MTB"
        threat_id = "2147851114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 24 00 00 0a 2b 05 72 23 00 00 70 fe 0e 00 00 2b 05 72 23 00 00 70 72 35 00 00 70 2b 05 72 23 00 00 70 28 1e 00 00 0a 2b 05 72 23 00 00 70 72 57 00 00 70 2b 05 72 23 00 00 70 6f 1f 00 00 0a 2b 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PHK_2147851227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PHK!MTB"
        threat_id = "2147851227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PrintNotifyPotato.exe" ascii //weight: 1
        $x_1_2 = "55089d6f-65d7-4f1f-a1d5-583e5c54ab67" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSTM_2147851887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSTM!MTB"
        threat_id = "2147851887"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 08 11 08 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 28 ?? 00 00 06 13 09 72 24 02 00 70 17 8d 13 00 00 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMS_2147852131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMS!MTB"
        threat_id = "2147852131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WinGuido\\GuidoAusili prova" wide //weight: 1
        $x_1_2 = "http://188.213.167.248/download" wide //weight: 1
        $x_1_3 = "GATraduttore.dll" wide //weight: 1
        $x_1_4 = "KillExplorer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMAA_2147852137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMAA!MTB"
        threat_id = "2147852137"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 26 06 72 ?? 04 00 70 28 ?? 00 00 06 26 06 72 ?? 04 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "gMqeWOPLGVb37y00zMrL4/VVFHyxBgam/Ukb7bCU3Q8=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSTW_2147852143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSTW!MTB"
        threat_id = "2147852143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 2a 00 00 0a 72 3f 02 00 70 6f 2b 00 00 0a 0a 72 61 02 00 70 0b 73 2c 00 00 0a 0c 28 01 00 00 2b 0d 73 2e 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NBY_2147853097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NBY!MTB"
        threat_id = "2147853097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 4d 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08}  //weight: 5, accuracy: Low
        $x_5_2 = {02 28 07 00 00 06 0a 06 6f ?? 00 00 0a 0b 2b 00 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSWP_2147889556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSWP!MTB"
        threat_id = "2147889556"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 02 00 00 06 7e 01 00 00 04 72 09 00 00 70 28 ?? 00 00 0a 72 1d 00 00 70 28 ?? 00 00 0a 72 09 00 00 70 28 ?? 00 00 0a 72 a1 00 00 70 28 ?? 00 00 0a 6f 03 00 00 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSWR_2147890091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSWR!MTB"
        threat_id = "2147890091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 05 6f 14 00 00 0a 72 0f 00 00 70 72 25 00 00 70 6f ?? 00 00 0a 00 11 05 02 07 6f ?? 00 00 0a 00 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NDL_2147890297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NDL!MTB"
        threat_id = "2147890297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 69 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 08 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "MySql.Installer.Launcher.wd_T5end.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NTDY_2147891420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NTDY!MTB"
        threat_id = "2147891420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 09 9a 07 09 9a 6f ?? 00 00 0a 00 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
        $x_1_2 = "Files downloaded and set to run at user startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_GMG_2147891583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.GMG!MTB"
        threat_id = "2147891583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 9a 14 17 8d 0f 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 26 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "Eqggpsce.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NYY_2147891691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NYY!MTB"
        threat_id = "2147891691"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 02 00 00 04 a2 25 18 72 ?? 00 00 70 a2 25 19 28 ?? 00 00 0a a2 25 1a 72 ?? 00 00 70 a2 25 1b 7e ?? 00 00 04 a2 28 ?? 00 00 0a 28 ?? 00 00 06 00 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 72 ?? 00 00 70 72 ?? 00 00 70 72 ?? 00 00 70 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Assistente.Program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_RDB_2147892287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.RDB!MTB"
        threat_id = "2147892287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 16 6f 13 00 00 0a 25 17 6f 14 00 00 0a 25 17 6f 15 00 00 0a 25 17 6f 16 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_YAB_2147892417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.YAB!MTB"
        threat_id = "2147892417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "getAVName" ascii //weight: 1
        $x_1_2 = "fromStringToB64" ascii //weight: 1
        $x_1_3 = {28 14 00 00 0a 02 6f 2c 00 00 0a 28 2d 00 00 0a 72 69 01 00 70 72 5d 01 00 70 6f 26 00 00 0a 72 fd 01 00 70 72 65 01 00 70 6f 26 00 00 0a 72 95 02 00 70 72 99 02 00 70 6f 26 00 00 0a 72 9d 02 00 70 72 a1 02 00 70 6f 26 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSZB_2147893078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSZB!MTB"
        threat_id = "2147893078"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0e 72 5b 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 20 03 00 00 00 38 ba ff ff ff 11 0e 11 0e 28 ?? 00 00 06 11 0e 6f 04 00 00 0a 28 ?? 00 00 06 13 01}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMAB_2147893929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMAB!MTB"
        threat_id = "2147893929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 07 6f ?? 00 00 0a 17 73 ?? 02 00 0a 0c 08 02 16 02 8e 69 6f ?? 02 00 0a 08 6f ?? 02 00 0a 06 6f ?? 01 00 0a 0d 09 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_SSPP_2147895187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.SSPP!MTB"
        threat_id = "2147895187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 08 6f ?? ?? ?? 06 08 6f ?? ?? ?? 06 11 04 8f 0a 00 00 02 7b 8e 00 00 04 11 05 08 6f ?? ?? ?? 06 11 04 8f 0a 00 00 02 7b 8d 00 00 04 28 ?? ?? ?? 0a 00 00 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 06 7b 84 00 00 04 fe 04 13 2a 11 2a 3a 73 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMBA_2147895533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMBA!MTB"
        threat_id = "2147895533"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 07 16 09 6f ?? 00 00 0a 17 59 6f ?? 00 00 0a 17 6f ?? 00 00 0a 28 ?? 00 00 0a 0c 00 11 04 17 58 13 04 11 04 02 fe 04 13 06 11 06 2d d0}  //weight: 1, accuracy: Low
        $x_1_2 = "c:\\windows\\god\\up.exe" ascii //weight: 1
        $x_1_3 = "c:\\windows\\god\\sendb.exe" ascii //weight: 1
        $x_1_4 = "sendb.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTBI_2147895669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTBI!MTB"
        threat_id = "2147895669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 07 6f 11 00 00 0a 0c 08 28 ?? 00 00 0a 0d 09 2c 25 00 08 28 ?? 00 00 0a 2d 04 1f 61 2b 02 1f 41}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTBS_2147896164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTBS!MTB"
        threat_id = "2147896164"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7d 06 00 00 04 02 28 ?? 00 00 0a 00 00 02 28 ?? 00 00 06 00 16 28 ?? 00 00 0a 00 72 07 00 00 70 72 15 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTBT_2147896531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTBT!MTB"
        threat_id = "2147896531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 22 00 00 0a 26 07 6f 23 00 00 0a 6f 24 00 00 0a 0c 08 17 8d 31 00 00 01 25 16 1f 2d 9d 6f 25 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTBY_2147896543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTBY!MTB"
        threat_id = "2147896543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 06 28 40 00 00 0a 02 6f 41 00 00 0a 6f 42 00 00 0a 0b 73 35 00 00 0a 0c 16 0d 2b 1e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_SPQN_2147896638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.SPQN!MTB"
        threat_id = "2147896638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0d 1c 2c d2 09 06 6f ?? ?? ?? 0a 16 2d ab 00 06 6f ?? ?? ?? 0a 13 04 11 04 13 07 16 2d 9b de 3d}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTCC_2147896857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTCC!MTB"
        threat_id = "2147896857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 26 00 00 01 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f 1c 00 00 0a 1f 10 28 ?? 00 00 0a 9c 08 18 58 0c 08 06 32 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PTCI_2147897094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PTCI!MTB"
        threat_id = "2147897094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 11 04 2c 0c 72 89 00 00 70 28 ?? 00 00 0a 00 00 38 ce 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PSDS_2147899356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PSDS!MTB"
        threat_id = "2147899356"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 0a 7e 13 ?? ?? ?? 06 6f 14 ?? ?? ?? 72 73 00 00 70 6f 15 ?? ?? ?? 6f 16 ?? ?? ?? 25 72 8b 00 00 70 6f 17 ?? ?? ?? 39 96 00 00 00 73 18 ?? ?? ?? 25 72 a1 00 00 70 6f 19 ?? ?? ?? 25 17 6f 1a ?? ?? ?? 25 17 6f 1b ?? ?? ?? 25 16 6f 1c ?? ?? ?? 25 17 6f 1d ?? ?? ?? 0b 73 1e ?? ?? ?? 25 07 6f 1f ?? ?? ?? 25 6f 20 ?? ?? ?? 26 25 6f 21 ?? ?? ?? 72 bf 00 00 70 6f 22 ?? ?? ?? 20 c4 09 00 00 28 23 ?? ?? ?? 25 6f 21 ?? ?? ?? 72 10 02 00 70 6f 22 ?? ?? ?? 6f 21 ?? ?? ?? 72 a1 08 00 70 6f 22 ?? ?? ?? 20 e8 03 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "WriteLine" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMBH_2147899967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMBH!MTB"
        threat_id = "2147899967"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 63 d1 13 17 11 11 11 09 91 13 25 11 11 11 09 11 26 11 25 61 19 11 1b 58 61 11 2d 61 d2 9c 17 11 09 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMBG_2147901944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMBG!MTB"
        threat_id = "2147901944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 09 17 9a 28 ?? 00 00 0a 28 ?? 00 00 0a 08 17 8d ?? 00 00 01 16 17 6f ?? 00 00 0a 08 17 8d ?? 00 00 01 16 17 6f ?? 00 00 0a 38 ?? 01 00 00 09 17 9a 28}  //weight: 3, accuracy: Low
        $x_3_2 = {28 0c 00 00 0a 09 18 9a 6f ?? 00 00 0a 13 08 11 07 72 ?? 00 00 70 6f ?? 00 00 0a 11 07 09 19 9a 73 ?? 00 00 0a 6f ?? 00 00 0a 11 07}  //weight: 3, accuracy: Low
        $x_1_3 = "HttpWebResponse" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "WriteAllBytes" ascii //weight: 1
        $x_1_6 = "GetFolderPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_KAA_2147902499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.KAA!MTB"
        threat_id = "2147902499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 08 02 08 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 fe 01 0d 09 2c 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NB_2147902554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NB!MTB"
        threat_id = "2147902554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 06 17 6a da b7 17 d6 17 da 17 d6 17 da 17 d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NC_2147902555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NC!MTB"
        threat_id = "2147902555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0f 2c 16 11 04 17 6a da b7 17 d6 17 da 17 d6 17 da 17 d6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMMB_2147904302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMMB!MTB"
        threat_id = "2147904302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 0f 07 11 0f 91 08 61 d2 9c 11 0f 17 58 13 0f 11 0f 07 8e 69 32 e8}  //weight: 2, accuracy: High
        $x_1_2 = "CreateThread" wide //weight: 1
        $x_1_3 = "WaitForSingleObject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMME_2147905913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMME!MTB"
        threat_id = "2147905913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 61 [0-12] 5d 91 59 20 00 01 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_KAB_2147905941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.KAB!MTB"
        threat_id = "2147905941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 02 07 94 03 6f ?? 00 00 0a 20 ?? 00 00 00 61 5b 0d 09 08 20 00 01 00 00 5a 59 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_CCIB_2147907108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.CCIB!MTB"
        threat_id = "2147907108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Successfull connected" wide //weight: 1
        $x_1_2 = "RUN_FILE" wide //weight: 1
        $x_1_3 = "START_REMOTE_DESKTOP" wide //weight: 1
        $x_1_4 = "SLEEP_PC" wide //weight: 1
        $x_1_5 = "KILL_PROCESS" wide //weight: 1
        $x_1_6 = "BLOCK_PROCESS" wide //weight: 1
        $x_1_7 = "/c SCHTASKS /Create /SC minute /TN Chrome /TR" wide //weight: 1
        $x_1_8 = "/ST 00:00 /ET 23:59 /K /mo 1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_RV_2147911644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.RV!MTB"
        threat_id = "2147911644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Administrator\\Desktop\\Pillager_\\Pillager\\obj\\Debug\\Pillager.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_RW_2147911733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.RW!MTB"
        threat_id = "2147911733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 08 0e 04 0e 04 8e 69 12 04 11 05 11 05 8e 69 09 09 8e 69 12 06 16 28 ?? ?? ?? 06 13 07 11 07 7e ?? ?? ?? ?? fe 01 13 09 11 09 2c 0b 72}  //weight: 5, accuracy: Low
        $x_1_2 = "Pillager.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_RX_2147911821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.RX!MTB"
        threat_id = "2147911821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {06 28 0e 00 00 06 6f 06 00 00 0a 17 8d 08 00 00 01 25 16 1f 0a 9d 17 6f 07 00 00 0a 0b 07 8e 69 17 32 1c 07 16 9a 6f 08 00 00 0a 80 04 00 00 04 07 17 9a 6f 08 00 00 0a 80 05 00 00 04 2b 14}  //weight: 4, accuracy: High
        $x_1_2 = "<PrivateImplementationDetails>{488FDCFC-7BEA-4AD4-9E29-287FC69784C5}" ascii //weight: 1
        $x_1_3 = "virustotalBypass.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_SGB_2147912596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.SGB!MTB"
        threat_id = "2147912596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 01 00 00 04 72 0f 00 00 70 28 19 00 00 0a 80 02 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_NAB_2147921841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.NAB!MTB"
        threat_id = "2147921841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e ?? 2a 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? 7a 00 06 58 54 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "2d8a26b7-02b6-48f0-a480-add869963599" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ARAZ_2147928216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ARAZ!MTB"
        threat_id = "2147928216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$323534cf-1ddb-4e54-be39-8704ee83811e" ascii //weight: 2
        $x_2_2 = "/moc.codnogazam//:sptth" wide //weight: 2
        $x_2_3 = "SELECT * FROM Win32_NetworkAdapter" wide //weight: 2
        $x_2_4 = "select * from Win32_PhysicalMemory" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_EANT_2147928921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.EANT!MTB"
        threat_id = "2147928921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b 18 07 28 1b 00 00 0a 0c 06 12 02 28 1c 00 00 0a 6f 1d 00 00 0a 07 17 58 0b 07 28 1e 00 00 0a 32 e0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AMDC_2147931899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AMDC!MTB"
        threat_id = "2147931899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 13 04 11 04 02 7e ?? 00 00 0a 7e ?? 00 00 0a 7e ?? 00 00 0a 16 20 ?? 00 00 08 7e ?? 00 00 0a 14 12 02 12 03 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_EAMI_2147934428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.EAMI!MTB"
        threat_id = "2147934428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 9a 28 14 00 00 06 26 06 07 9a 28 15 00 00 06 06 07 9a 72 37 0b 00 70 28 57 00 00 0a 2c 08 06 07 9a 28 16 00 00 06 07 17 58 0b 07 06 8e 69}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_PGTK_2147939661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.PGTK!MTB"
        threat_id = "2147939661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 05 00 00 04 6f ?? 00 00 0a 80 02 00 00 04 20 02 00 00 00 fe 0e 04 00 00 fe 0c 04 00 20 03 00 00 00 fe 01 39 2b 00 00 00 28 ?? 00 00 0a 20 0a 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_EPL_2147941727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.EPL!MTB"
        threat_id = "2147941727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 02 07 6f a6 00 00 0a 03 07 6f a6 00 00 0a 61 60 0a 07 17 58 0b 07 02 6f 3f 00 00 0a 32 e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_AB_2147945009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.AB!MTB"
        threat_id = "2147945009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 7e d7 00 00 04 0e 06 17 59 e0 95 58 0e 05 28 2d 01 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ARR_2147957141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ARR!MTB"
        threat_id = "2147957141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {5d 58 61 d2 9c 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d dd}  //weight: 15, accuracy: High
        $x_5_2 = "KjQrOCwsCAQOD0oAHgI=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_ARR_2147957141_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.ARR!MTB"
        threat_id = "2147957141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "$21a85034-d725-41d8-9ab9-19507fa1e20c" ascii //weight: 8
        $x_10_2 = "ComputerScanner.exe" ascii //weight: 10
        $x_2_3 = "<streamStream>5__6" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Tedy_LME_2147959064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Tedy.LME!MTB"
        threat_id = "2147959064"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {14 0a 72 01 00 00 70 28 03 00 00 0a 0a 06 72 ba 00 00 70 6f 04 00 00 0a 0b 07 72 06 01 00 70 20 38 01 00 00}  //weight: 10, accuracy: High
        $x_20_2 = "C:\\Windows\\Microsoft.Net\\assembly\\GAC_MSIL\\ABCpdf\\v4.0_9.1.1.7__a7a0b3f5184f2169\\ABCpdf.dll" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

