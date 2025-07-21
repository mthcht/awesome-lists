rule Trojan_MSIL_DarkComet_AMT_2147832042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AMT!MTB"
        threat_id = "2147832042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 0c 2b 12 08 06 08 06 93 02 7b 08 00 00 04 07 91 04 60 61 d1 9d 06 17 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AMT_2147832042_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AMT!MTB"
        threat_id = "2147832042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 09 16 13 08 11 09 6f ?? ?? ?? 0a 13 0a 2b 3d 11 09 11 08 6f ?? ?? ?? 0a 13 05 09 11 05 6f ?? ?? ?? 06 13 06 11 06 03 28 ?? ?? ?? 0a da 13 07 08 7e 0d 00 00 04 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AMT_2147832042_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AMT!MTB"
        threat_id = "2147832042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 03 11 05 16 6f ?? 00 00 06 28 ?? 00 00 0a 0b 02 03 11 05 17 6f ?? 00 00 06 28 ?? 00 00 0a 0d 18 09 d8 6c 04 28 ?? 00 00 0a 59 07 6c 59 28}  //weight: 3, accuracy: Low
        $x_2_2 = {03 11 05 08 20 00 01 00 00 5d b4 9c 03 11 05 17 d6 11 04 20 00 01 00 00 5d b4 9c 11 05 18 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AOU_2147832707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AOU!MTB"
        threat_id = "2147832707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 6a 59 69 17 58 8d 1b 00 00 01 0b 06 07 16 06}  //weight: 2, accuracy: High
        $x_1_2 = "T.resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_NE_2147833831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.NE!MTB"
        threat_id = "2147833831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 28 13 00 00 0a 0b 07 6f 14 00 00 0a 0c 06 20 60 af d9 8d 28 01 00 00 06 0d 12 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AGDJ_2147836110_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AGDJ!MTB"
        threat_id = "2147836110"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 04 91 08 58 d2 13 05 09 11 04 17 58 91 08 58 d2 13 06 09 11 04 11 06 9c 09 11 04 17 58 11 05 9c 11 04 18 58 13 04 11 04 11 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AGFE_2147836111_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AGFE!MTB"
        threat_id = "2147836111"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 25 17 58 0a 02 7b 02 00 00 04 07 6f ?? ?? ?? 0a 08 91 9c 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AFVK_2147836283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AFVK!MTB"
        threat_id = "2147836283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 18 07 08 02 08 91 06 20 00 01 00 00 6f ?? ?? ?? 0a d2 61 d2 9c 08 17 58 0c 08 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AWI_2147836316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AWI!MTB"
        threat_id = "2147836316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 00 01 00 00 5d 13 0a 11 07 09 94 13 10 11 07 09 11 07 11 0a 94 9e 11 07 11 0a 11 10 9e 11 07 11 07 09 94 11 07 11 0a 94 d6 20 00 01 00 00 5d 94 13 0f 02 11 06 17 da 17}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AAX_2147836984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AAX!MTB"
        threat_id = "2147836984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 14 1a 8d ?? ?? ?? 01 13 04 11 04 16 03 a2 11 04 17 04 a2 11 04 18 05 a2 11 04 19 0e 04 a2 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Comite" wide //weight: 1
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_4 = "otoR.etimoC" wide //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AEU_2147836985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AEU!MTB"
        threat_id = "2147836985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 08 02 8e b7 5d 02 08 02 8e b7 5d 91 07 08 07 8e b7 5d 91 61 02 08 17 58 02 8e b7 5d 91 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AUM_2147836986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AUM!MTB"
        threat_id = "2147836986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 11 05 11 07 11 04 11 05 6f ?? ?? ?? 0a 11 05 da 6f ?? ?? ?? 0a 13 09 06 1f 28}  //weight: 2, accuracy: Low
        $x_1_2 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ABBC_2147836987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ABBC!MTB"
        threat_id = "2147836987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 08 91 13 04 07 11 08 17 d6 91 13 06 18 11 06 d8 08 da 11 04 da 13 07 08 11 04 da 11 06 d6 13 05 07 11 08 11 05}  //weight: 2, accuracy: High
        $x_1_2 = "hard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AXR_2147837455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AXR!MTB"
        threat_id = "2147837455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 31 00 00 01 0c 03 8e b7 17 da 0a 2b 19 08 06 17 da 02 03 06 91 03 06 17 da 91 65 b5 6f ?? ?? ?? 06 9c 06 15 d6 0a 06 17 2f e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ACU_2147837456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ACU!MTB"
        threat_id = "2147837456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 07 17 da 02 03 07 91 03 07 17 da 91 65 b5 6f ?? ?? ?? 06 9c 07 15 d6 0b 07 17 2f e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADZ_2147837457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADZ!MTB"
        threat_id = "2147837457"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 06 17 da 02 03 06 91 03 06 17 da 91 65 b5 6f ?? ?? ?? 06 9c 06 15 d6 0a 06 17 2f e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AOY_2147837823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AOY!MTB"
        threat_id = "2147837823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 c4 09 00 00 28 ?? ?? ?? 0a 14 0b 17 72 ?? ?? ?? 70 12 00 73 ?? ?? ?? 0a 0b 06 2d 05 28}  //weight: 2, accuracy: Low
        $x_1_2 = "ReleaseMutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AF_2147838191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AF!MTB"
        threat_id = "2147838191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 02 16 91 0d 19 02 8e b7 17 da 13 05 0a 2b 48 09 02 17 91 fe 01 09 02 17 91 fe 02 60 2c 04 02 16 91 0d 02 06 91 09 da 0c 08 16 2f 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AC_2147838425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AC!MTB"
        threat_id = "2147838425"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 02 8e b7 17 da 0d 0c 2b 12 02 08 02 08 91 07 08 07 8e b7 5d 91 61 9c 08 17 d6 0c 08 09 31 ea}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AAVY_2147839136_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AAVY!MTB"
        threat_id = "2147839136"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 50 06 02 50 06 91 7e 03 00 00 04 06 7e 03 00 00 04 8e 69 5d 91 61 d2 9c 06 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AD_2147839584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AD!MTB"
        threat_id = "2147839584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 08 06 16 06 8e b7 6f 5d 00 00 0a 08 6f 5e 00 00 0a 28 5f 00 00 0a 11 04 6f 60 00 00 0a 6f 61 00 00 0a 13 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AD_2147839584_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AD!MTB"
        threat_id = "2147839584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 15 13 04 07 09 16 09 8e 69 6f 0c 00 00 0a 13 04 38 17 00 00 00 08 09 16 11 04 6f 09 00 00 0a 07 09 16 09 8e 69 6f 0c 00 00 0a 13 04 11 04 16 30 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AD_2147839584_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AD!MTB"
        threat_id = "2147839584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 09 11 10 58 11 05 11 0e 6e 11 10 6a 58 d4 91 9c 00 11 10 17 58 13 10 11 10 6a 11 0d 6e fe 04 13 13 11 13 2d d8}  //weight: 2, accuracy: High
        $x_1_2 = "QuickLZ" ascii //weight: 1
        $x_1_3 = "Swagger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AD_2147839584_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AD!MTB"
        threat_id = "2147839584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 14 19 8d ?? ?? ?? 01 13 05 11 05 16 06 8c ?? ?? ?? 01 a2 11 05 17 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Sharpieclass" wide //weight: 1
        $x_1_3 = "invokeshittyfunction" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 1a 00 02 06 7e 04 00 00 04 06 91 03 06 0e 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2c 02 2b 50 72 ?? 00 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 17 17 6f ?? 00 00 0a 0b 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 16 08 a2 11 06 17 03 16 9a 74 ?? 00 00 1b a2 11 06 18 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a a2 11 06 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 ?? 0d 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 12 02 12 01 28 ?? ?? ?? 06 74 01 00 00 1b 13 04 12 03 12 00 28 ?? ?? ?? 06 74 01 00 00 1b 13 05 11 05 28 ?? ?? ?? 0a 13 06 11 04 13 07 28 ?? ?? ?? 0a 1f 33 8d 02 00 00 01 25 d0 05 00 00 04 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 2b 48 06 17 d6 20 ff 00 00 00 5f 0a 07 11 05 06 91 d6 20 ff 00 00 00 5f 0b 11 05 06 91 13 07 11 05 06 11 05 07 91 9c 11 05 07 11 07 9c 09 08 11 05 11 05 06 91 11 05 07 91 d6 20 ff 00 00 00 5f 91 02 08 91 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 21 28 ?? ?? ?? 0a 09 8e b7 17 da 6b 5a 6b 6c 28 ?? ?? ?? 0a b7 13 04 06 09 11 04 93 6f ?? ?? ?? 0a 26 06 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "Fries.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 0c 2b 49 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 19 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 08 1f 1f 5d 18 d6 b4 59 86 9c 07 08 91 1f 20 2f 14 07 13 04 11 04 08 13 05 11 05 11 04 11 05 91 1f 5f 58 86 9c 08 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 02 50 8e b7 17 da 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5}  //weight: 2, accuracy: High
        $x_1_2 = "TheElevator.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 03 6f ?? 00 00 0a 17 da 13 05 0c 2b 61 16 03 6f ?? 00 00 0a 17 da 13 06 13 04 2b 48 03 08 11 04 6f ?? 00 00 0a 0d 09 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 06 12 03 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 38 6e 01 00 00 11 05 11 09 09 94 d6 20 00 01 00 00 5d 13 05}  //weight: 2, accuracy: Low
        $x_1_2 = {11 09 09 94 13 0f 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 0f 9e 11 09 11 09 09 94 11 09 11 05 94 d6 20 00 01 00 00 5d 94 13 10 fe 0c 01 00 6d 16 5f 16 fe 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADC_2147841420_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADC!MTB"
        threat_id = "2147841420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e}  //weight: 2, accuracy: Low
        $x_1_2 = "CrypooSS" wide //weight: 1
        $x_1_3 = "SbieCtrl" wide //weight: 1
        $x_1_4 = "DollDll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AE_2147841501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AE!MTB"
        threat_id = "2147841501"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 07 05 50 6f ?? ?? ?? 0a 26 07 0e 04 6f ?? ?? ?? 0a 26 02 50 28 ?? ?? ?? 0a 03 50 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 8e b7 1f 0f da 17 d6 8d ?? ?? ?? 01 13 04 06 1f 10 11 04 16 06 8e b7 1f 10 da 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 1d 16 0c 2b 0f 02 07 02 07 91 06 08 91 61 d2 9c 08 17 58 0c 08 06 8e 69 32 eb 07 17 58 0b 07 02 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0c 2b 1f 06 08 8f 0c 00 00 01 25 71 0c 00 00 01 07 08 07 8e 69 5d 91 61 d2 81 0c 00 00 01 08 17 58 0c 08 06 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 1f 26 9c 11 05 17 20 dc 00 00 00 9c 11 05 18 20 ff 00 00 00 9c 11 05 19 16 9c 11 05 1a 20 ad 00 00 00 9c 11 05 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 19 02 06 02 06 91 03 06 7e ?? 00 00 04 5d 91 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 03 8e b7 17 da 13 04 0d 2b 24 03 09 03 09 91 ?? ?? ?? 8e b7 5d 91 09 06 d6 07 8e b7 d6 1d 5f 64 d2 20 ff 00 00 00 5f b4 61 9c 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 21 02 50 06 02 50 06 91 7e 01 00 00 04 06 7e 01 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 9c 06 17 58 0a 06 02 50 8e 69 32 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 03 06 72 ?? 00 00 70 6f ?? 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 2b 25 08 09 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 1f 67 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 17 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 02 8e b7 17 da 13 06 13 05 2b 29 09 11 05 02 11 05 91 11 04 61 08 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 20 19 15 15 28 ?? 00 00 0a 1f 0a 13 07 1b 07 15 6a 16 28 ?? 00 00 0a 1f 0b 13 07 17 8d ?? 00 00 01 13 04 11 04 16 1b 9e 11 04 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 16 0c 2b 31 02 08 8f 11 00 00 01 25 71 11 00 00 01 07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 11 00 00 01 08 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0d 09 0e 04 2f 03 09 10 04 16 0a 2b 0e 05 06 d3 18 5a 58 08 06 93 53 06 17 58 0a 06 0e 04 32 ed}  //weight: 1, accuracy: High
        $x_1_2 = {16 0a 2b 0b 07 06 03 06 58 47 9c 06 17 58 0a 06 04 32 f1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 04 16 13 06 2b 5d 11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 0d 16 0c 2b 2b 09 08 9a 0b 07 6f ?? 00 00 0a 72 d1 0d 00 70 6f ?? 00 00 0a 13 04 11 04 2c 0b 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 d6 0c 00 08 09 8e b7 fe 04 13 04 11 04 2d c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0d 13 0a 2b 56 11 09 17 d6 20 00 01 00 00 5d 13 09 07 11 05 11 09 91 d6 20 00 01 00 00 5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 02 50 11 0a 02 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6 13 0a 11 0a 11 0d 31 a4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 2b 1e 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 06 08 6f ?? 00 00 0a d2 61 d2 9c 08 17 58 0c 08 06}  //weight: 2, accuracy: Low
        $x_1_2 = {16 13 05 2b 1d 11 04 11 05 91 0c 07 08 13 06 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 11 05 17 58 13 05 11 05 11 04 8e 69 fe 04 13 07 11 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 08 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 06 2b 0a 11 0a 16 8f ?? ?? ?? 01 13 06 11 05 25 13 0a 2c 06 11 0a 8e 69 2d 06 16 e0 13 07 2b 0a 11 0a 16 8f ?? ?? ?? 01 13 07 11 06 d3 11 07 d3 08 8e 69 11 05 8e 69 28 ?? ?? ?? 06 13 04 16 e0 13 07 16 e0 13 06 00 11 04 16 32 0a 11 05 8e 69 11 04 fe 04 2b 01 17 13 0b 11 0b 2d 87}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b5 0b 07 02 1f 20 19 16 15 28 ?? 00 00 0a 17 8d ?? 00 00 01 0c 08 16 07 9e 08 28 ?? 00 00 0a de 0e 28 ?? 00 00 0a 17 0a 28}  //weight: 3, accuracy: Low
        $x_2_2 = {02 50 17 8d ?? 00 00 01 13 04 11 04 16 06 8c ?? 00 00 01 a2 11 04 14 28 ?? 00 00 0a 02 50 17 8d ?? 00 00 01 13 05 11 05 16 07 8c ?? 00 00 01 a2 11 05 14 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 02 50 8e b7 17 da 0c 0b 2b 37 02 50 07 02 50 8e b7 5d 02 50 07 02 50 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 50 07 17 d6 02 50 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 17 d6 0b 07 08 31 c5}  //weight: 2, accuracy: High
        $x_1_2 = "TheElevator.txt" wide //weight: 1
        $x_1_3 = "SzCWyEROwKjjLTgI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 da 13 06 13 05 2b 34 09 11 05 02 11 05 91 11 04 61 08 07 91 61 9c 08 28 ?? ?? ?? 0a 00 07 08 8e b7 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05 00 07 17 d6}  //weight: 2, accuracy: Low
        $x_1_2 = "omeusegundo.Properties.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADK_2147849043_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADK!MTB"
        threat_id = "2147849043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {15 13 05 08 06 16 06 8e b7 6f ?? 00 00 0a 13 05 2b 1a 11 04 06 16 11 05 6f ?? 00 00 0a 00 08 06 16 06 8e b7 6f ?? 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06 2d db}  //weight: 3, accuracy: Low
        $x_2_2 = {13 04 0d 2b 39 03 09 18 28 ?? 00 00 0a 0b 08 72 ?? 00 00 70 07 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a b7 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 09 17 d6 0d 00 09 17 d6 0d 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AAEH_2147850258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AAEH!MTB"
        threat_id = "2147850258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 06 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 18 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d 08}  //weight: 3, accuracy: Low
        $x_1_2 = "KKKKKKKKKLLLLLLLMMMMPPPPOOOO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AATL_2147893504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AATL!MTB"
        threat_id = "2147893504"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 13 04 2b 14 11 06 11 04 02 7b ?? 00 00 04 11 04 91 9c 11 04 17 58 13 04 11 04 11 06 8e 69 fe 04 13 08 11 08 2d de}  //weight: 3, accuracy: Low
        $x_3_2 = {16 13 04 2b 1f 02 7b ?? 00 00 04 02 7b ?? 00 00 04 8e 69 11 04 59 17 59 11 06 11 04 91 9c 11 04 17 58 13 04 11 04 11 06 8e 69 fe 04 13 08 11 08 2d d3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AATM_2147893512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AATM!MTB"
        threat_id = "2147893512"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 0f 09 17 d6 20 00 01 00 00 5d 0d 11 05 11 09 09 94 d6 20 00 01 00 00 5d 13 05 11 09 09 94 13 0f 11 09 09 11 09 11 05 94 9e 11 09 11 05 11 0f 9e 11 09 11 09 09 94 11 09 11 05 94 d6 20 00 01 00 00 5d 94 13 10 02 06 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 0f 11 0f 11 10 61 13 0d 08 11 0d 28 ?? 00 00 0a 6f ?? 00 00 0a 26 12 00 28 ?? 00 00 0a 06 17 da 28 ?? 00 00 0a 26 00 06 02 6f ?? 00 00 0a fe 02 16 fe 01 13 11 11 11}  //weight: 4, accuracy: Low
        $x_1_2 = "h4ck3rShotK3Y" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADA_2147899784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADA!MTB"
        threat_id = "2147899784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 02 02 8e b7 17 da 91 1f 70 61 0d 02 8e b7 17 d6 8d 1e 00 00 01 0b 16 02 8e b7 17 da 13 06 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADA_2147899784_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADA!MTB"
        threat_id = "2147899784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 17 59 32 02 2b 2d 07 08 8e b7 32 02 16 0b 11 06 11 07 93 13 0a 08 07 93 13 08 11 0a 09 59 11 08 59 13 09 11 05 11 07 11 09 28 ?? 00 00 0a 9d 07 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADA_2147899784_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADA!MTB"
        threat_id = "2147899784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 02 8e 69 0d 02 8e 69 18 5a 06 8e 69 58 13 04 38 2f 00 00 00 11 04 17 58 0c 02 11 04 09 5d 02 11 04 09 5d 91 06 11 04 06 8e 69 5d 91 61 02 08 09 5d 91 28 ?? 00 00 06 07 58 07 5d d2 9c 11 04 15 58 13 04 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADA_2147899784_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADA!MTB"
        threat_id = "2147899784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 07 2b 3a 09 11 07 02 11 07 91 07 61 08 11 04 91 61 9c 08 28 ?? ?? ?? 0a 00 11 04 08 8e 69 17 da fe 01 16 fe 01 13 08 11 08 2d 05 16 13 04 2b 07 00 11 04 17 d6 13 04 11 07 17 d6 13 07 11 07 11 06 fe 02 16 fe 01 13 08 11 08 2d b7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {da 0d 0c 2b 3f 07 08 91 1f 1f fe 02 07 08 91 1f 7f fe 04 5f 2c 14 07 08 13 04 11 04 07 11 04 91 08 1f 1f 5d 18 d6 b4 59 86 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 1d 07 08 8f ?? 00 00 01 25 71 ?? 00 00 01 02 08 06 5d 91 61 d2 81 ?? 00 00 01 08 17 58 0c 08 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 02 8e b7 17 da 13 06 13 05 2b 29 08 11 05 02 11 05 91 11 04 61 09 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da 33 04 16 0b 2b 04 07 17 d6 0b 11 05 17 d6 13 05 11 05 11 06 31 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0d 2b 1e 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 02 7b ?? 00 00 04 09 91 61 d2 9c 09 17 58 0d 09 02 7b ?? 00 00 04 8e 69 fe 04 13 04 11 04 2d d1 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 20 17 19 15 28 ?? 00 00 0a 1a 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 0b 1b 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 05 1c 13 0a 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 13 06 1d 13 0a 17 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 05 0d 2b 52 72 ?? ?? ?? 70 02 09 18 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 03 08 6f ?? 00 00 0a 28 ?? 00 00 0a 6a 61 69 28 ?? 00 00 0a 28 ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 26 08 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 02 8e b7 17 da 13 08 13 07 2b 33 09 11 07 02 11 07 91 11 05 61 11 04 11 06 91 61 9c 11 04 28 ?? ?? ?? 0a 11 06 11 04 8e b7 17 da}  //weight: 1, accuracy: Low
        $x_1_2 = {0d 0b 2b 24 16 0c 02 07 94 08 33 0f 06 08 17 da 13 04 11 04 06 11 04 94 17 d6 9e 08 17 d6 0c 08 1f 0a 31 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADM_2147899974_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADM!MTB"
        threat_id = "2147899974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 2b 49 72 ?? 00 00 70 06 8c ?? 00 00 01 28 ?? 00 00 0a 0b 07 28 ?? 00 00 0a 6f ?? 00 00 0a 16 9a 0c 08 06 73 ?? 00 00 0a 0d 18 17 1c 73}  //weight: 1, accuracy: Low
        $x_1_2 = {16 0a 2b 1f 7e ?? 00 00 04 06 7e ?? 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69 32 db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0b 61 d2 9c 07 1f 0b 58 0b 07 08 31 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0c 2b 18 07 08 03 08 91 06 20 00 01 00 00 6f ?? 00 00 0a d2 61 d2 9c 08 17 58 0c 08 03 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 0a 11 05 11 09 91 13 04 11 05 11 09 11 05 06 91 9c 11 05 06 11 04 9c 11 05 11 09 91 11 05 06 91 d6 20 00 01 00 00 5d 0b 03 50 11 0a 03 50 11 0a 91 11 05 07 91 61 9c 11 0a 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 0d 2b 47 02 08 09 6f ?? 00 00 0a 13 04 11 04 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28 ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 05 08 11 05 8e b7 5d 91 d6 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 08 11 07 08 11 07 09 91 9c 11 07 09 11 08 9c 08 17 d6 0c 08 11 0c}  //weight: 2, accuracy: High
        $x_1_2 = {0c 09 11 07 08 91 d6 20 ff 00 00 00 5f 0d 11 07 08 91 13 09 11 07 08 11 07 09 91 9c 11 07 09 11 09 9c 11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 20 ff 00 00 00 5f 91 06 11 04 91 61 9c 11 04 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADT_2147899978_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADT!MTB"
        threat_id = "2147899978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 3a 06 11 06 11 07 94 d6 09 11 07 94 d6 20 00 01 00 00 5d 0a 11 06 11 07 94 13 0c 11 06 11 07 11 06 06 94 9e 11 06 06 11 0c 9e 12 07 28 ?? 00 00 0a 11 07 17 da 28}  //weight: 1, accuracy: Low
        $x_1_2 = {08 94 11 06 11 0a 94 d6 20 00 01 00 00 5d 94 13 0f 02 11 05 17 da 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93 13 0e 11 0e 28 ?? 00 00 0a 13 10 11 10 11 0f 61 13 0d 11 04 11 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADO_2147899981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADO!MTB"
        threat_id = "2147899981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 0b 11 05 11 09 91 13 04 11 05 11 09 11 05 07 91 9c 11 05 07 11 04 9c 11 05 11 09 91 11 05 07 91 d6 20 00 01 00 00 5d 0c 02 50 11 0a 02 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADO_2147899981_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADO!MTB"
        threat_id = "2147899981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 18 5a 03 8e 69 58 0a 2b 35 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 0b 07 20 00 01 00 00 5d d2 0c 02 06 02 8e 69 5d 08 9c 06 15 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADO_2147899981_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADO!MTB"
        threat_id = "2147899981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 13 05 16 0c 06 74 ?? 00 00 01 08 1f 64 d6 17 d6 8d ?? 00 00 01 28 ?? 00 00 0a 74 ?? 00 00 1b 0a 07 06 11 05 1f 64 6f ?? 00 00 0a 13 06 11 06 16 2e 0e 11 05 11 06 d6 13 05 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADO_2147899981_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADO!MTB"
        threat_id = "2147899981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1e 9c 11 05 1f 0e 1f 22 9c 11 05 1f 0f 1f 3c 9c 11 05 73 ?? 00 00 0a 0b 11 04 07 1f 20 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 07 1f 10 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "bummybumbum" wide //weight: 1
        $x_1_3 = "HardCoreDLL.DimDom" wide //weight: 1
        $x_1_4 = "dummmydumdum" wide //weight: 1
        $x_1_5 = "ericsson" wide //weight: 1
        $x_1_6 = "SayHardCoreTrooll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADE_2147901975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADE!MTB"
        threat_id = "2147901975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {94 d6 09 11 08 94 d6 20 00 01 00 00 5d 0a 11 07 11 08 94 13 0c 11 07 11 08 11 07 06 94 9e 11 07 06 11 0c 9e 12 08 28 ?? ?? ?? 0a 11 08 17 da 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADE_2147901975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADE!MTB"
        threat_id = "2147901975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 20 17 19 15 28 ?? 00 00 0a 02 17 28 ?? 00 00 0a b7 28 ?? 00 00 0a 7d ?? 00 00 04 17 02 7c ?? 00 00 04 15 6a 16 28 ?? 00 00 0a 17 8d ?? 00 00 01 13 0b 11 0b 16 17 9e 11 0b 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_EDAA_2147902781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.EDAA!MTB"
        threat_id = "2147902781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 12 01 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 18 73 ?? 00 00 0a 0c 08 06 16 06 8e b7 6f ?? 00 00 0a 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_HCAA_2147904679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.HCAA!MTB"
        threat_id = "2147904679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 05 07 11 05 91 08 11 05 91 61 28 ?? 00 00 0a 25 26 9c 11 05 17 58 13 05 11 05 11 09 31 e0}  //weight: 5, accuracy: Low
        $x_5_2 = {07 11 04 02 11 04 91 07 8e b7 03 8e b7 5d 59 03 08 91 59 09 58 28 ?? 00 00 0a 25 26 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_DarkComet_JIAA_2147906261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.JIAA!MTB"
        threat_id = "2147906261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 11 06 6f ?? 00 00 0a 8c ?? 00 00 01 13 07 08 11 07 28 ?? 00 00 0a 16 8c ?? 00 00 01 6f ?? 00 00 06 03 28 ?? 00 00 0a 28 ?? 00 00 0a 8c ?? 00 00 01 0d 7e ?? 00 00 04 09 28 ?? 00 00 0a 6f ?? 02 00 06 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "dawadwadawda" wide //weight: 1
        $x_1_3 = "#bndertp#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADR_2147907669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADR!MTB"
        threat_id = "2147907669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 13 05 2b 2d 07 11 05 02 11 05 91 09 61 08 11 04 91 61 b4 9c 11 04 03 6f ?? 00 00 0a 17 da 33 05 16 13 04 2b 06 11 04 17 d6 13 04 11 05 17 d6 13 05 11 05 11 06 31 cd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADR_2147907669_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADR!MTB"
        threat_id = "2147907669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 25 13 06 13 05 16 13 07 2b 5f 11 05 17 58 20 00 01 00 00 5d 13 05 11 06 08 11 05 91 58 20 00 01 00 00 5d 13 06 08 11 05 91 13 04 08 11 05 08 11 06 91 9c 08 11 06 11 04 9c 08 11 05 91 08 11 06 91 58 20 00 01 00 00 5d 13 08 06 11 07 8f 0c 00 00 01 25 71 0c 00 00 01 08 11 08 91 61 d2 81 0c 00 00 01 11 07 17 58 13 07 11 07 06 16 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADD_2147915863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADD!MTB"
        threat_id = "2147915863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 0a 11 05 11 09 91 13 04 11 05 11 09 11 05 06 91 9c 11 05 06 11 04 9c 11 05 11 09 91 11 05 06 91 d6 20 00 01 00 00 5d 0c 03 50 11 0a 03 50 11 0a 91 11 05 08 91 61 9c 11 0a 17 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_SIAA_2147916786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.SIAA!MTB"
        threat_id = "2147916786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {15 59 91 61 ?? 08 20 0d 02 00 00 58 20 0c 02 00 00 59 1d 59 1d 58 ?? 8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ADB_2147916973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ADB!MTB"
        threat_id = "2147916973"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0d 0c 2b 3f 06 08 91 1f 1f fe 02 06 08 91 1f 7f fe 04 5f 2c 14 06 08 13 04 11 04 06 11 04 91 08 1f 1f 5d 17 d6 b4 59 86 9c 06 08 91 1f 20 2f 0f 06 08 13 04 11 04 06 11 04 91 1f 5f 58 86 9c 08 17 d6 0c 08 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_NM_2147917954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.NM!MTB"
        threat_id = "2147917954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {58 20 e4 db 9b 28 58 20 cb 52 ca b8 20 e8 2c a2 69 59 59 20 f4 26 7d 94 20 7b 18 00 ab 20 c0 73 82 50 59 20 02 69 fd 09 58 59 61 61 11 06 61 d2 9c 11 06 17 58 13 06 18 13 08 2b 90 d0 01 00 00 04 17 1c 33 03 26 2b 01 26 01 11 06 11 05 8e 69 fe 04 2d 8d}  //weight: 3, accuracy: High
        $x_1_2 = "enizum.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_USAA_2147919826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.USAA!MTB"
        threat_id = "2147919826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0d 74 75 00 00 01 02 28 ?? 00 00 2b 28 ?? 00 00 2b 16 02 8e 69 6f ?? 00 00 0a 1a 13 16 2b c1 11 0d 75 ?? 00 00 01 6f ?? 00 00 0a de 49}  //weight: 3, accuracy: Low
        $x_2_2 = {8d 06 00 00 01 25 16 09 75 22 00 00 1b a2 14 14 16 17 28 ?? 00 00 0a 19 13 11 2b 93 11 05 14 16 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKD_2147932045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKD!MTB"
        threat_id = "2147932045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0c 0b 2b 24 02 07 02 07 91 02 07 17 d6 02 8e b7 5d 91 d6 20 00 01 00 00 5d b4 03 07 03 8e b7 5d 91 61 9c 00 07 17 d6 0b 07 08 0d 09 31 d6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKD_2147932045_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKD!MTB"
        threat_id = "2147932045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 43 16 0c 2b 35 06 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 16 0d 2b 18 06 08 06 08 91 03 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 03 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKD_2147932045_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKD!MTB"
        threat_id = "2147932045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 17 58 20 00 01 00 00 5d 0b 11 05 11 08 07 91 58 20 00 01 00 00 5d 13 05 11 08 07 91 13 0d 11 08 07 11 08 11 05 91 9c 11 08 11 05 11 0d 9c 11 08 07 91 11 08 11 05 91 58 d2 20 00 01 00 00 5d 13 0c 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKD_2147932045_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKD!MTB"
        threat_id = "2147932045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 11 09 07 94 d6 11 06 07 94 d6 20 00 01 00 00 5d 13 0a 11 09 07 94 13 0c 11 09 07 11 09 11 0a 94 9e 11 09 11 0a 11 0c 9e 7e ?? 00 00 04 7e ?? 00 00 04 12 01 28 ?? 00 00 06 07 17 da 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKC_2147932596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKC!MTB"
        threat_id = "2147932596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 33 09 11 04 9a 26 03 03 0e 04 05 58 6f ?? 00 00 0a 0b 07 1f fb 2e 17 03 0e 04 04 8e 69 58 07 0e 04 59 04 8e 69 59 6f ?? 00 00 0a 0c de 32 11 04 17 58 13 04 11 04 09 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = {06 13 05 16 13 06 2b 11 11 05 11 06 9a 26 05 19 58 10 03 11 06 17 58 13 06 11 06 11 05 8e 69 32 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AOD_2147935366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AOD!MTB"
        threat_id = "2147935366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 3b 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 03 06 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 06 04 58 03 6f ?? 00 00 0a 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 06 17 58 0a 06 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_SEV_2147936944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.SEV!MTB"
        threat_id = "2147936944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {74 17 00 00 01 0d 09 28 16 00 00 0a 28 17 00 00 0a 72 21 00 00 70 6f 18 00 00 0a 28 02 00 00 06 13 04 72 7b 00 00 70 28 19 00 00 0a 73 1a 00 00 0a 13 05 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ALPA_2147937233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ALPA!MTB"
        threat_id = "2147937233"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 74 04 00 00 1b 07 8f 14 00 00 01 25 71 14 00 00 01 02 07 1f 10 5d 91 61 d2 81 14 00 00 01 19 0d 38 ?? ff ff ff 07 17 58 0b 18 0d 38 ?? ff ff ff 07 06 74 04 00 00 1b 8e 69 32 17}  //weight: 3, accuracy: Low
        $x_2_2 = {02 8e 69 1f 10 59 8d ?? 00 00 01 0a 02 1f 10 06 75 ?? 00 00 1b 16 06 75 ?? 00 00 1b 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKI_2147938098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKI!MTB"
        threat_id = "2147938098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 1b 03 06 7e 03 00 00 04 5d 91 0b 02 06 02 06 91 07 61 28 ?? 00 00 0a 9c 06 17 58 0a 06 02 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ACM_2147941010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ACM!MTB"
        threat_id = "2147941010"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 84 95 d7 6e 20 ff 00 00 00 6a 5f b8 13 04 11 05 07 84 95 0d 11 05 07 84 11 05 11 04 84 95 9e 11 05 11 04 84 09 9e 08 11 09 02 11 09 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_ACD_2147941761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.ACD!MTB"
        threat_id = "2147941761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 da 13 06 0d 2b 47 03 08 09 6f ?? 00 00 0a 13 04 11 04 16 16 16 16 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 27 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 07 12 04 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkComet_AKT_2147944106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkComet.AKT!MTB"
        threat_id = "2147944106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkComet"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0a 2b 55 06 17 58 20 00 01 00 00 5d 0a 11 07 11 08 06 91 58 20 00 01 00 00 5d 13 07 11 08 06 91 0b 11 08 06 11 08 11 07 91 9c 11 08 11 07 07 9c 11 08 06 91 11 08 11 07 91 58 20 00 01 00 00 5d 13 05 02 50 11 0a 02 50 11 0a 91 11 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

