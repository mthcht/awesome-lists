rule Trojan_MSIL_Spynoon_MFP_2147782172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.MFP!MTB"
        threat_id = "2147782172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {19 8d 10 00 00 01 0a 06 16 28 ?? ?? ?? 06 a2 06 17 28 ?? ?? ?? 06 a2 06 18 72 ?? ?? ?? 70 a2 d0 ?? ?? ?? 02 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0b 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 08 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0d 09 13 ?? 16 13 ?? 11 ?? 16 fe ?? 13 ?? 11}  //weight: 5, accuracy: Low
        $x_5_2 = {00 72 b7 0f 00 70 0a 02 6f ?? ?? ?? 0a 0b 17 0c 2b 2c 00 02 08 28 ?? ?? ?? 0a 03 08 1e 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 d1 13 04 12 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 00 08 17 d6 0c 08 07 fe ?? 16 fe ?? 13 ?? 11 ?? 2d}  //weight: 5, accuracy: Low
        $x_5_3 = {17 13 25 11 ?? 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 ?? ?? ?? 0a 13 26 11 26 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 ?? ?? ?? 0a 13 ?? 11 ?? 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 25 16 16 8c ?? ?? ?? 01 a2 25 17 06 a2 14 14 28 ?? ?? ?? 0a 13 ?? 72 ?? ?? ?? 70}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Spynoon_VMS_2147787667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.VMS!MTB"
        threat_id = "2147787667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 06 0a 72 01 00 00 70 06 1a 1f 0a 6f ?? 00 00 06 8c 26 00 00 01 28 ?? 00 00 0a 00 72 01 00 00 70 06 1a 1f 0a 6f ?? 00 00 06 8c 26 00 00 01 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0b 07 28 ?? 00 00 06 28 ?? 00 00 06 72 1b 00 00 70 6f ?? 00 00 0a 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "4 + 10 = {0}" wide //weight: 1
        $x_1_3 = "FLV Download Setup" wide //weight: 1
        $x_1_4 = "www.lumixsoft.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_SYN_2147828289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.SYN!MTB"
        threat_id = "2147828289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 91 2b 0e 07 25 17 59 1e 2d 13 26 16 fe 02 0c 2b 07 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABEW_2147836679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABEW!MTB"
        threat_id = "2147836679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 08 06 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 06 8e 69 fe 04 13 09 11 09 2d de}  //weight: 3, accuracy: Low
        $x_1_2 = "CurrencyConverter.POIUYHJK" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_DC_2147841776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.DC!MTB"
        threat_id = "2147841776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 0a 75 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 1d 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 1b 13 0e 38}  //weight: 4, accuracy: Low
        $x_1_2 = "Append" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_DD_2147842413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.DD!MTB"
        threat_id = "2147842413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 16 0b 2b 16 02 07 8f ?? 00 00 01 25 47 06 07 1f 10 5d 91 61 d2 52 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e0}  //weight: 2, accuracy: Low
        $x_1_2 = "Append" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "WindowsFormsApp1.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_FAM_2147845258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.FAM!MTB"
        threat_id = "2147845258"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 0a 72 ?? 13 00 70 28 ?? 00 00 0a 0b 06 07 6f ?? 00 00 0a 0c 02 8e 69 8d ?? 00 00 01 0d 08 02 16 02 8e 69 09 16 6f ?? 00 00 0a 13 04 09 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 2b 00 11 05 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABSW_2147846102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABSW!MTB"
        threat_id = "2147846102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 04 2b 09 de 0d 28 ?? 00 00 06 2b f5 0a 2b f4 26 de ec}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 05 2b 06 2b 0b 2a 02 2b f8 28 ?? 00 00 2b 2b f3 28 ?? 00 00 2b 2b ee}  //weight: 2, accuracy: Low
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABPY_2147847375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABPY!MTB"
        threat_id = "2147847375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "OptNIstones.Properties.Resources.resources" ascii //weight: 4
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "QYwAc.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABXK_2147847813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABXK!MTB"
        threat_id = "2147847813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 0a 2b 00 06 2a 19 00 7e ?? 00 00 04 6f}  //weight: 2, accuracy: Low
        $x_2_2 = "SuperAraneid.Properties.Resources" wide //weight: 2
        $x_1_3 = "DataBasePracticalJob" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_GAM_2147848226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.GAM!MTB"
        threat_id = "2147848226"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fs0JYlJrm4ctQ8lU8jppsPZqY18A5j7mntcEqqXf" wide //weight: 1
        $x_1_2 = "NbwAgtkgoNZOc6uSzVwsbUU1uMrLHa7LlO7T" wide //weight: 1
        $x_1_3 = "yJayxtrqRcg0OrwqPQB+f8iWssba6kXINDq8Kj0Afn" wide //weight: 1
        $x_1_4 = "IlrLG2upFyDQ6vCo9AH5/yJayxtrqRcg0OrwqPQB" wide //weight: 1
        $x_1_5 = "TLbnUNC1iCwEQOQnQPVcmQpuvJYqDxnwxSg4U20UL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABYA_2147848453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABYA!MTB"
        threat_id = "2147848453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 41 00 00 70 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 06 74 ?? 00 00 1b 28 ?? 00 00 06 0b dd ?? 00 00 00 26 de d1}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABZT_2147848784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABZT!MTB"
        threat_id = "2147848784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 08 11 07 6f ?? 00 00 0a 13 09 16 13 0a 11 06 13 0c 11 0c 13 0b 11 0b}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 21 12 09 28 ?? 00 00 0a 13 0a 2b 16 12 09 28 ?? 00 00 0a 13 0a 2b 0b 12 09 28 ?? 00 00 0a 13 0a 2b 00 07 11 0a 6f ?? 00 00 0a 00 00 11 08 17 58 13 08 11 08 09 fe 04 13 0d 11 0d 2d 97}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AABA_2147848868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AABA!MTB"
        threat_id = "2147848868"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 28 06 09 5d 13 07 06 09 5b 13 08 08 11 07 11 08 6f ?? 00 00 0a 13 0a 11 04 12 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 06 17 58 0a 06 09 11 05 5a 32 d1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AABO_2147849051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AABO!MTB"
        threat_id = "2147849051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b}  //weight: 3, accuracy: Low
        $x_1_2 = "476a274f-fdbe-4042-9b4b-a1852e74909c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AABW_2147849172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AABW!MTB"
        threat_id = "2147849172"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 08 07 6f ?? 01 00 0a 13 13 16 0d 11 05 06 9a 20 ea 74 bb fb 28 ?? 01 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 44 11 05 06 9a 20 e2 74 bb fb 28 ?? 01 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 0a 12 13 28 ?? 01 00 0a 0d 2b 21 11 05 06 9a 20 da 74 bb fb 28 ?? 01 00 06 28 ?? 00 00 0a 13 0e 11 0e 2c 08 12 13 28 ?? 01 00 0a 0d 11 06 09 6f ?? 01 00 0a 08 17 58 0c 08 11 08 fe 04 13 0f 11 0f 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AACF_2147849321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AACF!MTB"
        threat_id = "2147849321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 08 07 6f ?? 00 00 0a 13 12 16 0d 11 05 06 9a 20 0c bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0b 11 0b 2c 0a 12 12 28 ?? 00 00 0a 0d 2b 44 11 05 06 9a 20 14 bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0c 11 0c 2c 0a 12 12 28 ?? 00 00 0a 0d 2b 21 11 05 06 9a 20 1c bd 56 0f 28 ?? 00 00 06 28 ?? 00 00 0a 13 0d 11 0d 2c 08 12 12 28 ?? 00 00 0a 0d 11 06 09 6f ?? 00 00 0a 08 17 58 0c 08 11 08 fe 04 13 0e 11 0e 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASAU_2147849747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASAU!MTB"
        threat_id = "2147849747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 11 04 8e 69 17 da 13 09 16 13 0a 2b 1d 11 05 11 0a 11 04 11 0a 9a 1f 10 28 ?? 00 00 0a 86 6f ?? 00 00 0a 00 11 0a 17 d6 13 0a 11 0a 11 09 31 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASAT_2147849835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASAT!MTB"
        threat_id = "2147849835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 0a 74 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1 6f ?? 00 00 0a 26 16 13 0e 38 ?? fe ff ff 11 09 17 58 13 09 1d 13 0e 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABT_2147849947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABT!MTB"
        threat_id = "2147849947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 2c 17 8d 09 00 00 01 25 16 72 d3 01 00 70 28 ?? 00 00 06 72 ?? 02 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 a2}  //weight: 5, accuracy: Low
        $x_5_2 = {00 00 0f 00 28 50 00 00 0a 0b 07 06 58 03 06 91 52 00 00 06 17 58 0a 06 03 8e 69 fe 04 0c 08 2d df}  //weight: 5, accuracy: High
        $x_1_3 = "WebClient" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "VirtualAlloc" ascii //weight: 1
        $x_1_7 = "HtmlDecode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAEG_2147850252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAEG!MTB"
        threat_id = "2147850252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 0c 11 0c 18 6f ?? 00 00 0a 00 11 0c 18 6f ?? 00 00 0a 00 11 0c 72 0d c2 12 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0c 6f ?? 00 00 0a 13 0d 11 0d 06 16 06 8e 69 6f ?? 00 00 0a 13 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASBI_2147850613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASBI!MTB"
        threat_id = "2147850613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 16 13 06 2b 23 00 08 11 06 18 6f ?? 00 00 0a 13 07 09 11 06 18 5b 11 07 1f 10 28 ?? 00 00 0a d2 9c 00 11 06 18 58 13 06 11 06 08 6f ?? 00 00 0a fe 04 13 08 11 08 2d cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAEM_2147850703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAEM!MTB"
        threat_id = "2147850703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "vU0ABsourFBuWlH6" wide //weight: 1
        $x_1_3 = "ForestInhabitant.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAEU_2147850711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAEU!MTB"
        threat_id = "2147850711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 8e 69 17 da 13 11 16 13 12 2b 1b 11 04 11 12 09 11 12 9a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 17 d6 13 12 11 12 11 11 31 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAEV_2147850712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAEV!MTB"
        threat_id = "2147850712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 07 2b 24 00 09 11 07 18 6f ?? 00 00 0a 13 08 11 04 11 07 18 5b 11 08 1f 10 28 ?? 00 00 0a d2 9c 00 11 07 18 58 13 07 11 07 20 02 d0 00 00 fe 04 13 09 11 09 2d cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAFF_2147850998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAFF!MTB"
        threat_id = "2147850998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 05 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a 1b 00 7e ?? 00 00 04 6f}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "Main_Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASBT_2147851318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASBT!MTB"
        threat_id = "2147851318"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R6PR63RZZRZZRZMRZZRZZRZZRZZR2ZRZ1RZZRZZRZ2R" ascii //weight: 1
        $x_1_2 = "4R4PR53R2ZR6NR6PR64R65R2ORZNRZNRZKR24RZZ" ascii //weight: 1
        $x_1_3 = "1R28R18RZZRZZRZKR16R6PR19RZZRZZRZKRZKRZ6R8OR16RPORZ3RZLRZ7R2MR2KRZZRZ6R" ascii //weight: 1
        $x_1_4 = "4R16R1PR11R73R3MRZZRZZRZKR6PR45RZZR" ascii //weight: 1
        $x_1_5 = "83RZPR16RZZRN2RZOR9ZR15RZKRZZRN2R14RM6R13RZKRZZR58R14" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAHT_2147851813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAHT!MTB"
        threat_id = "2147851813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 20 d4 c9 c4 ec 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 20 21 c9 c4 ec 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASCO_2147852184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASCO!MTB"
        threat_id = "2147852184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 0a 2b 19 07 06 08 06 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a d2 9c 06 17 58 0a 06 07 8e 69 fe 04 13 07 11 07 2d db}  //weight: 1, accuracy: Low
        $x_1_2 = "Quan_Ly_Thu_Vien.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAIN_2147852213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAIN!MTB"
        threat_id = "2147852213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 09 07 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 06 07 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 05 11 05 2d b5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAIQ_2147852230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAIQ!MTB"
        threat_id = "2147852230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 0d 08 09 16 1a 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 11 05 11 06 16 11 04 6f ?? 00 00 0a 26 11 06 13 07 dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 05 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASCT_2147852685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASCT!MTB"
        threat_id = "2147852685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 00 0d 2b 34 07 09 07 8e 69 5d 07 09 07 8e 69 5d 91 08 09 1f 16 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c 09 15 58 0d 09 16 fe 04 16 fe 01 13 06 11 06 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASCU_2147852753_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASCU!MTB"
        threat_id = "2147852753"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 8e 69 17 da 13 0e 16 13 0f 2b 1b 11 06 11 05 11 0f 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31}  //weight: 1, accuracy: Low
        $x_1_2 = "DJKGYSJHDHJ KDGJKHSDGKJHSDG" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAJQ_2147852759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAJQ!MTB"
        threat_id = "2147852759"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 04 07 8e 69 5d 07 11 04 07 8e 69 5d 91 08 11 04 1f 16 5d 28 ?? 00 00 06 61 28 ?? 00 00 06 07 11 04 17 58 07 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASCV_2147852837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASCV!MTB"
        threat_id = "2147852837"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 8e 69 17 da 13 0e 16 13 0f 2b 1b 11 06 11 05 11 0f 9a 1f 10 28 ?? 01 00 0a b4 6f ?? 01 00 0a 00 11 0f 17 d6 13 0f 11 0f 11 0e 31 df}  //weight: 1, accuracy: Low
        $x_1_2 = "FinalProject.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_MBHT_2147852940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.MBHT!MTB"
        threat_id = "2147852940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aj0cHMNfvR8XpVkJoC.DPEIneQqdwttp4gVrl" wide //weight: 1
        $x_1_2 = "Ee7bVsviP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAKI_2147853011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAKI!MTB"
        threat_id = "2147853011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 07 07 8e 69 5d 07 11 07 07 8e 69 5d 91 08 11 07 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 07 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c 11 07 15 58 13 07 11 07 16 2f af}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAKJ_2147853012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAKJ!MTB"
        threat_id = "2147853012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 21 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 02 28 ?? 00 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "uFGjn9c50Mjj8oFBJhWF/83qnGFWt5dBx8vIt84GzRg=" wide //weight: 1
        $x_1_4 = "Germania.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAKR_2147853126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAKR!MTB"
        threat_id = "2147853126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 03 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 07 28 ?? 00 00 06 10 00 02 0c de 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAKY_2147853244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAKY!MTB"
        threat_id = "2147853244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 08 11 08 28 ?? 00 00 06 11 08 28 ?? 00 00 06 28 ?? 00 00 06 13 0b 20 00 00 00 00 7e ?? 01 00 04 7b ?? 01 00 04 3a ?? ff ff ff 26}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASBO_2147891265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASBO!MTB"
        threat_id = "2147891265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 59 13 0e 16 13 0f 2b 16 00 11 0e 11 0e 09 11 0f 91 17 58 5d 58 13 0e 00 11 0f 17 58 13 0f 11 0f 09 8e 69 fe 04 13 12 11 12 2d dd}  //weight: 2, accuracy: High
        $x_2_2 = {59 5f 13 0e 11 10 11 0f 11 0b 11 0f 91 11 0e d2 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 0b 8e 69 fe 04 13 12 11 12 3a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAPE_2147891323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAPE!MTB"
        threat_id = "2147891323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 10 11 0a 5d 13 11 11 10 11 0b 5d 13 12 11 08 11 11 91 13 13 11 09 11 12 28 ?? 00 00 06 13 14 02 11 08 11 10 28 ?? 00 00 06 13 15 02 11 13 11 14 11 15 28 ?? 00 00 06 13 16 11 08 11 11 11 16 20 00 01 00 00 5d d2 9c 11 10 17 59 13 10 11 10 16 2f ad}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAPL_2147891465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAPL!MTB"
        threat_id = "2147891465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0a 20 ed 9b ba 24 28 ?? 00 00 06 28 ?? 00 00 06 20 ca 9b ba 24 28 ?? 00 00 06 28 ?? 00 00 06 6f ?? 00 00 0a 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAPM_2147891466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAPM!MTB"
        threat_id = "2147891466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0d 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 09 08 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 09 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 28 ?? 00 00 2b 13 04 11 04}  //weight: 5, accuracy: Low
        $x_1_2 = "7C584G8GF8FIGHH47S7Z54" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASEF_2147891644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASEF!MTB"
        threat_id = "2147891644"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0d 02 11 0b 11 0c 11 0d 28 ?? 00 00 06 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c 00 11 08 17 59 13 08 11 08 16 fe 04 16 fe 01 13 0f 11 0f 2d}  //weight: 1, accuracy: Low
        $x_1_2 = "7B5QA88S258X89EAA5NGR5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAQA_2147891681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAQA!MTB"
        threat_id = "2147891681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 07 2b 28 08 09 7e ?? 00 00 04 09 91 11 04 11 07 1a 5b 95 11 07 1a 5d 1e 5a 1f 1f 5f 64 d2 61 d2 9c 11 07 17 58 13 07 09 17 58 0d 11 07 1f 10 2f 0c 09 7e ?? 00 00 04 8e 69 fe 04 2b 01 16 13 08 11 08 2d bf}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AASA_2147892713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AASA!MTB"
        threat_id = "2147892713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 11 07 8e 69 5d 13 12 11 11 08 6f ?? 00 00 0a 5d 13 13 07 11 12 91 13 14 08 11 13 6f ?? 00 00 0a 13 15 02 07 11 11 28 ?? 00 00 06 13 16 02 11 14 11 15 11 16 28 ?? 00 00 06 13 17 07 11 12 02 11 17 28 ?? 00 00 06 9c 00 11 11 17 59 13 11 11 11 16 fe 04 16 fe 01 13 18 11 18 2d a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AASR_2147893065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AASR!MTB"
        threat_id = "2147893065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 06 73 ?? 00 00 0a 0d 09 11 05 16 73 ?? 00 00 0a 13 04 11 04 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 de 1d 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AATC_2147893259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AATC!MTB"
        threat_id = "2147893259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 07 8e 69 5d 13 08 09 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 09 28 ?? 00 00 06 13 0c 02 17 11 0a 11 0b 11 0c 28 ?? 00 00 06 13 0d 07 11 08 02 11 0d 28 ?? 00 00 06 9c 00 09 17 59 0d 09 16 fe 04 16 fe 01 13 0e 11 0e 2d a7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AATE_2147893273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AATE!MTB"
        threat_id = "2147893273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 91 72 01 00 00 70 28 ?? 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69 32 e4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AATQ_2147894559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AATQ!MTB"
        threat_id = "2147894559"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Dean.Edwards.Properties.Resources" ascii //weight: 2
        $x_2_2 = "fe3d45bf-f2da-4b78-9ae6-c39375383825" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAUT_2147894700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAUT!MTB"
        threat_id = "2147894700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 07 11 07 07 8e 69 6a 5d d4 11 08 20 00 01 00 00 5d d2 9c 00 11 07 17 6a 58 13 07 11 07 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 09 11 09 2d a2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAUY_2147894986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAUY!MTB"
        threat_id = "2147894986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 10 07 8e 69 6a 5d d4 91 08 11 10 08 8e 69 6a 5d d4 91 61 07 11 10 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 11 07 11 10 07 8e 69 6a 5d d4 11 11 20 00 01 00 00 5d d2 9c 00 11 10 17 6a 58 13 10 11 10 07 8e 69 17 59 09 17 58 5a 6a fe 02 16 fe 01 13 12 11 12 2d a2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAVB_2147895063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAVB!MTB"
        threat_id = "2147895063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 06 25 80 ?? 00 00 04 0b 02 03 06 07 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "$$$a$m$s$i$.$d$l$l$$$" wide //weight: 1
        $x_1_3 = "$$$A$ms$iSc$a$nBu$f$fer$$$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAWG_2147895948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAWG!MTB"
        threat_id = "2147895948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 08 11 04 5d 13 09 11 08 1f 16 5d 13 0a 11 08 17 58 11 04 5d 13 0b 07 11 09 91 13 0c 20 00 01 00 00 13 0d 11 0c 08 11 0a 91 61 07 11 0b 91 59 11 0d 58 11 0d 5d 13 0e 07 11 09 11 0e d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0f 11 0f 2d a9}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAWO_2147896687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAWO!MTB"
        threat_id = "2147896687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 08 11 04 5d 13 09 11 08 17 58 11 04 5d 13 0a 07 11 09 91 13 0b 11 08 1f 16 5d 13 0c 07 11 09 11 0b 08 11 0c 91 61 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 08 17 58 13 08 11 08 11 04 09 17 58 5a fe 04 13 0d 11 0d 2d ae}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ABSD_2147896719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ABSD!MTB"
        threat_id = "2147896719"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JhHh.Resources.resources" ascii //weight: 3
        $x_1_2 = "$bcc41665-492c-44e5-9b7c-34d0f2cb1866" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAOW_2147896762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAOW!MTB"
        threat_id = "2147896762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QuanLyTC.GUI.DangNhap.resources" ascii //weight: 1
        $x_1_2 = "QuanLyTC" wide //weight: 1
        $x_1_3 = "2f0b1c59-9dea-4b18-8e0d-bd5df1d9d827" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAWU_2147896892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAWU!MTB"
        threat_id = "2147896892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1d 11 04 06 08 06 91 11 05 06 11 05 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 06 17 58 0a 06 08 8e 69 32 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAYW_2147898601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAYW!MTB"
        threat_id = "2147898601"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0c 08 11 08 1f 16 5d 91 61 13 0d}  //weight: 1, accuracy: High
        $x_1_2 = {11 0d 11 0b 59 13 0e 07 11 09 11 0e 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: High
        $x_1_3 = {07 11 0a 91 20 00 01 00 00 58 13 0b}  //weight: 1, accuracy: High
        $x_1_4 = "Power_Troubleshooter.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAZI_2147898783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAZI!MTB"
        threat_id = "2147898783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 11 04 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0b 91 11 08 58 13 0c 07 11 0a 91 13 0d 08 09 1f 16 5d 91 13 0e 11 0d 11 0e 61 13 0f}  //weight: 2, accuracy: High
        $x_2_2 = {07 11 0a 11 10 11 08 5d d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AF_2147899948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AF!MTB"
        threat_id = "2147899948"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c}  //weight: 2, accuracy: High
        $x_2_2 = {17 58 20 ff 00 00 00 5f 13 07 11 05 11 04 11 07 95 58 20 ff 00 00 00 5f}  //weight: 2, accuracy: High
        $x_1_3 = "E4ZDFA4U8X5579G4VFS95G" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AAAX_2147900020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AAAX!MTB"
        threat_id = "2147900020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 28 01 00 00 2b 28 ?? 00 00 2b 13 03 20 ?? 00 00 00 38 ?? ff ff ff d0 ?? 00 00 01 28 ?? 00 00 0a 11 04 28 ?? 00 00 06 28 ?? 00 00 2b 72 ?? 00 00 70 28 ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 06 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AM_2147900314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AM!MTB"
        threat_id = "2147900314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "85.209.176.126:3000" wide //weight: 2
        $x_1_2 = "baited.bat" wide //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_BXAA_2147901281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.BXAA!MTB"
        threat_id = "2147901281"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 13 08 11 06 13 09 11 08 11 09 fe 02 16 fe 01 13 16 11 16 2d 03 00 2b 22 11 04 11 07 09 11 07 1e 5a 1e 6f ?? 00 00 0a 18 28 ?? 00 00 0a 9c 11 07 17 58 13 07 00 17 13 16 2b c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_CDAA_2147901462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.CDAA!MTB"
        threat_id = "2147901462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 04 11 09 94 13 0a 09 11 09 09 8e 69 5d 91 13 0b 11 05 11 09 11 0a 11 0b 66 5f 11 0a 66 11 0b 5f 60 9e 00 11 09 17 58 13 09 11 09 11 04 8e 69 fe 04 13 0c 11 0c 2d c7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_CEAA_2147901486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.CEAA!MTB"
        threat_id = "2147901486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 11 00 11 00 28 ?? 00 00 06 11 00 28 ?? 00 00 06 28 ?? 00 00 06 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_CUAA_2147901992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.CUAA!MTB"
        threat_id = "2147901992"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0b 91 61 08 11 08 07 20 88 00 00 00 58 5d 91 11 07 58 11 07 5d 59 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_DCAA_2147902127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.DCAA!MTB"
        threat_id = "2147902127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 19 5d 3a ?? 00 00 00 72 ?? ?? 00 70 12 03 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 09 17 58 0d 09 02 31 da}  //weight: 2, accuracy: Low
        $x_2_2 = {17 13 05 38 ?? 00 00 00 11 04 11 05 58 13 04 11 05 17 58 13 05 11 05 02 31 ee}  //weight: 2, accuracy: Low
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_DVAA_2147902600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.DVAA!MTB"
        threat_id = "2147902600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 2c 39 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 07 08 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 05 11 04 12 05 28 ?? 00 00 0a 13 07 11 07 2d c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AO_2147902968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AO!MTB"
        threat_id = "2147902968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 06 1f 10 8d ?? 00 00 01 6f ?? 00 00 0a 00 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 00 08 07 16 73 ?? 00 00 0a 0d 00 09 73 ?? 00 00 0a 13 04 00 11 04 6f ?? 00 00 0a 13 05 de}  //weight: 2, accuracy: Low
        $x_1_2 = "/C TIMEOUT /T 3 && DEL /f" wide //weight: 1
        $x_1_3 = "citrix hypervisor" wide //weight: 1
        $x_1_4 = "vmware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_EOAA_2147903004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.EOAA!MTB"
        threat_id = "2147903004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 09 02 74 ?? 00 00 1b 16 02 14 72 3c 15 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 09 6f ?? 00 00 0a 00 11 08 6f ?? 00 00 0a 0d de 0e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_FCAA_2147903190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.FCAA!MTB"
        threat_id = "2147903190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4DZ5AZ9QQ3{QQQ4{QQ0ZFFZFF{Q0ZB8{QQQQQ" wide //weight: 1
        $x_1_2 = "Z80NavBarControl.Resources" wide //weight: 1
        $x_1_3 = "12{Q0Z2BZ13{DZ16Z13{EZ1CZ13Z18Z38" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_FUAA_2147903563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.FUAA!MTB"
        threat_id = "2147903563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5d d4 91 61 28 ?? 00 00 0a 07 11 07 08 6a 5d d4 91 28 ?? 00 00 0a 59 11 08 58 11 08 5d 28 ?? 00 00 0a 9c 00 11 05 17 6a 58}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_GNAA_2147904287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.GNAA!MTB"
        threat_id = "2147904287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 04 2b 1f 00 7e ?? 00 00 04 11 04 7e ?? 00 00 04 11 04 91 20 ?? ?? 00 00 59 d2 9c 00 11 04 17 58 13 04 11 04 7e ?? 00 00 04 8e 69 fe 04 13 05 11 05 2d d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_HVAA_2147905158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.HVAA!MTB"
        threat_id = "2147905158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 1f 16 6a 5d d4 91 61 28 ?? 00 00 06 07 11 07 08 6a 5d d4 91 28 ?? 00 00 06 59 11 08 58 11 08 5d 28 ?? 00 00 06 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_IFAA_2147905511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.IFAA!MTB"
        threat_id = "2147905511"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 28 ?? 00 00 06 73 ?? 00 00 0a 0c 08 11 04 16 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 de 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_LHAA_2147908442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.LHAA!MTB"
        threat_id = "2147908442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 72 72 f8 03 70 72 76 f8 03 70 17 8d ?? 00 00 01 25 16 1f 2d 9d 28 ?? 00 00 0a 28 ?? 00 00 0a 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 06 72 80 f8 03 70 72 84 f8 03 70 6f ?? 00 00 0a 28 ?? 00 00 06 a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_MHAA_2147909844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.MHAA!MTB"
        threat_id = "2147909844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 0a 91 11 0e 61 07 11 0f 91 59 13 10 11 10 20 00 01 00 00 58 13 11 07 11 0a 11 11 20 ff 00 00 00 5f d2 9c 00 11 0a 17 58 13 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_NMAA_2147911338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.NMAA!MTB"
        threat_id = "2147911338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 17 58 09 5d 13 07 07 11 07 91 13 08 02 07 06 91 11 06 61 11 08 28 ?? 00 00 06 13 09 07 06 11 09 28 ?? 00 00 0a 9c 06 17 58 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_KAF_2147911340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.KAF!MTB"
        threat_id = "2147911340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 11 05 91 11 06 61 11 08 28 ?? 00 00 06 13}  //weight: 1, accuracy: Low
        $x_1_2 = {03 04 59 0a 06 20 00 ?? 00 00 58 20 ff 00 00 00 5f 0b 1a 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_KAH_2147911959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.KAH!MTB"
        threat_id = "2147911959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 08 91 11 ?? 61 07 08 17 58 07 8e 69 5d 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_OYAA_2147912603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.OYAA!MTB"
        threat_id = "2147912603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 11 91 11 12 61 13 13 11 11 17 58 11 05 8e 69 5d 13 14 11 05 11 14 91 13 15 11 13 11 15 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 16 11 05 11 11 11 16 d2 9c 00 11 11 17 58}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_PIAA_2147913650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.PIAA!MTB"
        threat_id = "2147913650"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 0a 06 07 02 07 91 9d 07 17 58 0b 07 02 8e 69 32 f0}  //weight: 2, accuracy: High
        $x_2_2 = {0a 7e 25 00 00 04 7e 26 00 00 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_2_3 = "HeyCanIPopShit.Properties.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_RDAA_2147915517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.RDAA!MTB"
        threat_id = "2147915517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0a 02 28 ?? 00 00 06 0b 73 49 00 00 0a 25 06 6f ?? 00 00 0a 25 07 6f ?? 00 00 0a 0c 08 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0d de 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AE_2147918986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AE!MTB"
        threat_id = "2147918986"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 13 04 2b 21 00 07 09 11 04 6f ?? 01 00 0a 13 08 08 12 08 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f ?? 01 00 0a fe 04 13 09 11 09 2d cf 09 17 58 0d 00 09 07 6f}  //weight: 4, accuracy: Low
        $x_1_2 = "MyFtpClient.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_VSAA_2147920466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.VSAA!MTB"
        threat_id = "2147920466"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 04 11 07 95 11 04 11 05 95 58 20 ff 00 00 00 5f 13 13 11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c 00 11 12 17 58 13 12 11 12 09 8e 69 fe 04 13 15 11 15 2d 90}  //weight: 4, accuracy: High
        $x_1_2 = "E4ZDFA4U8X5579G4VFS95G" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ALCA_2147925216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ALCA!MTB"
        threat_id = "2147925216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 07 17 58 0b 07 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 d0}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AWCA_2147925859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AWCA!MTB"
        threat_id = "2147925859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 03 06 08 04 28 ?? 00 00 06 00 08 17 58 0c 00 08 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0d 09 2d d6}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 13 05 00 11 05 13 06 16 13 07 2b 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ALEA_2147927034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ALEA!MTB"
        threat_id = "2147927034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0d 03 09 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 00 03 09 1e 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 05}  //weight: 3, accuracy: Low
        $x_2_2 = {03 19 8d d9 00 00 01 25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 ?? 00 00 2b 6f ?? 00 00 0a 00 00 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ALFA_2147927897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ALFA!MTB"
        threat_id = "2147927897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0a 06 02 7d ?? 00 00 04 00 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 18 5b 28 ?? 00 00 0a 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 2b 00 07 2a}  //weight: 3, accuracy: Low
        $x_2_2 = "4D5A9~03~~04~~FFFF~0B8~~~~004~~~~~~~~~~~~~~~~~~~~~~~008~~" wide //weight: 2
        $x_2_3 = "00E1FBA0E00B409CD21B8014CCD21546869732070726F677261" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AXFA_2147928098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AXFA!MTB"
        threat_id = "2147928098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 00 07 28 ?? 00 00 0a 05 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 03 16 04 8e 69 6f ?? 00 00 0a 13 04 de 16}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ARNA_2147935716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ARNA!MTB"
        threat_id = "2147935716"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {16 0a 2b 1b 00 7e 20 00 00 04 06 7e 20 00 00 04 06 91 20 a6 06 00 00 59 d2 9c 00 06 17 58 0a 06 7e 20 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 4, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AALA_2147936388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AALA!MTB"
        threat_id = "2147936388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {01 25 16 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 61 0f 00 28 ?? 00 00 0a 61 d2 9c 25 17 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 5f 60 d2 9c 25 18 0f 00 28 ?? 00 00 0a 0f 00 28 ?? 00 00 0a 66 66 5f d2 9c 0a 03 06 6f ?? 00 00 0a 00 2a}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AXQA_2147938674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AXQA!MTB"
        threat_id = "2147938674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 05 07 11 05 94 02 5a 1f 64 5d 9e}  //weight: 3, accuracy: High
        $x_3_2 = {07 11 07 07 11 07 94 03 5a 1f 64 5d 9e}  //weight: 3, accuracy: High
        $x_3_3 = {11 08 16 28 ?? ?? 00 06 13 11 11 08 17 28 ?? ?? 00 06 13 12 11 08 18 28 ?? ?? 00 06 13 13 03}  //weight: 3, accuracy: Low
        $x_2_4 = "Student_Housing.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AXRA_2147939856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AXRA!MTB"
        threat_id = "2147939856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 07 11 09 6f ?? ?? 00 0a 13 0a 11 06 11 05 6f ?? ?? 00 0a 59 13 0b 11 0b 19 32 3d 19 8d ?? 00 00 01 25 16 12 0a 28 ?? ?? 00 0a 9c 25 17 12 0a 28 ?? ?? 00 0a 9c 25 18 12 0a 28 ?? ?? 00 0a 9c 13 0c 08}  //weight: 5, accuracy: Low
        $x_2_2 = {11 05 11 0c 6f ?? ?? 00 0a 2b 48 11 0b 16 31 43 19 8d ?? 00 00 01 25 16 12 0a 28 ?? ?? 00 0a 9c 25 17 12 0a 28 ?? ?? 00 0a 9c 25 18 12 0a 28 ?? ?? 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AOUA_2147941864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AOUA!MTB"
        threat_id = "2147941864"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 16 07 16 94 9e 09 17 07 17 94 9e 02 07 16 94 07 17 94 6f ?? 00 00 0a 13 06 19 8d ?? 00 00 01 13 07 11 07 16 12 06 28 ?? 00 00 0a 9c 11 07 17 12 06 28 ?? 00 00 0a 9c 11 07 18 12 06 28 ?? 00 00 0a 9c 09 18 04 03 6f ?? 00 00 0a 59 9e 09 18 94 19}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_ASVA_2147942444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.ASVA!MTB"
        threat_id = "2147942444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 0a 11 0b 6f ?? 00 00 0a 13 0c 12 0c 28 ?? 00 00 0a 16 61 d2 13 0d 12 0c 28 ?? 00 00 0a 16 61 d2 13 0e 12 0c 28 ?? 00 00 0a 16 61 d2 13 0f 07 11 0d 6f ?? 00 00 0a 00 08 11 0e 6f ?? 00 00 0a 00 09 11 0f 6f ?? 00 00 0a 00 04 03 6f ?? 00 00 0a 59 13 10 11 10 19 fe 04 16 fe 01 13 11 11 11 2c 3a 00 07 6f ?? 00 00 0a 13 12 08 6f ?? 00 00 0a 13 13 09 6f ?? 00 00 0a 13 14 03 11 12 6f ?? 00 00 0a 00 03 11 13 6f ?? 00 00 0a 00 03 11 14 6f ?? 00 00 0a 00 00 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AVVA_2147942848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AVVA!MTB"
        threat_id = "2147942848"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 06 04 7d ?? 00 00 04 00 16 06 7b ?? 00 00 04 6f ?? 01 00 0a 06 7b ?? 00 00 04 6f ?? 01 00 0a 5a 28 ?? 01 00 0a 0b 07 06 fe ?? ?? 00 00 06 73 ?? 01 00 0a 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 01 00 0a 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 01 00 0a 28 ?? 00 00 2b 7e ?? 00 00 04 25 2d 17}  //weight: 5, accuracy: Low
        $x_2_2 = {13 0a 2b 37 11 0a 6f ?? 01 00 0a 13 0b 00 06 7b ?? 00 00 04 6f ?? 01 00 0a 06 7b ?? 00 00 04 fe 04 16 fe 01 13 0c 11 0c 2c 02 2b 18 06 7b ?? 00 00 04 11 0b 6f ?? 01 00 0a 00 00 11 0a 6f ?? 01 00 0a 2d c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AHWA_2147943238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AHWA!MTB"
        threat_id = "2147943238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 73 ?? ?? 00 0a 13 05 11 04 14 fe 03 13 06 11 06 2c 56 11 04 08 6f ?? ?? 00 0a 00 11 04 08 6f ?? ?? 00 0a 00 11 04 6f ?? ?? 00 0a 13 07 00 11 05 11 07 17 73 ?? ?? 00 0a 13 08 11 08 02 16 02 8e 69 6f ?? ?? 00 0a 00 11 08 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 0d de 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_AIWA_2147943375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.AIWA!MTB"
        threat_id = "2147943375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 24 72 37 01 00 70 28 ?? 00 00 0a 8c ?? 00 00 01 6f ?? 00 00 0a 00 11 24 72 4b 01 00 70 72 6b 01 00 70 11 0a 1e 5d 13 2d 12 2d 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 11 3e}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 72 c5 04 00 70 a2 25 17 12 17 28 ?? 00 00 0a a2 25 18 72 db 04 00 70 a2 25 19 12 21 28 ?? 00 00 0a a2 25 1a 72 e5 04 00 70 a2}  //weight: 2, accuracy: Low
        $x_2_3 = {01 25 16 11 25 9c 25 17 11 26 9c 25 18 11 27 9c 13 32 11 0b 20 e8 03 00 00 5d 20 e7 03 00 00 fe 01 16 fe 01 13 33}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Spynoon_APAB_2147947394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Spynoon.APAB!MTB"
        threat_id = "2147947394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Spynoon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 08 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6c 07 28 ?? 00 00 0a 5a 13 04 12 03 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 f0 3f 58 28 ?? 00 00 0a 5a 13 05 12 03 28 ?? 00 00 0a 6c 07 23 65 73 2d 38 52 c1 00 40 58 28 ?? 00 00 0a 5a 11 04 11 04 5a 23 00 00 00 00 20 c0 ef 40 5b 13 06 11 05 11 05 5a 23 00 00 00 00 20 c0 ef 40 5b 13 07 25 5a 23 00 00 00 00 20 c0 ef 40 5b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

