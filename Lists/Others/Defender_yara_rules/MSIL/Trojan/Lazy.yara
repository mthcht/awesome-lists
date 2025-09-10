rule Trojan_MSIL_Lazy_NEA_2147833834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NEA!MTB"
        threat_id = "2147833834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 11 04 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 02 0c 06 6f ?? 00 00 0a 08 16 08 8e 69 6f ?? 00 00 0a 13 05 de 25 07 2b d2 09 2b d1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NEAA_2147834402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NEAA!MTB"
        threat_id = "2147834402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 9a 1b 28 ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a a2 06 17 58 0a 06 7e 11 00 00 04 8e 69 32 cf}  //weight: 10, accuracy: Low
        $x_5_2 = "VjFod1QxWXlSbGRqUldoUVZrVktjbFV3Wkc1a2R6MDk=" wide //weight: 5
        $x_5_3 = "VjFkd1QxRXdNVWhTYkdoUVYwWmFjVlJYZUV0TmJIQkdZVVpPVDFJeFNrTlZSbEYzVUZFOVBRPT0=" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ASVN_2147836101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ASVN!MTB"
        threat_id = "2147836101"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 1f 10 0c 03 07 06 28 ?? ?? ?? 06 0d 03 07 06 58 03 8e 69 06 59 07 59 08 59 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Chlonium.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLA_2147837016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLA!MTB"
        threat_id = "2147837016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {62 20 ef 8c 77 72 58 20 ?? ?? ?? fe 61 7d ?? ?? ?? 04 20 ?? ?? ?? 00 38 ?? ?? ?? ff 7e ?? ?? ?? 04 20 ?? ?? ?? 09 65 20 ?? ?? ?? fd 61 7d ?? ?? ?? 04 20 ?? ?? ?? 00 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_1_2 = "Jeodptqpswc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLA_2147837016_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLA!MTB"
        threat_id = "2147837016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 18 58 13 04 38 ?? 00 00 00 11 03 11 04 18 5b 11 06 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 38 d8 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "nodeffender" ascii //weight: 1
        $x_1_3 = "KDE Softwares" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLA_2147837016_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLA!MTB"
        threat_id = "2147837016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 2d 00 00 0a 25 02 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 73 ?? ?? ?? 0a 02 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 02 28 ?? ?? ?? 06}  //weight: 5, accuracy: Low
        $x_5_2 = {28 15 00 00 0a 0a 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 06 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0b 25 17 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 25 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 25 72 ?? ?? ?? 70 07 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 de 03}  //weight: 5, accuracy: Low
        $x_1_3 = "YPHU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AO_2147838635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AO!MTB"
        threat_id = "2147838635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 1b 8d 24 00 00 01 0c 02 28 ?? ?? ?? 06 15 16 6f ?? ?? ?? 0a 26 02 28 ?? ?? ?? 06 08 16 1b 16 6f ?? ?? ?? 0a 0b 1a 8d 24 00 00 01 25 16 08 16 91 9c 25 17 08 17 91 9c 25 18 08 18 91 9c 25 19 08 19 91 9c 16 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NEAC_2147838652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NEAC!MTB"
        threat_id = "2147838652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8e 69 5d 91 fe 09 08 00 71 02 00 00 1b fe 09 0a 00 71 03 00 00 01 91 61 d2 9c fe 09 0a 00 71 03 00 00 01 20 01 00 00 00 58 fe 0e 00 00 fe 09 0a 00 fe 0c 00 00 81 03 00 00 01 fe 09 0a 00 71 03 00 00 01 fe 09 08 00 71 02 00 00 1b 8e 69 fe 04}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NHL_2147839725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NHL!MTB"
        threat_id = "2147839725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 16 00 00 0a 0a 72 ?? 00 00 70 0b 72 ?? 00 00 70 0c 06 08 6f ?? 00 00 0a 0d 72 ?? 00 00 70 07 72 ?? 00 00 70 28 ?? 00 00 0a 13 04 72 ?? 00 00 70 13 05 72 ?? 00 00 70 13 06 11 05 28 ?? 00 00 0a 26 06 09 11 04 6f ?? 00 00 0a 00 72 ?? 00 00 70 13 07 00 11 06 28 ?? 00 00 0a 26 11 04 11 07 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Zeon V1.0.2 Bootstrapper" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NEAE_2147839874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NEAE!MTB"
        threat_id = "2147839874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 fe 0c 00 00 7e 01 00 00 04 6f 06 00 00 0a 00 fe 0c 00 00 7e 02 00 00 04 6f 07 00 00 0a 00 fe 0c 00 00 20 01 00 00 00 6f 08 00 00 0a 00 fe 0c 00 00 20 02 00 00 00 6f 09 00 00 0a 00 fe 0c 00 00 fe 0c 00 00 6f 0a 00 00 0a fe 0c 00 00 6f 0b 00 00 0a 6f 0c 00 00 0a fe 0e 01 00 7e 04 00 00 04 73 0d 00 00 0a fe 0e 02 00}  //weight: 10, accuracy: High
        $x_5_2 = "GtLAOU7rakYBBGeB9wNKiQ==" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_CY_2147840167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.CY!MTB"
        threat_id = "2147840167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 6f 3a 00 00 0a 0c 08 28 ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 0c 08 17 8d ?? ?? 00 01 25 16 1f 0d 9d 6f ?? ?? 00 0a 0c 02 08 17 8d ?? ?? 00 01 25 16 1f 0d 9d 6f ?? ?? 00 0a 7d ?? ?? 00 04 02 7b ?? ?? 00 04 0d 16 13 04 2b 18}  //weight: 5, accuracy: Low
        $x_1_2 = "shipinfo.Properties.Resources" ascii //weight: 1
        $x_1_3 = "writefile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NL_2147840169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NL!MTB"
        threat_id = "2147840169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 bd 00 00 70 13 04 72 a3 00 00 70 13 05 73 ?? 00 00 0a 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "Conquer.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NL_2147840169_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NL!MTB"
        threat_id = "2147840169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 7b 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 28 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "KeyAuth Loader Winform Example" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NL_2147840169_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NL!MTB"
        threat_id = "2147840169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 95 01 00 70 06 73 ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "COLLECTBIO.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "COLLECTBIO" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NL_2147840169_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NL!MTB"
        threat_id = "2147840169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {72 41 01 00 70 13 0b 11 05 72 fe 01 00 70 72 41 01 00 70 6f 27 00 00 0a 13 0c 11 07 16 fe 04 16 fe 01 13 0d 11 0d 2c 3b 00 02 7b 0c 00 00 04}  //weight: 3, accuracy: High
        $x_2_2 = {72 e5 02 00 70 72 e0 01 00 70 28 23 00 00 0a 26 20 ee 02 00 00 28 03 00 00 0a 00 72 0f 03 00 70 28 35 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NEAF_2147840211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NEAF!MTB"
        threat_id = "2147840211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 57 00 00 0a 7e 19 00 00 04 28 6a 00 00 0a 28 6b 00 00 0a 6f 6c 00 00 0a 7e 85 00 00 04 25 2d 17}  //weight: 10, accuracy: High
        $x_2_2 = "fuck_you_mom" wide //weight: 2
        $x_2_3 = "U0VMRUNUICogRlJPTSBBbnRpdmlydXNQcm9kdWN0" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AL_2147840274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AL!MTB"
        threat_id = "2147840274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 02 00 20 01 00 00 00 fe 01 39 12 00 00 00 73 ?? ?? ?? 0a fe 0e 00 00 20 02 00 00 00 fe 0e 02 00 00 fe 0c 02 00 20 03 00 00 00 fe 01 39 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AL_2147840274_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AL!MTB"
        threat_id = "2147840274"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 05 08 07 11 05 17 6f 96 00 00 0a 6f 97 00 00 0a 26 11 04 17 d6 13 04 11 04 09 31 d2}  //weight: 2, accuracy: High
        $x_1_2 = "Gradient Crypter.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NZ_2147840345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NZ!MTB"
        threat_id = "2147840345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 6d 00 00 0a 0b 07 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 08 8e 69 17 da 13 04 16 13 05 2b 1f}  //weight: 5, accuracy: Low
        $x_1_2 = "WinForms_RecursiveFormCreate" wide //weight: 1
        $x_1_3 = "WinForms_SeeInnerException" wide //weight: 1
        $x_1_4 = "onlyone_updater" wide //weight: 1
        $x_1_5 = "Blog_Keyword.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ABLN_2147841106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ABLN!MTB"
        threat_id = "2147841106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 0b 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 25 06 16 06 8e 69 6f ?? 00 00 0a 0c 6f ?? 00 00 0a 28 ?? 00 00 0a 08 6f ?? 00 00 0a 2a 3c 00 02 28 ?? 00 00 0a 0a 28}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "TransformFinalBlock" ascii //weight: 1
        $x_1_4 = "Decrypthook" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLY_2147842956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLY!MTB"
        threat_id = "2147842956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 1f 20 6f 43 00 00 0a 13 05 73 ?? ?? ?? 0a 13 06 11 06 20 00 01 00 00 6f ?? ?? ?? 0a 11 06 17 6f ?? ?? ?? 0a 11 06 18 6f 47 00 00 0a 11 06 11 05}  //weight: 5, accuracy: Low
        $x_1_2 = "Task24Main" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLT_2147843446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLT!MTB"
        threat_id = "2147843446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 09 06 00 71 ?? ?? ?? 01 fe ?? ?? 00 fe ?? ?? 00 6f ?? ?? ?? 0a fe ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Rommanyxanthan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSKH_2147844242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSKH!MTB"
        threat_id = "2147844242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 dd 01 00 06 74 a8 00 00 01 14 14 6f 74 00 00 0a 2a}  //weight: 4, accuracy: High
        $x_1_2 = "m_password" wide //weight: 1
        $x_1_3 = "SkipVerification" ascii //weight: 1
        $x_1_4 = "%logger" wide //weight: 1
        $x_1_5 = "Ukzwzbprcuywwkmsesksmqe" wide //weight: 1
        $x_1_6 = "Xhuunkiqhafdz.Hifyziewmzdryribcfpzr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 0b 72 ?? 01 00 70 0c 06 28 ?? 00 00 0a 16 fe 01 0d 09 2c 09 00 06 28 ?? 00 00 0a 26 00 73 ?? 00 00 0a 08 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 03 1f 10 28 ?? 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 20 00 00 00 00 38 58 00 00 00 00 38 64 01 00 00 00 73 02 01 00 0a 25 11 04 28 ?? 03 00 06 00 25 17 28 ?? 03 00 06 00 25 18 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 06 07 28 ?? 00 00 0a 28 ?? 00 00 0a 2d 0d 06 07 28 ?? 00 00 0a 08 28 ?? 00 00 0a de 14 26 72 ?? 01 00 70 02 28}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0c 08 28 06 00 00 0a 02 6f 07 00 00 0a 6f 08 00 00 0a 08 06 6f 09 00 00 0a 08 08 6f 0a 00 00 0a 08 6f 0b 00 00 0a 6f 0c 00 00 0a 0d 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 2b 28 09 6f ?? 00 00 0a 74 ?? 00 00 01 13 04 00 11 04 72 ?? 00 00 70 6f ?? 00 00 0a 14 fe 01 13 05 11 05 2c 04 00 17 0a 00 00 09 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {11 07 17 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 11 07 16 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 73 19 00 00 0a 13 08 11 08 11 07 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 04 2b 71 00 06 19 11 04 5a 6f ?? ?? ?? 0a 13 05 11 05 1f 39 fe 02 13 07 11 07 2c 0d 11 05 1f 41 59 1f 0a 58 d1 13 05 2b 08 11 05 1f 30 59 d1 13 05 06 19 11 04 5a 17 58 6f ?? ?? ?? 0a 13 06 11 06 1f 39 fe 02 13 08 11 08 2c 0d 11 06 1f 41 59 1f 0a 58 d1 13 06 2b 08 11 06 1f 30 59 d1 13 06 08 11 04 1f 10 11 05 5a 11 06 58 d2 9c 00 11 04 17 58 13 04 11 04 07 fe 04 13 09 11 09 2d 84}  //weight: 2, accuracy: Low
        $x_1_2 = "PelayoSNonograms" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALZ_2147844265_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALZ!MTB"
        threat_id = "2147844265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 16 0d 2b 1d 08 09 9a 03 28 ?? 00 00 06 13 04 11 04 28 ?? 00 00 0a 2d 05 11 04 0b de 2b 09 17 58 0d 09 08 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "obj\\Release\\Wagerssi_UI Launcher.pdb" ascii //weight: 1
        $x_1_3 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\World of Warcraft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSJV_2147844536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSJV!MTB"
        threat_id = "2147844536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 01 00 00 70 28 08 00 00 06 13 02 38 12 00 00 00 fe 0c 00 00 45 01 00 00 00 3c 00 00 00 38 37 00 00 00 28 02 00 00 0a 11 02 28 0c 00 00 06 28 0d 00 00 06 28 0e 00 00 06 13 03 20 00 00 00 00 7e 5e 00 00 04 7b 6c 00 00 04 39 c6 ff ff ff 26 20 00 00 00 00 38 bb ff ff ff dd 10 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSKB_2147844903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSKB!MTB"
        threat_id = "2147844903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 28 87 00 00 0a 7e 0e 00 00 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 18 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 13 05 02 13 06 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 0a de 2b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLC_2147845307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLC!MTB"
        threat_id = "2147845307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 12 00 00 04 07 25 17 58 0b 91 1e 62 58 16 2d bf 7e ?? 00 00 04 07 25 17 58 0b 91 58 16 2d e0}  //weight: 5, accuracy: Low
        $x_1_2 = "FileAssociation" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_MKA_2147845324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.MKA!MTB"
        threat_id = "2147845324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 16 07 16 1f 10 28 65 00 00 0a 08 16 07 1f 0f 1f 10 28 65 00 00 0a 06 07 6f 9b 00 00 0a 06 18 6f 9c 00 00 0a 06 6f 9d 00 00 0a 0d 09 04 16 04 8e 69 6f 9e 00 00 0a 13 04 de 46 73 62 00 00 0a 2b a2 0a 2b a1 0b 2b a9 73 9f 00 00 0a 2b a4 28 a0 00 00 0a 2b 9f 02 2b 9e 6f a1 00 00 0a 38 96 ff ff ff 28 a2 00 00 0a 38 8e ff ff ff 0c 38 8d ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSLS_2147846177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSLS!MTB"
        threat_id = "2147846177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {14 0a 38 17 00 00 00 00 72 01 00 00 70 28 08 00 00 06 0a dd 06 00 00 00 26 dd 00 00 00 00 06 2c e6 06 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALY_2147846326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALY!MTB"
        threat_id = "2147846326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 16 0c 2b 28 07 08 9a 0d 09 6f 85 00 00 0a 1c 33 17 09 6f 86 00 00 0a 17 33 0e 09 6f 87 00 00 0a 6f 1e 00 00 0a 0a 2b 0a 08 17 58 0c 08 07 8e 69 32 d2}  //weight: 2, accuracy: High
        $x_1_2 = "Mert\\Desktop\\DiscordTelegram\\obj\\Release\\DiscordTelegram.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ALY_2147846326_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ALY!MTB"
        threat_id = "2147846326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 08 13 04 16 13 05 2b 24 11 04 11 05 6f ?? ?? ?? 0a 13 06 09 12 06 28 ?? ?? ?? 0a 72 9a 12 00 70 28 ?? ?? ?? 0a 0d 11 05 17 58 13 05 11 05 11 04 6f ?? ?? ?? 0a 32 d1 09 09 6f ?? ?? ?? 0a 17 59 17}  //weight: 2, accuracy: Low
        $x_1_2 = "Windows Logger is now running in the background of this system" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPH_2147846379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPH!MTB"
        threat_id = "2147846379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 72 85 00 00 70 6f ?? ?? ?? 0a 13 05 de 1a 6f ?? ?? ?? 0a 72 c9 00 00 70 16 28 ?? ?? ?? 0a 17 33 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSPA_2147847894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSPA!MTB"
        threat_id = "2147847894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 5b 02 08 18 6f 58 00 00 0a 1f 10 28 60 00 00 0a 9c 08 18 58 0c 08 06 fe 04 0d 09 2d e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSNJ_2147848853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSNJ!MTB"
        threat_id = "2147848853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 06 11 06 72 9f 39 01 70 06 17 14 16 13 10 12 10 6f 4b 00 00 06 26 14 13 06 00 00 00 28 70 00 00 0a 28 dd 00 00 06 72 37 3a 01 70 28 55 00 00 0a 0d 11 1d 09 6f d5 01 00 0a 13 23 11 23 2c 0c 11 1d 09 18 18 6f 4e 02 00 0a 00 00 00 de 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSOJ_2147848859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSOJ!MTB"
        threat_id = "2147848859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 c1 05 00 06 08 8d 1a 00 00 01 13 04 7e 58 01 00 04 02 1a 58 11 04 16 08 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 13 05 7e 5d 01 00 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSPE_2147848879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSPE!MTB"
        threat_id = "2147848879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 05 00 00 0a 0a 28 ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 72 3f 00 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0b 28 ?? ?? ?? 0a 02 6f ?? ?? ?? 0a 0c 06 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSPU_2147849360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSPU!MTB"
        threat_id = "2147849360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 73 7a 00 00 0a 0c 16 13 0a 2b 2a 00 08 11 09 11 0a 8f 14 00 00 02 7c 2c 00 00 04 7b 22 00 00 04 28 7b 00 00 0a 6f 7c 00 00 0a de 03}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSQR_2147849654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSQR!MTB"
        threat_id = "2147849654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 6f 82 00 00 0a 17 73 83 00 00 0a 13 04 11 04 02 16 02 8e 69 6f 84 00 00 0a 11 04 6f 4b 00 00 0a de 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_GNC_2147850671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.GNC!MTB"
        threat_id = "2147850671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "klenecektir. Yedekleme stratejinize g" ascii //weight: 1
        $x_1_2 = "Halen devam eden bir yedekleme i" ascii //weight: 1
        $x_1_3 = "Arkaplan uygulamas" ascii //weight: 1
        $x_1_4 = "backupso.com/download" ascii //weight: 1
        $x_1_5 = "Herhangi bir FTP/SFTP" ascii //weight: 1
        $x_1_6 = "zamanli.txt" ascii //weight: 1
        $x_1_7 = "Backupso.exe" ascii //weight: 1
        $x_1_8 = "kapatsinmi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSRW_2147850758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSRW!MTB"
        threat_id = "2147850758"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 02 73 ?? 01 00 0a 0d 09 08 16 73 e2 01 00 0a 13 04 11 04 28 ?? 01 00 0a 73 ?? 01 00 0a 13 05 11 05 6f ?? 01 00 0a 0a de 2c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSSH_2147850768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSSH!MTB"
        threat_id = "2147850768"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 18 00 00 0a 07 72 73 00 00 70 73 19 00 00 0a 08 6f ?? 00 00 0a 06 7b 05 00 00 04 6f ?? 00 00 0a 26 08 28 ?? 00 00 0a 2d 57 73 14 00 00 0a 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_RDE_2147850789_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.RDE!MTB"
        threat_id = "2147850789"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 23 00 00 00 00 00 00 3a 40 07 6f 8a 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 8b 00 00 0a 28 8c 00 00 0a 28 8d 00 00 0a 0d 12 03 28 8e 00 00 0a 28 8f 00 00 0a 0a 08 17 58 0c 08 1b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KBA_2147850833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KBA!MTB"
        threat_id = "2147850833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 15 11 16 9a 13 0b 11 09 11 0b 6f ?? 00 00 0a 11 16 17 58 13 16 11 16 11 15 28 ?? 00 00 06 69 32 de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMS_2147851794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMS!MTB"
        threat_id = "2147851794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The software you just executed is considered malware" wide //weight: 1
        $x_1_2 = "DO YOU WANT EXECUTE THIS MALWARE, RESULTING IN AN UNUSABLE MACHINE" wide //weight: 1
        $x_1_3 = "THE CREATOR IS NOT RESPONSIBLE FOR ANY DAMAGE MADE USING THIS MALWARE" wide //weight: 1
        $x_1_4 = "YOUR COMPUTER HAS BEEN FUCKED BY THE MEMZ TROJAN" wide //weight: 1
        $x_1_5 = "so use it as long as you can!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSTT_2147852004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSTT!MTB"
        threat_id = "2147852004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 72 4b 00 00 70 7e 01 00 00 04 1b 1f 19 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 13 04 11 04 2c 03 00 2b ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSTY_2147852255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSTY!MTB"
        threat_id = "2147852255"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 18 00 00 0a 13 04 11 04 72 eb 02 00 70 72 9e 03 00 70 6f ?? 00 00 0a 00 72 9e 03 00 70 28 ?? 00 00 0a 26 02 28 ?? 00 00 06 00 00 15 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMAC_2147852456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMAC!MTB"
        threat_id = "2147852456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 ?? ?? ?? ?? ?? 58 9e 11 0f 17 58 13 0f 11 16 17 58 13 16 11 16 11 06 37 c1}  //weight: 1, accuracy: Low
        $x_1_2 = {11 0c 11 15 11 0b 9e 11 0d 11 15 11 09 9e 11 09 1b 64 11 09 1f 1b 62 60 13 08 11 0a 19 64 11 0a 1f 1d 62 60 13 09 11 0b 1d 64 11 0b 1f 19 62 60 13 0a 11 08 1f 0b 64 11 08 1f 15 62 60 13 0b 11 15 17 58 13 15 11 15 1f 10 32 b5}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualProtect" ascii //weight: 1
        $x_1_4 = "Riceboy.Riceboy" ascii //weight: 1
        $x_1_5 = "transfer.sh/get" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSUE_2147852494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSUE!MTB"
        threat_id = "2147852494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 03 00 00 06 0b 14 0c 14 0d 0e 04 13 05 11 05 2c 17 00 07 03 72 30 15 00 70 04 28 10 00 00 0a 6f 11 00 00 0a 0d 00 2b 1c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AALI_2147888158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AALI!MTB"
        threat_id = "2147888158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 05 03 02 8e 69 6f ?? 01 00 0a 0a 2b 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "$$$$$$$$$$C$$$$$$$$$$$$reat$$$$$$$eIn$$$$$$$$$$stan$$$$$$$$$$$ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSVH_2147888166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSVH!MTB"
        threat_id = "2147888166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 02 00 00 04 07 06 a2 2b 61 07 2d 32 28 ?? 00 00 0a 0c 12 02 fe 16 10 00 00 01 6f ?? 00 00 0a 6f ?? 00 00 0a 72 93 00 00 70 72 01 00 00 70 6f ?? 00 00 0a 19 1f 14 6f ?? 00 00 0a 0a 2b 0e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSVR_2147888536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSVR!MTB"
        threat_id = "2147888536"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 37 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 72 d6 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0c 08 2c 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSVU_2147888817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSVU!MTB"
        threat_id = "2147888817"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 00 28 ?? 00 00 0a 72 9d 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 73 ?? 00 00 0a 0b 07 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSVZ_2147888881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSVZ!MTB"
        threat_id = "2147888881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 3a b0 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSWU_2147890094_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSWU!MTB"
        threat_id = "2147890094"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 02 28 07 00 00 06 26 7e 10 00 00 0a 0d 12 03 08 16 28 ?? 00 00 06 26 28 ?? 00 00 0a 6f ?? 00 00 0a 13 04 72 9e 01 00 70 11 04 72 cc 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 06 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSWZ_2147890099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSWZ!MTB"
        threat_id = "2147890099"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 c7 00 00 70 6f ?? 00 00 0a 0d 09 2c 27 09 a5 27 00 00 01 17 33 1e 08 72 c7 00 00 70 6f ?? 00 00 0a 72 e5 00 00 70 72 29 01 00 70 16 1f 40 28 ?? 00 00 0a 26 de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMAA_2147892237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMAA!MTB"
        threat_id = "2147892237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 02 07 91 66 d2 9c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 58 d2 81 ?? 00 00 01 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 ?? 00 00 01 00 07 17 58 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMAA_2147892237_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMAA!MTB"
        threat_id = "2147892237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 20 ?? ?? ?? ?? 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 14 0a 2b 0c 00 28 ?? 00 00 06 0a de 03 26 de 00 06 2c f1 73 ?? 00 00 0a 0b 06 73 ?? 00 00 0a 0d 09 11 05 16 73 ?? 00 00 0a 13 04 11 04 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 06 de 1d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NLZ_2147892303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NLZ!MTB"
        threat_id = "2147892303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0f 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 1e 39 ?? 00 00 00 38 ?? 00 00 00 26 38 ?? 00 00 00 fe 0c 03 00}  //weight: 5, accuracy: Low
        $x_1_2 = "Cppvp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMAB_2147893931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMAB!MTB"
        threat_id = "2147893931"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1f 27 0d 11 04 13 06 12 06 03 28 ?? 00 00 06 11 06 74 ?? 00 00 01 13 04 1f 28 0d 11 04 6f ?? 00 00 0a 13 05 1f 29 0d 11 05 02 16 02 8e 69 6f ?? 00 00 0a 0a}  //weight: 4, accuracy: Low
        $x_1_2 = "Dbatic.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KAD_2147894567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAD!MTB"
        threat_id = "2147894567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 03 61 0a 7e ?? 00 00 04 0c 08 74 ?? 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 18 13 0e 2b 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTBF_2147895560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTBF!MTB"
        threat_id = "2147895560"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 14 0a 02 28 ?? 00 00 06 0a 02 03 04 28 ?? 00 00 06 0a 06 28 ?? 00 00 0a 00 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTBM_2147895777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTBM!MTB"
        threat_id = "2147895777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 02 11 00 70 28 ?? 00 00 0a 0b 06 28 ?? 00 00 0a 07 6f 24 00 00 0a 6f 25 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTBN_2147895888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTBN!MTB"
        threat_id = "2147895888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 13 00 00 0a 0d 03 28 ?? 00 00 0a 73 15 00 00 0a 13 04 11 04 09 07 08 6f 16 00 00 0a 16 73 17 00 00 0a 13 05 11 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NBL_2147896417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NBL!MTB"
        threat_id = "2147896417"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 7b 09 03 00 04 6f aa 00 00 06 0b 02 7b 09 03 00 04 6f aa 00 00 06 0c 03 08 6f 09 01 00 0a 3a 08 00 00 00 03 08 14 6f 0a 01 00 0a 07 1f 20 5f 3a 01 00 00 00 2a 07 17 5f 39 06 00 00 00 1a 38 01 00 00 00 18 0d 07 1e 5f 39 09 00 00 00 09 18 58 0d 38 0d 00 00 00 07 1f 40 5f 39 04 00 00 00 09 1a 58 0d 07 20 80 00 00 00 5f 39 04 00 00 00 09 1e 58 0d 02 7b 09 03 00 04 09 6f a2 00 00 06 26 38 7a ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "RunRegistry" ascii //weight: 1
        $x_1_3 = "DeleteRegistry" ascii //weight: 1
        $x_1_4 = "SetRegistry" ascii //weight: 1
        $x_1_5 = "InvokePolicy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTAP_2147897056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTAP!MTB"
        threat_id = "2147897056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 55 0f 00 06 17 28 56 0f 00 06 75 7a 00 00 01 28 9e 02 00 06 7e 90 00 00 04 25 3a 17 00 00 00 26 7e 8f 00 00 04 fe 06 a3 02 00 06 73 fe 00 00 0a 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_GNF_2147897072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.GNF!MTB"
        threat_id = "2147897072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "eRClgZbl.exe" ascii //weight: 1
        $x_1_2 = "m_aa67c29e89e9404fadacad12a2e59f85" ascii //weight: 1
        $x_1_3 = "m_bb696782161d4c01a78bf0930c8183cc" ascii //weight: 1
        $x_1_4 = "aR3nbf8dQp2feLmk31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KAE_2147897391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAE!MTB"
        threat_id = "2147897391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 03 00 fe 0c 04 00 fe 0c 02 00 fe 0c 04 00 91 fe 0c 00 00 fe 0c 04 00 fe 0c 00 00 8e 69 5d 91 61 d2 9c fe 0c 04 00 7e ?? 00 00 04 58 fe 0e 04 00 fe 0c 04 00 fe 0c 02 00 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KAE_2147897391_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAE!MTB"
        threat_id = "2147897391"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 93 28 ?? 00 00 0a 39 ?? 00 00 00 06 07 93 28 ?? 00 00 0a 3a ?? 00 00 00 1f 41 38 ?? 00 00 00 1f 61 0c 06 07 06 07 93 08 59 1f 0d 58 1f 1a 5d 08 58 d1 9d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SK_2147897485_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SK!MTB"
        threat_id = "2147897485"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 06 8e 69 5d 0c 06 08 91 13 06 11 04 07 1f 16 5d 6f ?? ?? ?? 0a d2 13 07 06 07 17 58 06 8e 69 5d 91 13 08 11 06 11 07 61 11 08 20 00 01 00 00 58 20 00 01 00 00 5d 59 13 09 06 08 11 09 d2 9c 07 17 59 0b 07 16 2f b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMCC_2147898299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMCC!MTB"
        threat_id = "2147898299"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "28A3^^063A36[7[[[[262079^^^382B" wide //weight: 2
        $x_2_2 = "80C^^B603^^[62E^^6C34" wide //weight: 2
        $x_1_3 = "HexStringToByteArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMCD_2147898300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMCD!MTB"
        threat_id = "2147898300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 1b d2 13 2d 11 1b 1e 63 d1 13 1b 11 1a 11 0b 91 13 29 11 1a 11 0b 11 29 11 25 61 19 11 1f 58 61 11 2d 61 d2 9c 11 29 13 1f 11 0b 17 58 13 0b 11 0b 11 28 32 a4}  //weight: 2, accuracy: High
        $x_1_2 = {11 24 11 12 11 0c 11 12 91 9d 17 11 12 58 13 12 11 12 11 15 32 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTDO_2147898330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTDO!MTB"
        threat_id = "2147898330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 13 6f a6 00 00 06 13 15 11 13 6f a6 00 00 06 13 16 07 11 15 11 16 6f 40 00 00 0a 11 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTDR_2147898472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTDR!MTB"
        threat_id = "2147898472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 94 00 00 00 38 87 dd ff ff 11 07 38 bc 0a 00 00 80 53 00 00 04 20 31 00 00 00 fe 0e 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTDY_2147899011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTDY!MTB"
        threat_id = "2147899011"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 84 02 00 70 15 16 28 ?? 00 00 0a 02 7b 11 00 00 04 28 ?? 00 00 0a 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTDZ_2147899012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTDZ!MTB"
        threat_id = "2147899012"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 20 ff 00 00 00 5f 2b 1d 03 6f 31 00 00 0a 0c 2b 17 08 06 08 06 93 02 7b 0b 00 00 04 07 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSBW_2147899332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSBW!MTB"
        threat_id = "2147899332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 00 72 3d 08 00 70 28 41 ?? ?? ?? 0a 06 6f 42 ?? ?? ?? 0b 07 6f 43 ?? ?? ?? 0c 73 44 ?? ?? ?? 0d 08 09 28 15 00 00 06 00 09 6f 45 ?? ?? ?? 80 5e 00 00 04 28 17 00 00 06 00 7e 5e 00 00 04 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSFI_2147899365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSFI!MTB"
        threat_id = "2147899365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 1f 28 28 1e 00 00 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 0a 0b 07 39 ?? ?? ?? 00 00 06 72 ?? ?? ?? 70 16 28 ?? ?? ?? 0a 0c 00 08 0d 16 13 04 38 ?? ?? ?? 00 09 11 04 9a 13 05 00 11 05 72 ?? ?? ?? 70 16 28 ?? ?? ?? 0a 13 06 11 06 7e ?? ?? ?? 04 25 2d 17 26 7e ?? ?? ?? 04 fe ?? ?? ?? 00 06 73 ?? ?? ?? 0a 25 80 ?? ?? ?? 04 28 01 00 00 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
        $x_1_3 = "WriteLine" ascii //weight: 1
        $x_1_4 = "GetEnumerator" ascii //weight: 1
        $x_1_5 = "CathayFuturesFXConfig" ascii //weight: 1
        $x_1_6 = "ChangeHosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSQA_2147899410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSQA!MTB"
        threat_id = "2147899410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 6f 7d 00 00 0a 0c 07 08 17 73 ?? ?? ?? 0a 0d 02 28 28 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 13 05 28 ?? ?? ?? 0a 11 05 16 11 05 8e 69 6f ?? ?? ?? 0a 13 06 de 1e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KAF_2147899618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAF!MTB"
        threat_id = "2147899618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 08 9a 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 1f 7c 9d 6f ?? 00 00 0a 0d 09 8e 69 18 33 2e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NNL_2147899704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NNL!MTB"
        threat_id = "2147899704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 02 09 6f 7c 00 00 0a 03 09 ?? ?? ?? ?? ?? 61 60 0a 00 09 17 58 0d 09 02 ?? ?? ?? ?? ?? fe 04 13 04 11 04 2d d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTEN_2147900033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTEN!MTB"
        threat_id = "2147900033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2b f6 17 0d 16 13 12 38 1a ff ff ff 28 ?? 01 00 06 13 08 11 08 2c 08 1c 13 12}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTEP_2147900034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTEP!MTB"
        threat_id = "2147900034"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 03 6f 20 00 00 0a 0b 04 28 ?? 00 00 0a 28 ?? 00 00 0a 26 04 07 28 ?? 00 00 0a de 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBA_2147900725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBA!MTB"
        threat_id = "2147900725"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 91 06 09 91 58 20 00 01 00 00 5d 13 08 02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 08 91 61 d2 81 ?? 00 00 01 11 05 17 58 13 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_BEAA_2147900927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.BEAA!MTB"
        threat_id = "2147900927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 00 11 06 08 6f ?? 00 00 0a 00 11 06 17 6f ?? 00 00 0a 00 11 06 09 6f ?? 00 00 0a 00 11 06 18 6f ?? 00 00 0a 00 11 06 6f ?? 00 00 0a 13 07 11 07 06 16 06 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTGJ_2147900960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTGJ!MTB"
        threat_id = "2147900960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 99 00 00 0a 00 02 6f 60 00 00 06 6f 9a 00 00 0a 6f 9b 00 00 0a 00 1b 8d 74 00 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTAT_2147901142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTAT!MTB"
        threat_id = "2147901142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 04 02 11 04 91 06 08 93 28 ?? 00 00 0a 61 d2 9c 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPAA_2147901197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPAA!MTB"
        threat_id = "2147901197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 05 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 06 11 07 91 61 d2 81 ?? ?? ?? 01 11 05 17 58 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_RDH_2147901372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.RDH!MTB"
        threat_id = "2147901372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 09 11 05 16 11 05 8e 69 6f 08 00 00 0a 09 16 6a 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPCX_2147901596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPCX!MTB"
        threat_id = "2147901596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 05 11 0a 11 05 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 11 06 58 11 07 5d 13 0b 11 08 02 11 0a 6f ?? ?? ?? 0a 11 0b 61 d1 6f ?? ?? ?? 0a 26 00 11 0a 17 58 13 0a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SL_2147901752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SL!MTB"
        threat_id = "2147901752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 05 06 17 58 13 09 06 20 00 90 01 00 5d 13 06 11 09 20 00 90 01 00 5d 13 0a 07 11 0a 91 11 05 58 13 0b 07 11 06 91 13 0c 11 07 06 1f 16 5d 91 13 0d 11 0c 11 0d 61 13 0e 07 11 06 11 0e 11 0b 59 11 05 5d d2 9c 06 17 58 0a 06 20 00 90 01 00 32 a9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBH_2147902028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBH!MTB"
        threat_id = "2147902028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 11 04 58 11 04 5d 59 d2 9c 06 17 58 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NC_2147902272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NC!MTB"
        threat_id = "2147902272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 17 11 0a 11 13 11 17 9d 11 13 17 d6 13 13 00 12 16 ?? ?? 01 00 0a 13 18 11 18 2d dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPDD_2147902383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPDD!MTB"
        threat_id = "2147902383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 08 09 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 16 31 01 2a 11 04 17 58 13 04 11 04 1b 32 e5}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBB_2147902688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBB!MTB"
        threat_id = "2147902688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0c 00 00 7e ?? 00 00 04 fe 0c 04 00 6f ?? 00 00 0a fe 0e 05 00 fe 0d 05 00 28 ?? ?? 00 0a 28 ?? 00 00 0a fe 0e 00 00 20 ?? ?? 00 00 fe 0e 06 00}  //weight: 2, accuracy: Low
        $x_1_2 = {fe 0c 01 00 fe 0c 02 00 6f ?? 00 00 0a fe 0e 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBC_2147902689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBC!MTB"
        threat_id = "2147902689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 17 9a 28 ?? 00 00 0a 7e ?? ?? 00 04 18 9a 28 ?? 00 00 0a 6f ?? ?? 00 0a 13 01 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTIV_2147903000_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTIV!MTB"
        threat_id = "2147903000"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 f3 03 00 70 72 17 04 00 70 73 9e 00 00 0a 6f 9f 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBE_2147903387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBE!MTB"
        threat_id = "2147903387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 0e 91 61 d2 81}  //weight: 2, accuracy: Low
        $x_2_2 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 16 13 0a 06 08 91 13 0a}  //weight: 2, accuracy: High
        $x_1_3 = "lld.23lenre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMBE_2147903387_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMBE!MTB"
        threat_id = "2147903387"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 08 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 08 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0d de 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
        $x_1_3 = "Delay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NE_2147903521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NE!MTB"
        threat_id = "2147903521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 06 09 11 06 91 04 61 d2 9c 11 06 17 58 ?? ?? ?? ?? 09 8e 69 32 e8 28 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMMB_2147903934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMMB!MTB"
        threat_id = "2147903934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {15 16 16 7e ?? 00 00 04 11 07 8f ?? 00 00 01 7e ?? 00 00 04 16 12 06}  //weight: 2, accuracy: Low
        $x_1_2 = "a2VybmVsMzIuZGxs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PTJY_2147905360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PTJY!MTB"
        threat_id = "2147905360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 d9 03 00 0a 20 e3 cd 33 8f 28 ?? 00 00 06 28 ?? 03 00 0a 0a 06 28 ?? 03 00 0a 02 06 28 ?? 03 00 0a 7d e2 01 00 04 de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPPX_2147905969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPPX!MTB"
        threat_id = "2147905969"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {11 06 6f 8f 00 00 0a 16 73 90 00 00 0a 13 0d 11 0d 11 07 28 64 00 00 06 de 14 11 0d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PSON_2147906119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PSON!MTB"
        threat_id = "2147906119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 02 7b 15 00 00 04 6f ?? ?? ?? 0a 0a 06 2c 29 00 73 ?? ?? ?? 0a 0b 07 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 02 7b 15 00 00 04 08 6f ?? ?? ?? 0a 00 00 2b 13}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_HNA_2147907273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.HNA!MTB"
        threat_id = "2147907273"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 64 6c 6c 00 50 72 6f 67 72 61 6d 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 4d 61 69 6e 00 2e 63 74 6f 72 00 53 79 73 74 65 6d}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 61 64 41 6c 6c 54 65 78 74 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00 47 5a 69 70 53 74 72 65 61 6d 00 53 74 72 65 61 6d 00 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 00 42 79 74 65 00 52 65 61 64 00 57 72 69 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SS_2147909030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SS!MTB"
        threat_id = "2147909030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_crypted" ascii //weight: 2
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "b7d8f503-8f40-42e5-bde3-f9512a4a6d15" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NG_2147909352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NG!MTB"
        threat_id = "2147909352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 03 17 11 04 58 91 11 04 1e 5a 1f 1f 5f 62 58 0d 11 04 17 58 13 04 11 04 1a}  //weight: 5, accuracy: High
        $x_5_2 = {17 2a 06 1e 58 02 8e 69 3c 6c 00 00 00 02 06 91 1f 4d}  //weight: 5, accuracy: High
        $x_2_3 = "_crypted.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPZM_2147909886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPZM!MTB"
        threat_id = "2147909886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 58 09 5d 13 0f 08 11 0a 91 11 0e 61 08 11 0f 91 59 13 10 11 10 20 00 01 00 00 58 13 11 08 11 0a 11 11 20 ff 00 00 00 5f d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ARA_2147910295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ARA!MTB"
        threat_id = "2147910295"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 2a 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 0c 08 61 d1 0d 06 09 6f ?? ?? ?? 0a 26 07 28 ?? ?? ?? 06 58 0b 07 02 6f ?? ?? ?? 0a 32 cd}  //weight: 2, accuracy: Low
        $x_2_2 = "\\temp.ps1" ascii //weight: 2
        $x_2_3 = "\\temp.bat" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPZC_2147910849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPZC!MTB"
        threat_id = "2147910849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {58 08 5d 13 0f 11 1a 20 02 01 00 00 94 20 78 92 00 00 59 13 18}  //weight: 2, accuracy: High
        $x_2_2 = {07 11 0a 91 11 0e 61 07 11 0f 91 59 13 10 11 19 1f 28 93 20 f2 59 00 00 59 13 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NH_2147911262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NH!MTB"
        threat_id = "2147911262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "_crypted.exe" ascii //weight: 5
        $x_5_2 = "file_" ascii //weight: 5
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetTempFileName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_HNE_2147912184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.HNE!MTB"
        threat_id = "2147912184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 00 63 00 2f 00 00 0b 26 00 62 00 69 00 64 00 3d 00 00 0d 26 00 6e 00 61 00 6d 00 65 00 3d 00 00 0f 74 00 61 00 73 00 6b 00 5f 00 69 00 64 00 00 13 74 00 61 00 73 00 6b 00 5f 00 74 00 79 00 70 00 65 00 00 13 74 00 61 00 73 00 6b 00 5f 00 64 00 61 00 74 00 61 00 00 03 31 00 00 [0-64] 44 00 6f 00 6e 00 65 00 2e 00 00 0b 46 00 61 00 69 00 6c 00 2e 00 00 03 33 00 00 03 34 00 00 03 35 [0-64] 26 00 74 00 61 00 73 00 6b 00 5f 00 69 00 64 00 3d 00 00 11 26 00 72 00 65 00 73 00 75 00 6c 00 74 00 3d 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {75 00 72 00 6c 00 00 07 47 00 45 00 54 00 00 09 50 00 4f 00 53 00 54 00 00 43 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 2f 00 78 00 2d 00 77 00 77 00 77 00 2d 00 66 00 6f 00 72 00 6d 00 2d 00 75 00 72 00 6c 00 65 00 6e 00 63 00 6f 00 64 00 65 00 64 00 01 0b 75 00 74 00 66 00 2d 00 38 00 01 09 2e 00 74 00 6d 00 70 00 00 ?? 66 00 74 00 70 00 3a 00 2f 00 2f 00 66 00 74 00 70 00 2e 00}  //weight: 2, accuracy: Low
        $x_2_3 = {2e 00 63 00 6f 00 6d 00 3a 00 32 00 31 00 2f 00 00 09 53 00 54 00 4f 00 52 00 00 09 74 00 65 00 73 00 74 00 00 21 6d 00 4c 00 5a 00 38 00 66 00 4c 00 52 00 32 00 47 00 43 00 72 00 50 00 69 00 36 00 4d 00 4e [0-48] 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 00 11 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 00 03 5c 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_HNF_2147912212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.HNF!MTB"
        threat_id = "2147912212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 5b 00 50 00 41 00 47 00 45 00 2c 00 20 00 55 00 50 00 5d 00 20 00 00 03 2b 00 00 1b 20 00 5b 00 42 00 41 00 43 00 4b 00 53 00 50 00 41 00 43 00 45 00 5d}  //weight: 3, accuracy: High
        $x_3_2 = {00 50 41 53 53 57 4f 52 44 5f 52 45 43 4f 56 45 52 59 5f 46 41 49 4c 45 44 00 41 44 4d 49 4e 5f 52 45 51 55 49 52 45 44 00 44 45 43 52 59 50 54 5f 44 41 54 41 5f 43 4f 52 52 55 50 54 45 44 00}  //weight: 3, accuracy: High
        $x_3_3 = {5b 00 49 00 4e 00 53 00 45 00 52 00 54 00 5d 00 20 00 00 0f 20 00 5b 00 45 00 4e 00 44 00 5d 00 20 00 00 1f 20 00 5b 00 41 00 52 00 52 00 4f 00 57 00 2c 00 20 00 44 00 4f 00 57 00 4e 00 5d 00}  //weight: 3, accuracy: High
        $x_3_4 = {00 65 00 43 00 4d 00 44 00 00 80 8d 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 46 00 75 00 6e 00 63 00 74 00 69 00 6f 00 6e 00 73 00 20 00 3e 00 3e 00 20 00 54 00 72 00 69 00 65 00 64 00 20 00 74 00 6f 00 20 00 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 43 00 4d 00 44 00 3a 00 20 00}  //weight: 3, accuracy: High
        $x_3_5 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 46 00 6f 00 72 00 6d 00 73 00 5c 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 32 [0-32] 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78}  //weight: 3, accuracy: Low
        $x_3_6 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 5c 00 49 00 6e 00 74 00 65 00 6c 00 6c 00 69 00 46 00 6f 00 72 00 6d 00 73 00 5c 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 32 [0-32] 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61 00 00 15 5c 00 6c 00 6f 00 67 00 69 00 6e 00 64 00 61 00 74 00 61}  //weight: 3, accuracy: Low
        $x_3_7 = {0e 01 00 09 54 75 74 43 6c 69 65 6e 74 00 00 05 01 00 00 00 00 17 01 00 12 43 6f 70 79 72 69 67 68 74 20 c2}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Lazy_GPBX_2147912800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.GPBX!MTB"
        threat_id = "2147912800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 01 39 24 00 00 00 00 00 23 00 [0-16] c1 23 00 00 [0-18] 28 ?? 00 00 0a fe}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPBF_2147912861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPBF!MTB"
        threat_id = "2147912861"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 58 07 8e 69 5d 13 10 07 11 10 91 13 11 11 0f 11 11 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 12}  //weight: 2, accuracy: High
        $x_2_2 = {07 11 0d 91 11 0e 61 13 0f 11 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NJ_2147913584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NJ!MTB"
        threat_id = "2147913584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54}  //weight: 5, accuracy: High
        $x_2_2 = "GetMRACGame" ascii //weight: 2
        $x_2_3 = "$$method0x600" ascii //weight: 2
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SG_2147914242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SG!MTB"
        threat_id = "2147914242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SW_HIDE" ascii //weight: 1
        $x_1_2 = "encrypted_key" wide //weight: 1
        $x_3_3 = "//api.gofile.io/getServer" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMAJ_2147914949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMAJ!MTB"
        threat_id = "2147914949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 59 18 5a 6a 59 07 6a 58 13 0b 11 0b d1 13 0c 11 07 08 17 58 11 0c 6f ?? 00 00 0a 00 08 18 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NB_2147915105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NB!MTB"
        threat_id = "2147915105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 07 1f 10 8d ?? 00 00 01 0c 08 16 1d 9c 08 17 1c 9c 08 18 1b 9c 08 19 1a 9c 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Skup.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SJPL_2147915124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SJPL!MTB"
        threat_id = "2147915124"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 91 11 07 61 13 1a 11 43}  //weight: 2, accuracy: High
        $x_1_2 = {07 09 17 58 08 5d 91 13 1b 11 1a 11 1b 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_MX_2147918780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.MX!MTB"
        threat_id = "2147918780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 28 31 00 00 0a 6f 32 00 00 0a 0d 06 09 6f 10 00 00 06 13 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_MX_2147918780_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.MX!MTB"
        threat_id = "2147918780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 6f 1f 00 00 0a 08 6f 20 00 00 0a 28 21 00 00 0a 0b de 14}  //weight: 1, accuracy: High
        $x_1_2 = {11 10 72 8b 01 00 70 6f 1a 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPRA_2147921750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPRA!MTB"
        threat_id = "2147921750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 28 11 20 61 19 11 1c 58 61 11 30 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_KAZ_2147924326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAZ!MTB"
        threat_id = "2147924326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08}  //weight: 1, accuracy: High
        $x_1_2 = "Enc_Output.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AJS_2147924671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AJS!MTB"
        threat_id = "2147924671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 72 bb 00 00 70 28 20 00 00 06 72 ed 00 00 70 28 20 00 00 06 28 21 00 00 06 13 0c 20 00 00 00 00 7e 90 00 00 04 7b 6e 00 00 04 39 0f 00 00 00 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ARAZ_2147928217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ARAZ!MTB"
        threat_id = "2147928217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$49831765-298d-43f2-82a0-018c3bff7857" ascii //weight: 2
        $x_2_2 = "gd_.Properties.Resources" ascii //weight: 2
        $x_2_3 = "\\gd].pdb" ascii //weight: 2
        $x_2_4 = "\\lol.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NS_2147929307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NS!MTB"
        threat_id = "2147929307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ftp-web.funpic.de" wide //weight: 2
        $x_1_2 = "Spybot.exe" ascii //weight: 1
        $x_1_3 = "trojascreenshot" ascii //weight: 1
        $x_1_4 = "$e5bc6751-971d-43ad-82cf-38dfed81957b" ascii //weight: 1
        $x_1_5 = "Start Menu\\Programs\\Startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AMCW_2147929515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AMCW!MTB"
        threat_id = "2147929515"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c}  //weight: 3, accuracy: High
        $x_1_2 = {09 02 8e 69 18 da 17 d6}  //weight: 1, accuracy: High
        $x_1_3 = {70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_MBWJ_2147929763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.MBWJ!MTB"
        threat_id = "2147929763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "lRlWTmZwmpDk4Kd7pJQZgjNpli9ZPF6ZLIQgcLvqdN1vlY8NpJM1hSY9l3o2HWfISVG8iNTpLBeinA" ascii //weight: 2
        $x_1_2 = "m8eG6wl856F8jPMhMARQ9etQ" ascii //weight: 1
        $x_1_3 = "Em/fE47ClCu263lwWIPe3GASleLBc/E" ascii //weight: 1
        $x_1_4 = "Anti-VT.exe" ascii //weight: 1
        $x_1_5 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_6 = "ae9ced6271c1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AYA_2147930961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AYA!MTB"
        threat_id = "2147930961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 05 07 11 05 91 11 04 11 05 11 04 8e b7 5d 91 61 9c 00 11 05 17 d6 13 05 11 05 11 07 13 08 11 08 31 dc}  //weight: 2, accuracy: High
        $x_2_2 = "snake.My.Resources" ascii //weight: 2
        $x_1_3 = "DecryptPayload" ascii //weight: 1
        $x_1_4 = "ExecutePayload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AYD_2147930962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AYD!MTB"
        threat_id = "2147930962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$c82ce7ac-31af-46b4-b97f-8ad002d69900" ascii //weight: 10
        $x_5_2 = "Stub\\obj\\Debug\\Stub.pdb" ascii //weight: 5
        $x_5_3 = "Stub.Properties.Resources" wide //weight: 5
        $x_5_4 = "pastebin.com/raw" wide //weight: 5
        $x_1_5 = "GenerateKey" ascii //weight: 1
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "DecryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Lazy_KAAH_2147931026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.KAAH!MTB"
        threat_id = "2147931026"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {47 7e 25 57 87 a8 26 9a 75 02 db 6a 6b 9a 29 4b 5e 8a 47 98 fe a3 b7 46 c6 86 ec}  //weight: 4, accuracy: High
        $x_3_2 = {a1 c3 fb a2 a4 ec d7 57 3d 4a 88 41 9a f0 4e 8c e6 20 30 ce 6c c7 65 26 65 56}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NIT_2147931115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NIT!MTB"
        threat_id = "2147931115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {fe 0c 01 00 fe 0c 02 00 6f bc 00 00 0a fe 0e 03 00 00 fe 0c 00 00 fe 0c 03 00 20 58 00 00 00 61 d1 6f bd 00 00 0a 26 00 fe 0c 02 00 20 01 00 00 00 58 fe 0e 02 00 fe 0c 02 00 fe 0c 01 00 6f be 00 00 0a 3f b8 ff ff ff fe 0c 00 00 6f 17 00 00 0a fe 0e 04 00 38 00 00 00 00 fe 0c 04 00 2a}  //weight: 2, accuracy: High
        $x_1_2 = {28 46 00 00 0a 6f 51 00 00 0a 0b 06 07 1f 42 28 37 00 00 06 28 52 00 00 0a 07 0c de 13 26 14 0c de 0e 06 28 53 00 00 0a 1f 42 28 37 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SVJI_2147931905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SVJI!MTB"
        threat_id = "2147931905"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 08 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 16 2d 0e 2b 21 2b 23 16 2b 23 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 25 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 de 30}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NU_2147933076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NU!MTB"
        threat_id = "2147933076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {17 33 1d 73 5c 00 00 0a 25 72 b6 01 00 70 6f 5d 00 00 0a 25 17 6f 5e 00 00 0a 28 5f 00 00 0a 26 02}  //weight: 3, accuracy: High
        $x_2_2 = {72 b0 04 00 70 02 7b 10 00 00 04 6f 3a 00 00 0a 28 72 00 00 0a 72 ba 04 00 70 6f 73 00 00 0a 72 64 0b 00 70 72 ba 04 00 70 6f 73 00 00 0a 28 6b 00 00 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SEDA_2147934970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SEDA!MTB"
        threat_id = "2147934970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 11 11 1e 11 09 91 13 21 11 1e 11 09 11 21 11 22 61 19 11 1c 58 61 11 2f 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PGL_2147939897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PGL!MTB"
        threat_id = "2147939897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 1f 14 6f ?? 00 00 0a 13 04 2b 29 11 04 1f 0a fe 02 13 06 11 06 2c 0c 07 08 66 5f 07 66 08 5f 60 0d 2b 16 11 05 74 ?? 00 00 01 17 1f 14 6f ?? 00 00 0a 13 04 17 13 07 2b d2 09 28 ?? 00 00 0a 0a 06 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PGL_2147939897_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PGL!MTB"
        threat_id = "2147939897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 00 65 00 6d 00 70 00 00 13 5c 00 78 00 4c 00 6f 00 6b 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_2_2 = "rgstjrepresentatived" ascii //weight: 2
        $x_2_3 = "hvydzspecificationsp" ascii //weight: 2
        $x_5_4 = "DownloadFile" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PGY_2147940191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PGY!MTB"
        threat_id = "2147940191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {12 00 20 00 0b fc ff 1d 63 66 20 00 f6 ff ff 18 63 65 1d 63}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PGY_2147940191_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PGY!MTB"
        threat_id = "2147940191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "iA9B1uKFddQdqiLSSuzvD2GhL1o2Jv+v" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NITA_2147941024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NITA!MTB"
        threat_id = "2147941024"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {12 00 02 7d 10 00 00 04 12 00 03 7d 11 00 00 04 12 00 04 7d 12 00 00 04 12 00 28 14 00 00 0a 7d 0f 00 00 04 12 00 15 7d 0e 00 00 04 12 00 7b 0f 00 00 04 0b 12 01 12 00 28 01 00 00 2b 12 00 7c 0f 00 00 04 28 16 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {03 11 0e 1f 0c 58 28 ?? 00 00 0a 13 10 03 11 0e 1f 10 58 28 ?? 00 00 0a 13 11 03 11 0e 1f 14 58 28 ?? 00 00 0a 13 12 11 11 2c 2e 11 11 8d 23 00 00 01 13 13 03 11 12 11 13 16 11 11 28 ?? 00 00 0a 12 00 7b 0a 00 00 04 11 0a 11 10 58 11 13 11 11 12 0b 28 ?? 00 00 06 26 11 0e 1f 28 58 13 0e 11 0f 17 58 13 0f 11 0f 11 0d 32 94 11 0a 28 29 00 00 0a 13 14 12 00 7b 0a 00 00 04 11 06 1f 29 94 1e 58 11 14 1a 12 0b 28 06 00 00 06 26 03 11 04 1f 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Lazy_AYB_2147942952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AYB!MTB"
        threat_id = "2147942952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mdridefys.info" wide //weight: 2
        $x_1_2 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_3 = "/c wmic path win32_computersystemproduct get uuid" wide //weight: 1
        $x_1_4 = "Cmd mode enabled, all commands will be redirect to CMD. Response delay is :" wide //weight: 1
        $x_1_5 = "SELECT * FROM Win32_Product" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_SPF_2147944006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.SPF!MTB"
        threat_id = "2147944006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 0f 11 20 11 09 91 13 28 11 20 11 09 11 26 11 28 61 11 1e 19 58 61 11 2e 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_GVC_2147944037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.GVC!MTB"
        threat_id = "2147944037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0f 11 20 11 09 91 13 28 11 20 11 09 11 26 11 28 61 ?? ?? ?? 58 61 11 2d 61 d2 9c 11 28 13 1e ?? ?? ?? 58 13 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_NJA_2147944382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.NJA!MTB"
        threat_id = "2147944382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1618af20-7450-47cf-a78d-03e017000dc8" ascii //weight: 2
        $x_1_2 = "\"a\"W\"P\"P\"G\"L\"V\"t\"G\"P\"Q\"K\"M\"L\"" ascii //weight: 1
        $x_1_3 = "C\"@\"A\"F\"G\"D\"E\"J\"K\"H\"I\"N\"O\"L\"M\"R\"S\"P\"Q\"V\"W\"T\"U\"Z\"[\"X\"" ascii //weight: 1
        $x_1_4 = "N*C*Y*Z*F*K*S*d*K*G*O***" ascii //weight: 1
        $x_1_5 = "g*E*P*C*F*F*K*" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AC_2147944994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AC!MTB"
        threat_id = "2147944994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 64 00 00 01 0d 11 06 20 b3 e5 26 d9 61 13 0a 38 1f 01 00 00 20 21 3f ?? da 13 06 11 06 20 32 97 ac 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_GVA_2147945301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.GVA!MTB"
        threat_id = "2147945301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 8c 3f 00 00 01 28 2b 00 00 0a 6f 2c 00 00 0a 26 11 0e 6f 29 00 00 0a 72 73 00 00 70 28 2d 00 00 0a 2c 08 11 0e 6f 2a 00 00 0a 0d 11 0d 17 58 13 0d 11 0d 11 0c 8e 69 32 95}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_ATW_2147948428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.ATW!MTB"
        threat_id = "2147948428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {09 6f 1d 00 00 06 6f 58 00 00 0a 28 59 00 00 0a 11 05 28 19 00 00 06 2c 0c 06 09 6f 1b 00 00 06 6f 06 00 00 06 09 6f 1f 00 00 06 18 40 8d 00 00 00 11 04 09 6f 1d 00 00 06 6f 58 00 00 0a 07 28 18 00 00 06 09 6f 1d 00 00 06 17}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_AKQ_2147948429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.AKQ!MTB"
        threat_id = "2147948429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 0a 11 09 28 18 00 00 0a 72 93 02 00 70 11 0a 28 12 00 00 0a 28 02 00 00 06 de 1d 13 0e 72 d5 02 00 70 11 0e 6f 19 00 00 0a 28 12 00 00 0a 28 02 00 00 06 dd a7 01 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {09 72 be 0a 00 70 6f 22 00 00 0a 09 72 d2 0a 00 70 6f 22 00 00 0a 09 72 0a 0b 00 70 06 72 16 0b 00 70 28 1c 00 00 0a 6f 22 00 00 0a 09 72 0a 0b 00 70 07 72 16 0b 00 70 28 1c 00 00 0a 6f 22 00 00 0a de 0a 09 2c 06 09 6f 23 00 00 0a dc 73 41 00 00 0a 25 07 6f 42 00 00 0a 25 17 6f 43 00 00 0a 25 17 6f 44 00 00 0a 28 45 00 00 0a 26 72 1a 0b 00 70 28 02 00 00 06 de 1a}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_JLK_2147948438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.JLK!MTB"
        threat_id = "2147948438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AntiAnalysis" ascii //weight: 2
        $x_2_2 = "AddToWindowsDefenderExclusions" ascii //weight: 2
        $x_2_3 = "CheckRemoteDebuggerPresent" ascii //weight: 2
        $x_2_4 = "RMLoader.LoginClassWindows.resources" ascii //weight: 2
        $x_2_5 = "https://pastebin.com/raw/n3KdM6ML" wide //weight: 2
        $x_2_6 = "http://93.123.84.0/CelBuild.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PGPH_2147949051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PGPH!MTB"
        threat_id = "2147949051"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 12 04 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
        $x_5_2 = "https://discord.horse/js/bw_bundle.js" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lazy_PPR_2147951170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lazy.PPR!MTB"
        threat_id = "2147951170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lazy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 12 02 28 ?? 00 00 06 11 0b 16 11 0a 16 6f ?? 00 00 0a 26 11 09 11 0b 16 11 0b 8e 69 6f ?? 00 00 0a 25 13 0a 16 30 da}  //weight: 10, accuracy: Low
        $x_5_2 = "offkeylogger.dll.compressed" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

