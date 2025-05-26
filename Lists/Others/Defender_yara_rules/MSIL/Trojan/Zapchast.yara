rule Trojan_MSIL_Zapchast_RDA_2147836832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.RDA!MTB"
        threat_id = "2147836832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c0a875c7-ffac-4ca6-88d2-b9d6cc9295ff" ascii //weight: 1
        $x_1_2 = "\\C_\\Application\\c_.#$%" wide //weight: 1
        $x_1_3 = "hN<v<.>ttN<v<.>ps:/N<v<.>/" wide //weight: 1
        $x_1_4 = "N<v<.>" wide //weight: 1
        $x_1_5 = "V2tjNWRGbFhiSFZqTXpFd1pVaFJQUT09" wide //weight: 1
        $x_1_6 = "WXpOV2FXWllValJrUVQwOQ==" wide //weight: 1
        $x_1_7 = "WVRKV05XWllValJrUVQwOQ==" wide //weight: 1
        $x_1_8 = "WWpOQ01HRlhPWFZqTXpFd1pVaFJQUT09" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_MBAT_2147838922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.MBAT!MTB"
        threat_id = "2147838922"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 00 62 00 67 00 68 00 67 00 74 00 72 00 66 00 62 00 67 00 66 00 62 00 67 00 66 00 62 00 67 00 64 00 74 00 64 00 68 00 62 00 64 00 67 00 72 00 62 00 66 00 66 00 74 00 62 00 67 00 68 00 67 00 74 00 72 00 66 00 62 00 67 00 66 00 62 00 67 00 66 00 62 00 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PSYI_2147891919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PSYI!MTB"
        threat_id = "2147891919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 36 00 00 0a 25 28 ?? 00 00 0a 6f 38 00 00 0a 72 92 01 00 70 28 ?? 00 00 0a 6f 3a 00 00 0a 0a 06 72 ea 01 00 70 72 f0 01 00 70 6f 3b 00 00 0a 0a 72 f4 01 00 70 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PSYJ_2147891920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PSYJ!MTB"
        threat_id = "2147891920"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 35 01 00 0a 17 73 66 01 00 0a 0c 08 02 16 02 8e 69 6f 85 01 00 0a 08 6f 9b 00 00 0a 06 6f 8e 00 00 0a 0d 09 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PSZX_2147894283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PSZX!MTB"
        threat_id = "2147894283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 11 6f 1f 00 00 0a 13 12 11 0e 28 ?? 00 00 0a 13 13 00 20 00 04 00 00 8d 24 00 00 01 13 14 2b 0f 00 11 12 11 14 16 11 15 6f 21 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PSZZ_2147894284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PSZZ!MTB"
        threat_id = "2147894284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 37 00 00 0a 0a 03 02 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 06 02 07 6f 38 00 00 0a 00 00 de 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PSQL_2147897149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PSQL!MTB"
        threat_id = "2147897149"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2f 1f 73 0a 00 00 0a 0a 06 72 0f 00 00 70 6f ?? ?? ?? 0a 06 17 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 26 de 0e 0b 07 28 ?? ?? ?? 0a 28 0f 00 00 0a de 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_PTAC_2147899415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.PTAC!MTB"
        threat_id = "2147899415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 6f 37 00 00 06 6f a1 00 00 0a a2 00 08 1a 72 d5 02 00 70 a2 00 08 28 ?? 00 00 0a 18 16 15 28 ?? 00 00 0a 26 00 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_AMBF_2147899657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.AMBF!MTB"
        threat_id = "2147899657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "KoAOkX.MXuuJb" wide //weight: 2
        $x_2_2 = "WwQTZc" wide //weight: 2
        $x_1_3 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_AMBH_2147900302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.AMBH!MTB"
        threat_id = "2147900302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 11 17 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 06 00 70 6f ?? 00 00 0a 72 ?? 06 00 70 6f ?? 00 00 0a 14 18 8d ?? 00 00 01 25 16 11 1b 72 ?? 06 00 70 28 ?? 00 00 0a a2 25 17 11 1a 28 ?? 00 00 0a a2}  //weight: 2, accuracy: Low
        $x_1_2 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "WebClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zapchast_ELO_2147942194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zapchast.ELO!MTB"
        threat_id = "2147942194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zapchast"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 11 10 58 11 13 11 13 8e 69 12 01 6f 20 00 00 06 2d 06 73 0b 00 00 0a 7a 11 0d 1f 28 58 13 0d 11 0f 17 58 13 0f 11 0f 11 0e 32 84}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

