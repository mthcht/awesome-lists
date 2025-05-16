rule Trojan_MSIL_Stealerc_SK_2147846283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.SK!MTB"
        threat_id = "2147846283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 3f d1 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAES_2147850709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAES!MTB"
        threat_id = "2147850709"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 05 00 11 05 6f ?? 00 00 0a 13 06 11 06 08 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 03 6a da 17 6a da 13 07 16 6a 13 08 2b 0f 07 16 6f ?? 00 00 0a 00 11 08 17 6a d6 13 08 11 08 11 07 31 eb de 0e 00 11 06 2c 08 11 06 6f ?? 00 00 0a 00 dc}  //weight: 3, accuracy: Low
        $x_2_2 = {16 13 04 2b 1d 07 02 11 04 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 04 18 d6 13 04 11 04 09 31 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAHN_2147851706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAHN!MTB"
        threat_id = "2147851706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 09 11 09 28 ?? ?? 00 06 11 09 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? fd ff ff 26 20 05 00 00 00 38 ?? fd ff ff 00 11 07 73 ?? 00 00 0a 13 03 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26 20 00 00 00 00 38 ?? 00 00 00 fe 0c 0c 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAML_2147888665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAML!MTB"
        threat_id = "2147888665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 13 06 20 00 00 00 00 28 ?? 00 00 06 39 ?? ff ff ff 26 20 00 00 00 00 38 ?? ff ff ff 00 11 05 11 0a 6f ?? 00 00 0a 38 ?? ff ff ff 00 11 05 17 6f ?? 00 00 0a 38 ?? ff ff ff 00 11 06 11 08 16 11 08 8e 69 6f ?? 00 00 0a 13 07}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAPW_2147891678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAPW!MTB"
        threat_id = "2147891678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 08 11 03 6f ?? 00 00 0a 20 00 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 11 08 17 28 ?? 00 00 06 38 ?? ff ff ff 00 00 11 08 6f ?? 00 00 0a 13 06 20 01 00 00 00 28 ?? 00 00 06 3a ?? ff ff ff 26 38 ?? ff ff ff 00 11 06 11 09 16 11 09 8e 69 6f ?? 00 00 0a 13 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAQY_2147892179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAQY!MTB"
        threat_id = "2147892179"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 20 0c 1f 8f f8 28 ?? 00 00 06 28 ?? 0e 00 06 20 2d 1f 8f f8 28 ?? 00 00 06 28 ?? 0e 00 06 28 ?? 0e 00 06 13 04}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAUC_2147893940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAUC!MTB"
        threat_id = "2147893940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 28 ?? 00 00 06 16 28 ?? 00 00 06 8e 69 6f ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_NC_2147894991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.NC!MTB"
        threat_id = "2147894991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 1c 13 01 12 01 1d 13 03 12 03 6f ?? 00 00 06 26}  //weight: 3, accuracy: Low
        $x_2_2 = {02 8e 69 1f 11 da 17 d6 8d ?? 00 00 01 13 0b 20 ?? 00 00 00 28 ?? 00 00 06 3a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_NC_2147894991_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.NC!MTB"
        threat_id = "2147894991"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 d2 52 07 08 8f ?? 00 00 01 25 47 07 11 05 91 06 1a 58 4a 61 d2 61 d2 52 07 11 05 8f 07 00 00 01 25 47 07 08 91 61 d2 52 11 05 17 58}  //weight: 5, accuracy: Low
        $x_1_2 = "Binance Airdrop_.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAXW_2147897632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAXW!MTB"
        threat_id = "2147897632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {25 11 04 28 ?? ?? 00 06 00 25 17 6f ?? 00 00 0a 00 25 18 6f ?? 00 00 0a 00 25 07 28 ?? ?? 00 06 00 13 08 20 00 00 00 00 38 ?? ff ff ff 00 05 1f 10 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 20 05 00 00 00 38 ?? ff ff ff 11 08 6f ?? 00 00 0a 13 09 20 07 00 00 00 38 ?? ff ff ff 11 09 09 16 09 8e 69 6f ?? 00 00 0a 13 06}  //weight: 4, accuracy: Low
        $x_1_2 = "{}d{}o{}h{}t{}e{}M{}t{}e{}G{}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAXZ_2147897718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAXZ!MTB"
        threat_id = "2147897718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {05 1f 10 28 ?? 00 00 2b 1f 20 28 ?? 00 00 2b 28 ?? 00 00 2b 0c 20 05 00 00 00 38 ?? ?? 00 00 11 08 28 ?? ?? 00 06 13 09}  //weight: 2, accuracy: Low
        $x_2_2 = {11 09 09 16 09 8e 69 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_1_3 = "{}d{}o{}h{}t{}e{}M{}t{}e{}G{}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAYE_2147897810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAYE!MTB"
        threat_id = "2147897810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 11 04 28 ?? ?? 00 06 00 25 17 6f ?? 00 00 0a 00 25 18 28 ?? ?? 00 06 00 25 07 28 ?? ?? 00 06 00 13 08}  //weight: 2, accuracy: Low
        $x_2_2 = {11 09 09 16 09 8e 69 28 ?? ?? 00 06 13 06}  //weight: 2, accuracy: Low
        $x_1_3 = "{}d{}o{}h{}t{}e{}M{}t{}e{}G{}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAYK_2147898308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAYK!MTB"
        threat_id = "2147898308"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 01 00 04 06 1b 28 ?? 01 00 06 7e ?? 01 00 04 06 28 ?? 01 00 06 0d 7e ?? 01 00 04 09 05 16 05 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AAYP_2147898437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AAYP!MTB"
        threat_id = "2147898437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 11 02 6f ?? 00 00 0a 25 17 28 ?? ?? 00 06 25 18 28 ?? ?? 00 06 25 11 00 6f ?? 00 00 0a 6f ?? 00 00 0a 11 01 16 11 01 8e 69 28 ?? ?? 00 06 13 03}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_EGAA_2147902857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.EGAA!MTB"
        threat_id = "2147902857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 1b 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AMMB_2147904465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AMMB!MTB"
        threat_id = "2147904465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0d 8f ?? 00 00 01 25 71 ?? 00 00 01 11 01 11 11 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AMMF_2147906219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AMMF!MTB"
        threat_id = "2147906219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 15 7e ?? 00 00 04 16 8f ?? 00 00 01 7e ?? 00 00 04 8e 69 1f 40 12 00 6f ?? ?? 00 06 26 16 13 08 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualProtectEx" wide //weight: 1
        $x_1_3 = "WaitForSingleObject" wide //weight: 1
        $x_1_4 = "CreateThread" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_AMMF_2147906219_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AMMF!MTB"
        threat_id = "2147906219"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {64 00 20 00 a0 12 20 00 1d 12 20 00 35 12 20 00 1b 12 20 00 eb 12 20 00 1d 12 20 00 e8 12 20 00 1d 12 20 00 0b 12 20 00 28 13 20 00 60 12 20 00 41 00 20 00 6f 00 20 00 65 12 20 00 2d 12 20 00 00 13 20 00 62 12 20 00 2d 12 20 00 c8 12 20 00 e8 12 20 00 01 12 20 00 3b 12 20 00 4c 00 20 00}  //weight: 2, accuracy: High
        $x_2_2 = {65 00 70 00 20 00 79 00 20 00 54 00 20 00 74 00 20 00 70 12 20 00 62 12 20 00 2d 12 20 00 f5 12 20 00 54 13}  //weight: 2, accuracy: High
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_GPAX_2147915660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.GPAX!MTB"
        threat_id = "2147915660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 05 06 11 ?? 6f ?? 00 00 0a 13 ?? 08 07 6a 5a 11 ?? 6a 58 0c 00 11 ?? 17 58 13 ?? 11 ?? 09 fe 04 13 ?? 11 ?? 2d d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_MBXT_2147920900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.MBXT!MTB"
        threat_id = "2147920900"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "AAMJIIJZNZJPRULUSLKBJZEPYTYUCJJJHILFUREYLF" ascii //weight: 4
        $x_3_2 = "back7top_managment.Resources.resources" ascii //weight: 3
        $x_2_3 = "FCPLWVWJACDQWLCPZEWWOTZFWDIDLPQCBASLPFYALLYSGJAQJAEMDMDLCKOTMTX" ascii //weight: 2
        $x_1_4 = "cH8IXcwQY4Peh2qpAn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_SL_2147923084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.SL!MTB"
        threat_id = "2147923084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 07 6f 5c 00 00 0a 0c 04 03 6f 5d 00 00 0a 59 0d 09 19 32 2c 03 19 8d 58 00 00 01 25 16 12 02 28 5e 00 00 0a 9c 25 17 12 02 28 5f 00 00 0a 9c 25 18 12 02 28 60 00 00 0a 9c}  //weight: 2, accuracy: High
        $x_2_2 = "Poker.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_SM_2147923284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.SM!MTB"
        threat_id = "2147923284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 08 03 08 91 05 08 06 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 0d 09 2d e1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_SM_2147923284_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.SM!MTB"
        threat_id = "2147923284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 19 8d 8f 00 00 01 25 16 12 02 28 bd 00 00 0a 9c 25 17 12 02 28 be 00 00 0a 9c 25 18 12 02 28 bf 00 00 0a 9c}  //weight: 2, accuracy: High
        $x_2_2 = "AgroFarm.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_GPG_2147927071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.GPG!MTB"
        threat_id = "2147927071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 13 06 13 07 11 18 13 1c 18 8d 2c 00 00 01 13 17 11 17 16 1f 30 9e 00 11 17 17 1f f9 11 17 16 94 58 9e 00 11 1c 11 17 17 94}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_NK_2147928019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.NK!MTB"
        threat_id = "2147928019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "b584fd23-0cf9-4331-9777-a3ed637f83a8" ascii //weight: 2
        $x_1_2 = "AddDefenderExclusions" ascii //weight: 1
        $x_1_3 = "powershell.exe" ascii //weight: 1
        $x_1_4 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 64 00 61 00 6e 00 69 00 65 00 5c 00 73 00 6f 00 75 00 72 00 63 00 65 00 5c 00 72 00 65 00 70 00 6f 00 73 00 5c 00 51 00 77 00 65 00 73 00 74 00 5c 00 51 00 77 00 65 00 73 00 74 00 5c 00 6f 00 62 00 6a 00 5c 00 44 00 65 00 62 00 75 00 67 00 5c 00 [0-31] 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 3a 5c 55 73 65 72 73 5c 64 61 6e 69 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 51 77 65 73 74 5c 51 77 65 73 74 5c 6f 62 6a 5c 44 65 62 75 67 5c [0-31] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_6 = "powershell -Command \"Add-MpPreference -ExclusionPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Stealerc_AMDA_2147932347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.AMDA!MTB"
        threat_id = "2147932347"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 02 16 02 8e 69 6f ?? 00 00 0a 13 03 20}  //weight: 4, accuracy: Low
        $x_1_2 = {0a 26 20 00 00 00 00 7e ?? ?? 00 04 7b 40 00 d0 ?? 00 00 01 28 ?? 00 00 0a 11 ?? 6f ?? 00 00 0a 11 ?? a3 ?? 00 00 01 72 ?? 00 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_GPXA_2147938494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.GPXA!MTB"
        threat_id = "2147938494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sendDocument?chat_id=" ascii //weight: 2
        $x_2_2 = {1b 49 00 4d 00 41 00 50 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 1b 50 00 4f 00 50 00 33 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64}  //weight: 2, accuracy: High
        $x_1_3 = {65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 5f 00 6b 00 65 00 79 00 22 00 3a 00 22 00 28 00 2e 00 2a 00 3f 00 29}  //weight: 1, accuracy: High
        $x_1_4 = "Microsoft\\Edge\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_5 = "logins.json" ascii //weight: 1
        $x_1_6 = "Thunderbird\\Profiles" ascii //weight: 1
        $x_1_7 = "nss3.dll" ascii //weight: 1
        $x_1_8 = "PK11SDR_Decrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerc_GPAL_2147941551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerc.GPAL!MTB"
        threat_id = "2147941551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "www.new.eventawardsrussia.com" ascii //weight: 4
        $x_1_2 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

