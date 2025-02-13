rule Trojan_MSIL_Wagex_NEAA_2147836508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.NEAA!MTB"
        threat_id = "2147836508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 2b 00 07 09 6f ?? 00 00 0a 13 04 06 11 04 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 28 ?? 00 00 06 0c 06 6f ?? 00 00 0a 08 16 08 8e 69 6f ?? 00 00 0a 13 05 de 0e}  //weight: 10, accuracy: Low
        $x_10_2 = {1b 2d 1c 26 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 2b 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPAG_2147841200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPAG!MTB"
        threat_id = "2147841200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 25 17 59 0c 16 fe 02 2d ed 07 6f ?? ?? ?? 0a 0a 06 0d 09}  //weight: 1, accuracy: Low
        $x_1_2 = "Aenvgcyctphbsuiqqgz.Dpsnaptrbrjrwjsdiol" wide //weight: 1
        $x_1_3 = "Wazyxkpiaetzvacdc" wide //weight: 1
        $x_1_4 = "Pztqk.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_GFM_2147842965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.GFM!MTB"
        threat_id = "2147842965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "80.66.75.36" ascii //weight: 1
        $x_1_2 = "Nqjrnfwx" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "Ntpwogtityaiqhypplgdgk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPH_2147853407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPH!MTB"
        threat_id = "2147853407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {08 17 73 2c 00 00 0a 0d 07 02 20 ?? ?? ?? 00 06 09 6f ?? ?? ?? 0a 26 08 17 58 0c 08 1f 32 fe 02 16 fe 01 13 04 11 04 2d d7}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPAP_2147892263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPAP!MTB"
        threat_id = "2147892263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {2b 08 2b 09 2b 0a 2b 0f de 21 06 2b f5 02 2b f4 6f ?? ?? ?? 0a 2b ef 0b 2b ee 16 2d 0c 19 2c 09 06 2c 07 06 6f ?? ?? ?? 0a 00 dc 2b 0b}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPAQ_2147893943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPAQ!MTB"
        threat_id = "2147893943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 8e 69 13 05 2b 0d 00 08 07 11 05 91 6f ?? ?? ?? 0a 00 00 11 05 25 17 59 13 05 16 fe 02 13 06 11 06 2d e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPQM_2147895186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPQM!MTB"
        threat_id = "2147895186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {02 7b 05 00 00 04 02 7b 06 00 00 04 28 ?? ?? ?? 06 13 17 02 72 3c 03 00 70 12 16 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 02 7b 06 00 00 04 72 48 03 00 70 02 7b 04 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 72 e7 00 00 70 28 ?? ?? ?? 06 00 00 11 16 17 58 13 16 11 16 02 7b 04 00 00 04 28 ?? ?? ?? 0a fe 04 13 18 11 18 2d 97}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_BSAA_2147901222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.BSAA!MTB"
        threat_id = "2147901222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 17 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 02 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_SPDU_2147901248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.SPDU!MTB"
        threat_id = "2147901248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 04 09 17 73 ?? ?? ?? 0a 13 05 11 05 02 16 02 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 13 06 dd 2b 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_BYAA_2147901360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.BYAA!MTB"
        threat_id = "2147901360"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 0b 28 ?? 00 00 0a 02 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 18 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 00 11 05 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 06 00 11 04 6f ?? 00 00 0a 13 07 16 13 08 2b 23}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Wagex_BZAA_2147901361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Wagex.BZAA!MTB"
        threat_id = "2147901361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Wagex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 07 11 06 91 6f ?? 00 00 0a 00 00 11 06 25 17 59 13 06 16 fe 02 13 07 11 07 2d e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

