rule Trojan_MSIL_Stealerium_GMX_2147901138_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerium.GMX!MTB"
        threat_id = "2147901138"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 05 02 11 05 7d ?? ?? ?? ?? 00 72 ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 25 2d 04 26 14 2b 05 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 17 28 ?? ?? ?? 06 26 00 de 00}  //weight: 5, accuracy: Low
        $x_5_2 = {25 16 1f 2c 9d 6f ?? ?? ?? 0a 0b 07 07 8e 69 17 59 9a 0c 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerium_SPP_2147944907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerium.SPP!MTB"
        threat_id = "2147944907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 03 11 00 11 03 91 11 04 11 03 11 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerium_SI_2147956135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerium.SI!MTB"
        threat_id = "2147956135"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 0b 11 0c 6f 2d 00 00 0a 13 23 12 23 28 2e 00 00 0a 13 1d 19 8d 3a 00 00 01 25 16 1f 10 9e 25 17 1e 9e 13 1e 03 07 6f 2c 00 00 0a 59 13 1f 16 13 24 2b 27}  //weight: 1, accuracy: High
        $x_1_2 = {11 08 17 11 1b 17 5f 58 17 11 1b 17 58 17 5f 58 73 23 00 00 0a 6f 24 00 00 0a 00 11 1b 17 58 13 1b 11 1b 11 09 fe 04 13 1c 11 1c 2d d3}  //weight: 1, accuracy: High
        $x_1_3 = "NimGame.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Stealerium_AYA_2147959119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Stealerium.AYA!MTB"
        threat_id = "2147959119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealerium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 6f 23 00 00 0a 0b 02 73 24 00 00 0a 0c 08 07 16 73 25 00 00 0a 0d 73 26 00 00 0a 13 04 00 09 11 04 6f 27 00 00 0a 00 11 04 6f 28 00 00 0a 13 05 de 40 11 04 2c 08 11 04 6f 1d 00 00 0a 00 dc}  //weight: 5, accuracy: High
        $x_3_2 = "$64f6977a-ea10-4757-9bd6-6366a72939f1" ascii //weight: 3
        $x_2_3 = "stub\\obj\\Debug\\stub.pdb" ascii //weight: 2
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

