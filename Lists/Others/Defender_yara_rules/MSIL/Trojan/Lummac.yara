rule Trojan_MSIL_Lummac_GPC_2147918271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.GPC!MTB"
        threat_id = "2147918271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 06 09 91 9c 06 09 11 ?? 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d [0-47] 91 61 d2 81 1d 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PPC_2147919304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PPC!MTB"
        threat_id = "2147919304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0c 6a 61 69 13 11 11 16 6a 11 1e 6e 58 6d 13 14 11 13 11 10 58 13 0c 11 18 11 1e 59 13 15 11 18 6e 11 15 6a 59 6d 13 0b 11 1a 6a 11 09 6e 59 6d 13 08 11 0e 11 09 5a 13 10 11 0d 11 0d 5b 13 19 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 20 06 08 06 09 91 9c 06 09 11 20 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 21 11 1f 6e 11 11 6a 3c ?? ?? ?? ?? 11 18 11 1e 5a 13 1b 11 0e 6e 11 19 6a 5b 6d 13 08 11 1b 6a 11 0f 6e 5a 6d 13 0b 11 18 11 12 5a 13 14 11 08 11 17 5c 13 0d 11 14 6e 11 19 6a 5b 69 13 0c 11 1e 6e 11 1c 6a 5a 69 13 1b 11 0a 11 1d 5a 13 17 11 1a 6a 11 1f 6e 59 6d 13 1f 11 12 11 18 61 13 0b 02 11 07 8f ?? ?? ?? ?? 25 71 ?? ?? ?? ?? 06 11 21 91 61 d2 81 ?? ?? ?? ?? 11 07 17 58 13 07 11 07 02 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PPD_2147919713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PPD!MTB"
        threat_id = "2147919713"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 69 13 18 11 19 6e 11 1a 6a 61 69 13 1a 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 1b 06 08 06 09 91 9c 06 09 11 1b 9c 06 08 91 06 09 91 58 20 00 01 00 00 5d 13 1c 02 11 13 8f 14 00 00 01 25 71 14 00 00 01 06 11 1c 91 61 d2 81 14 00 00 01 11 13 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PPE_2147923505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PPE!MTB"
        threat_id = "2147923505"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 35 12 1f 28 ?? 00 00 0a 12 35 28 ?? 00 00 0a 26 16 13 36 12 29 28 ?? 00 00 0a 28 ?? 00 00 0a 13 36 03 11 35 91 13 37 06 11 36 91 13 38 11 37 11 38 61 d2 13 37}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PGL_2147939225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PGL!MTB"
        threat_id = "2147939225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 07 1f 28 5a 58 13 08 28 ?? 00 00 0a 07 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PGL_2147939225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PGL!MTB"
        threat_id = "2147939225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 2e 11 2b 11 2d 91 58 28 ?? 00 00 0a 72 f8 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 5d 13 2e 20 ?? 00 00 00 fe 0e 33 00 38 9f fc ff ff 16 13 2e 38 0d 00 00 00 16 13 2d 20 ?? 00 00 00 38 8e fc ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PGL_2147939225_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PGL!MTB"
        threat_id = "2147939225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 13 07 38 e3 ff ff ff 28 ?? 00 00 0a 11 01 11 08 1e 6f ?? 00 00 0a 17 8d ?? 00 00 01 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 0a 72 02 01 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 39 b0 ff ff ff 38 17 00 00 00 11 01 11 02 1c 58 28 ?? 00 00 0a 13 03 20 03 00 00 00 38 eb fd ff ff 11 01 11 08 1f 14 58 28 ?? 00 00 0a 13 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Lummac_PGL_2147939225_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Lummac.PGL!MTB"
        threat_id = "2147939225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YTVlY2ZkN2RjODQzZTM5ZTA4ZmE4MWExMzQ2NTFkNjVhNjI2MDEwNDc0ZTJmNzQ3YzUxMDg3MWJjMTc1N2QyMg==" ascii //weight: 1
        $x_2_2 = "AD446C34F2704865A9E424BE5755BC8F9140414FD7E1456F1A4581F8C2D778A0" ascii //weight: 2
        $x_3_3 = "RSACryptoServiceProvider" ascii //weight: 3
        $x_4_4 = "CreateEncryptor" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

