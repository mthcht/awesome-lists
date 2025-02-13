rule Trojan_MSIL_Gasti_MA_2147839057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gasti.MA!MTB"
        threat_id = "2147839057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gasti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 07 28 23 00 00 0a 2d 2b 07 28 24 00 00 0a 26 07 06 28 1f 00 00 0a 11 04 28 25 00 00 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 08 28 1f 00 00 0a 17 28 0b 00 00 06 de 03}  //weight: 5, accuracy: Low
        $x_5_2 = "\\InExplor\\" wide //weight: 5
        $x_5_3 = "VLCplayer.ps1" wide //weight: 5
        $x_5_4 = "Y2xzDQpBZGQtVHlwZSAtQXNzZW1ibHlOYW1lIFN5c3RlbS5EcmF3aW5nDQp" wide //weight: 5
        $x_5_5 = "-ExecutionPolicy Bypass" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Gasti_MB_2147840324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gasti.MB!MTB"
        threat_id = "2147840324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gasti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "dXJfQVgzMTIgPSByZXBsYWNlKCJBWDMxMmh0QVgzMTJ0QVgzMTJwOi9BWDMxMi8xQ" wide //weight: 5
        $x_5_2 = {0c 08 72 9c 06 00 70 6f 1d 00 00 0a 08 72 8c 06 00 70 6f 1e 00 00 0a 08 17 6f 1f 00 00 0a 73 20 00 00 0a 25 08 6f 21 00 00 0a 6f 22 00 00 0a 26 de 03 26 de}  //weight: 5, accuracy: High
        $x_5_3 = "cfe5417e-c92f-424d-9662-2d4b58a45ca0" ascii //weight: 5
        $x_5_4 = "res.vbs" wide //weight: 5
        $x_5_5 = "WindowBrokerHost.Properties" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Gasti_PSKZ_2147846128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gasti.PSKZ!MTB"
        threat_id = "2147846128"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gasti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 25 00 00 0a 1f 0a 1f 14 6f ?? ?? ?? 0a 0a 06 28 17 00 00 06 72 5f 00 00 70 28 ?? ?? ?? 0a 0b 07 72 5f 00 00 70 72 69 00 00 70 6f ?? ?? ?? 0a 0c 06 28 17 00 00 06 0d 28 0b 00 00 06 72 73 00 00 70 09 72 73 00 00 70 28 ?? ?? ?? 0a 13 04 72 77 00 00 70 72 77 00 00 70 72 83 00 00 70 28 ?? ?? ?? 0a 26 28 11 00 00 06 28 1c 00 00 06 13 05 11 05 17 8d 2c 00 00 01 25 16 1f 0a 9d 6f 2a 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Gasti_ABUL_2147847372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Gasti.ABUL!MTB"
        threat_id = "2147847372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Gasti"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 0d 2b 2d 06 09 28 ?? 00 00 06 5a 28 ?? 00 00 0a 6e 7e ?? 00 00 04 8e 69 6a 5d 13 04 07 7e ?? 00 00 04 11 04 d4 93 6f ?? 00 00 0a 26 09 17 58 0d 09 02 32 cf 07 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

