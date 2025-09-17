rule Trojan_MSIL_ResolverRAT_PGR_2147944265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ResolverRAT.PGR!MTB"
        threat_id = "2147944265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ResolverRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 1e 2b 3a 2b 3b 2b 3c 08 91 03 08 07 5d 6f ?? 00 00 0a 61 d2 9c 16 2d e9 1a 2c e6 08 17 58 0c 08 02 8e 69 32 dc 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ResolverRAT_AOXA_2147944541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ResolverRAT.AOXA!MTB"
        threat_id = "2147944541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ResolverRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 00 11 02 02 11 02 91 03 11 02 11 03 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 3, accuracy: Low
        $x_2_2 = {11 02 17 58 13 02 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ResolverRAT_AEFB_2147952423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ResolverRAT.AEFB!MTB"
        threat_id = "2147952423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ResolverRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 04 28 ?? 00 00 0a 0d 05 28 ?? 00 00 0a 13 04 08 09 11 04 6f ?? 00 00 0a 13 05 03 73 ?? 00 00 0a 13 06 11 06 11 05 16 73 ?? 00 00 0a 13 07 73 ?? 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 38}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

