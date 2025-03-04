rule Trojan_MSIL_Phoenixrat_NEAA_2147842025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phoenixrat.NEAA!MTB"
        threat_id = "2147842025"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phoenixrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {26 28 40 00 00 0a 25 26 11 64 28 41 00 00 0a 25 26 6f 42 00 00 0a 25 26 13 67 11 67 14}  //weight: 10, accuracy: High
        $x_5_2 = "Users\\LOTTE\\source" ascii //weight: 5
        $x_1_3 = "CryptoObfuscator_Output" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phoenixrat_NEAB_2147842027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phoenixrat.NEAB!MTB"
        threat_id = "2147842027"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phoenixrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 11 64 a2 25 17 06 11 66 17 28 ?? 00 00 0a 25 26 a2 25 18 07 11 66 17 28 ?? 00 00 0a 25 26 a2 25 19 08 11 66 17}  //weight: 10, accuracy: Low
        $x_5_2 = "CryptoObfuscator_Output" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Phoenixrat_NEAC_2147842550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Phoenixrat.NEAC!MTB"
        threat_id = "2147842550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Phoenixrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 06 0b 07 6f ?? 00 00 0a 17 da 0c 16 0d 2b 20 7e ?? 00 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 09 17 d6 0d 09 08 31 dc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

