rule Trojan_MSIL_DCRAT_STNB_2147812858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRAT.STNB!MTB"
        threat_id = "2147812858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f 00 08 20 00 04 00 00 58 28 ?? ?? ?? 2b 00 07 02 08 20 00 04 00 00 6f ?? ?? ?? 0a 0d 08 09 58 0c 09 20 00 04 00 00 fe 04 16 fe 01 13 05 11 05 2d 0c 00 0f 00 08 28 ?? ?? ?? 2b 00 2b 06 00 17 13 05 2b bb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DCRAT_STGB_2147812859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DCRAT.STGB!MTB"
        threat_id = "2147812859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DCRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {7e 05 00 00 04 11 09 28 ?? ?? ?? 06 25 26 7b cb 00 00 04 11 0a 91 28 ?? ?? ?? 06 11 0a 13 0b 11 0b 1f 0c 28 ?? ?? ?? 06 58 13 0a 11 0a 7e 05 00 00 04 11 09 28 ?? ?? ?? 06 25 26 7b cb 00 00 04 28 ?? ?? ?? 06 25 26 69 32 b6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

