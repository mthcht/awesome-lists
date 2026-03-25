rule Trojan_MSIL_RemBladabindi_ZNG_2147965486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RemBladabindi.ZNG!MTB"
        threat_id = "2147965486"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RemBladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 11 16 11 17 6f ?? 00 00 0a 13 18 11 0e 03 fe 04 13 19 11 19 2c 17 00 11 0b 12 18 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0e 17 58 13 0e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

