rule Trojan_MSIL_Nano_PLLUH_2147930806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Nano.PLLUH!MTB"
        threat_id = "2147930806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nano"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 1f 10 62 0f 01 28 ?? 01 00 0a 1e 62 60 0f 01 28 ?? 01 00 0a 60 0b 02 19 8d ?? 00 00 01 25 16 07 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 07 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 07 20 ?? 00 00 00 5f d2 9c 6f ?? 01 00 0a 00 09}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

