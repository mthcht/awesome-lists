rule Trojan_MSIL_SnakeKeylogge_ZAD_2147968444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeylogge.ZAD!MTB"
        threat_id = "2147968444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeylogge"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1c 13 2b 38 ?? 00 00 00 02 11 27 11 28 6f ?? 00 00 0a 13 29 03 11 26 6f ?? 00 00 0a 59 13 2a 11 25 2d 03 1a 2b 01 18 13 2b 38 ?? 00 00 00 11 26 12 29 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 2a 17}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

