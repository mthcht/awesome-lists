rule Trojan_MSIL_WhiteSnakeStealer_AAZY_2147899228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WhiteSnakeStealer.AAZY!MTB"
        threat_id = "2147899228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WhiteSnakeStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {20 00 00 00 00 fe 0e 06 00 38 ?? 00 00 00 fe 0c 03 00 fe 0c 06 00 fe 09 00 00 fe 0c 06 00 6f ?? 00 00 0a fe 0c 02 00 fe 0c 06 00 fe 0c 02 00 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 9d fe 0c 06 00 20 01 00 00 00 58 fe 0e 06 00 fe 0c 06 00 fe 09 00 00 6f ?? 00 00 0a 3f b1 ff ff ff}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

