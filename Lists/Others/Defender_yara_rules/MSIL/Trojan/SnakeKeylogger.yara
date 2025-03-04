rule Trojan_MSIL_SnakekeyLogger_AMAY_2147917384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakekeyLogger.AMAY!MTB"
        threat_id = "2147917384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakekeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 08 58 08 5d [0-40] 08 5d 08 58 [0-30] 61 [0-15] 58 20 00 01 00 00 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

