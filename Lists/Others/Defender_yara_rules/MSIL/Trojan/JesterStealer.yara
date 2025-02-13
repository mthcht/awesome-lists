rule Trojan_MSIL_JesterStealer_AVEA_2147927413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/JesterStealer.AVEA!MTB"
        threat_id = "2147927413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JesterStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 5d 7e ?? 00 00 04 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 06 02 08 17 58 02 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

