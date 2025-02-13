rule Trojan_MSIL_EternityStealer_AE_2147892349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/EternityStealer.AE!MTB"
        threat_id = "2147892349"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "EternityStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 26 16 0c 2b 12 06 6f ?? 00 00 0a 07 08 9a 6f ?? 00 00 0a 08 17 d6 0c 08 07 8e 69 32 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

