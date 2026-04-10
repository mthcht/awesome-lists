rule Trojan_MSIL_RedCap_BLN_2147966809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedCap.BLN!MTB"
        threat_id = "2147966809"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedCap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 0a 16 0b 2b ?? 06 03 28 42 00 00 0a 28 3e 00 00 0a 0a 07 17 58 0b 07 04 32 ?? 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

