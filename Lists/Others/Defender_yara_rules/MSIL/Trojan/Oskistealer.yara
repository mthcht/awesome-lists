rule Trojan_MSIL_OskiStealer_NE_2147828740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OskiStealer.NE!MTB"
        threat_id = "2147828740"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OskiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 29 00 00 0a 73 2a 00 00 0a ?? 72 21 00 00 70 ?? 28 1d 00 00 0a 09 72 5f 00 00 70 6f 2b 00 00 0a 28 2c 00 00 0a ?? ?? ?? 28 2f 00 00 06 6f 1e 00 00 0a ?? 28 1d 00 00 0a ?? ?? 75 00 00 70 6f 2b 00 00 0a 28 2c 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

