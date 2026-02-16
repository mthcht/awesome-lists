rule Trojan_MSIL_Fuery_ABF_2147963083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Fuery.ABF!MTB"
        threat_id = "2147963083"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Fuery"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {25 16 03 6f ?? 01 00 0a 03 6f ?? 01 00 0a 03 6f ?? 01 00 0a 0a 12 00 28 ?? 01 00 0a 16 73 ?? 01 00 0a a2 25 17 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

