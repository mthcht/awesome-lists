rule Trojan_MSIL_PovertyStealer_AP_2147897481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PovertyStealer.AP!MTB"
        threat_id = "2147897481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PovertyStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 73 ?? 00 00 06 08 6f ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

