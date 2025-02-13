rule Trojan_MSIL_Banbra_AMAF_2147901598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Banbra.AMAF!MTB"
        threat_id = "2147901598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banbra"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 28 ?? 00 00 0a 26 1f ?? 1f ?? 28 ?? 00 00 06 28 ?? 00 00 06 72 ?? ?? 00 70 28 ?? 00 00 0a 0d 08 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

