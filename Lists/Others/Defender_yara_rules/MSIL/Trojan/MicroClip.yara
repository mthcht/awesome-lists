rule Trojan_MSIL_MicroClip_RDA_2147933843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MicroClip.RDA!MTB"
        threat_id = "2147933843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MicroClip"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 07 6f ef 00 00 0a 6f f0 00 00 0a 13 05 08 07 11 05 17 6f f1 00 00 0a 6f f2 00 00 0a 26 11 04 17 d6 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

