rule Trojan_MSIL_Astraea_GDM_2147970541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Astraea.GDM!MTB"
        threat_id = "2147970541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Astraea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 17 59 02 08 91 06 61 08 17 59 20 00 01 00 00 5d 61 d2 9c 08 17 58 0c 08 02 8e 69 32 e1 28 ?? 00 00 0a 07 6f ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

