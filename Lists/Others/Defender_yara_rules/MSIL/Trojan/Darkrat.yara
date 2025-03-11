rule Trojan_MSIL_Darkrat_EARS_2147933527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Darkrat.EARS!MTB"
        threat_id = "2147933527"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Darkrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

