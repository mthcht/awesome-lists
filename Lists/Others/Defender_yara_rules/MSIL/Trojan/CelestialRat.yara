rule Trojan_MSIL_CelestialRat_AUGB_2147953949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CelestialRat.AUGB!MTB"
        threat_id = "2147953949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CelestialRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 02 09 7e ?? 00 00 04 8e 69 58 91 07 09 07 8e 69 5d 91 61 d2 9c}  //weight: 5, accuracy: Low
        $x_1_2 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

