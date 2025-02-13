rule Trojan_MSIL_Matanbuchus_AAMK_2147888658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Matanbuchus.AAMK!MTB"
        threat_id = "2147888658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 03 8e 69 5d 7e ?? ?? 00 04 03 06 1a 58 4a 03 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 06 1a 58 4a 1b 58 1a 59 03 8e 69 5d 91 59 20 fe 00 00 00 58 18 58 20 00 01 00 00 5d d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

