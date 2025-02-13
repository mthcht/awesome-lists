rule Trojan_MSIL_DelShad_ABFA_2147927590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DelShad.ABFA!MTB"
        threat_id = "2147927590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DelShad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 1a 58 4a 02 8e 69 5d 7e ?? 00 00 04 02 06 1a 58 4a 02 8e 69 5d 91 07 06 1a 58 4a 07 8e 69 5d 91 61 28 ?? ?? 00 06 02 06 1a 58 4a 1d 58 1c 59 02 8e 69 5d 91 59 20 fd 00 00 00 58 19 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

