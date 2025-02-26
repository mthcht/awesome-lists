rule Trojan_MSIL_GhostRat_ARG_2147934596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostRat.ARG!MTB"
        threat_id = "2147934596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 16 13 07 2b 14 11 06 11 07 11 05 11 07 91 1f 7f 5f d1 9d 11 07 17 58 13 07 11 07 11 04 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

