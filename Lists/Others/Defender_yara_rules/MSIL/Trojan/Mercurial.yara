rule Trojan_MSIL_Mercurial_RDA_2147895600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mercurial.RDA!MTB"
        threat_id = "2147895600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mercurial"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 06 11 05 93 07 11 05 93 6f 24 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

