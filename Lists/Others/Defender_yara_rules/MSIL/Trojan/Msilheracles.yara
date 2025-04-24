rule Trojan_MSIL_Msilheracles_PGM_2147939899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Msilheracles.PGM!MTB"
        threat_id = "2147939899"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Msilheracles"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IUdltHGYdgPZeIaNNIrJvXmLld.kjvvEHyOmySFEYdlfEyMxRIzhOn" ascii //weight: 1
        $x_4_2 = "eOmnWaBTvMCwNFQcwlZASvyEWJR" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

