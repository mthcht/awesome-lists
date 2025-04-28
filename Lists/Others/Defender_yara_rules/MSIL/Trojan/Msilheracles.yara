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

rule Trojan_MSIL_Msilheracles_PGM_2147939899_1
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
        $x_2_1 = "lUq9SRfYH8KkEzNKFzQp9saTIKdX0DmnRh3LO3KaRMI=" ascii //weight: 2
        $x_2_2 = "wZk5N6r9FvS2IYMR3QQpsQ==" ascii //weight: 2
        $x_1_3 = "FD74AFFB3FADC2FF30B30C2053C3169175F48BD3B282B2E7A0FC6E436F39B366" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

