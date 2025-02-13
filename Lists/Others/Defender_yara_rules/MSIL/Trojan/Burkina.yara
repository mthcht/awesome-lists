rule Trojan_MSIL_Burkina_A_2147766346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Burkina.A!MTB"
        threat_id = "2147766346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Burkina"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "AAAA4AgvYC" ascii //weight: 10
        $x_10_2 = "AEAAAAAAAIs4H" ascii //weight: 10
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "ReverseString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

