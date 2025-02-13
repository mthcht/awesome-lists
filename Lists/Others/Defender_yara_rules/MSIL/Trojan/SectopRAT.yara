rule Trojan_MSIL_SectopRAT_RDA_2147901009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SectopRAT.RDA!MTB"
        threat_id = "2147901009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SectopRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "outdoor_activity_app_with_manager" ascii //weight: 1
        $x_1_2 = "Unicom" ascii //weight: 1
        $x_1_3 = "Midea" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

