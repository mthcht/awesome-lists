rule Trojan_MSIL_Polyransom_SG_2147900165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Polyransom.SG!MTB"
        threat_id = "2147900165"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Polyransom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "set_UseShellExecute" ascii //weight: 1
        $x_2_2 = "ShiwWindow" ascii //weight: 2
        $x_1_3 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

