rule Backdoor_MSIL_SpyGateRAT_GG_2147776492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyGateRAT.GG!MTB"
        threat_id = "2147776492"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGateRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\Red Devil SpyGate-RAT" ascii //weight: 10
        $x_1_2 = "cam.DirectX.Capture" ascii //weight: 1
        $x_1_3 = "sqlite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

