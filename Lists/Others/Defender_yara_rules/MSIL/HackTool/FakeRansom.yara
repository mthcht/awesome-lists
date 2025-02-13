rule HackTool_MSIL_FakeRansom_RDA_2147851688_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/FakeRansom.RDA!MTB"
        threat_id = "2147851688"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FakeRansom"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dde2e71f-629a-4ea9-a799-0f603609fe28" ascii //weight: 1
        $x_1_2 = "FakeRansomware" ascii //weight: 1
        $x_1_3 = "kthxbai" ascii //weight: 1
        $x_1_4 = "BlackWindow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

