rule VirTool_MSIL_Bladabindi_A_2147684745_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Bladabindi.A"
        threat_id = "2147684745"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "njRAT Downloaeder v" ascii //weight: 3
        $x_2_2 = "By njq8" ascii //weight: 2
        $x_1_3 = "[startup]" ascii //weight: 1
        $x_1_4 = "[links]" ascii //weight: 1
        $x_1_5 = "\\stub.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

