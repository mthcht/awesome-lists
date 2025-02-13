rule VirTool_MSIL_Runpe_A_2147692862_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Runpe.A"
        threat_id = "2147692862"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Runpe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPE" ascii //weight: 1
        $x_1_2 = "PEBPatcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

