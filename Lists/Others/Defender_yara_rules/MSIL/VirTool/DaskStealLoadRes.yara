rule VirTool_MSIL_DaskStealLoadRes_2147765780_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/DaskStealLoadRes!MTB"
        threat_id = "2147765780"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DaskStealLoadRes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ButterFly.g.resources" ascii //weight: 1
        $x_1_2 = "ZorkGame.Properties" ascii //weight: 1
        $x_1_3 = "tEXtSoftware" ascii //weight: 1
        $x_1_4 = "System.Drawing.Bitmap" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

