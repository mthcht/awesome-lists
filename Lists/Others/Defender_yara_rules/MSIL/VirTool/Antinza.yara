rule VirTool_MSIL_Antinza_B_2147814113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Antinza.B!MTB"
        threat_id = "2147814113"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Antinza"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ExecuteAssemblyContext" ascii //weight: 1
        $x_1_2 = "MythicJob" ascii //weight: 1
        $x_1_3 = "CheckinResponse" ascii //weight: 1
        $x_1_4 = "UploadResponseData" ascii //weight: 1
        $x_1_5 = "MythicTask" ascii //weight: 1
        $x_1_6 = "MythicResponseResult" ascii //weight: 1
        $x_1_7 = "Athena.Config.HTTP" ascii //weight: 1
        $x_1_8 = "Athena.Socks" ascii //weight: 1
        $x_1_9 = "MythicUploadJob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

