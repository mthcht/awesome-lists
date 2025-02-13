rule VirTool_Win64_Evilengesz_A_2147921759_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Evilengesz.A!MTB"
        threat_id = "2147921759"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Evilengesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ").addJsInject" ascii //weight: 1
        $x_1_2 = ".socksAuthMethod" ascii //weight: 1
        $x_1_3 = ").IsActiveHostname" ascii //weight: 1
        $x_1_4 = ").getPivot" ascii //weight: 1
        $x_1_5 = ").getTLSCertificate" ascii //weight: 1
        $x_1_6 = ").EnableProxy" ascii //weight: 1
        $x_1_7 = ").ReportCredentialsSubmitted" ascii //weight: 1
        $x_1_8 = ").GetScriptInject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

