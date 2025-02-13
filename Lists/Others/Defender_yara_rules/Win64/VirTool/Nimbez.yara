rule VirTool_Win64_Nimbez_A_2147844993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Nimbez.A!MTB"
        threat_id = "2147844993"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Nimbez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "domain" ascii //weight: 1
        $x_1_2 = "username" ascii //weight: 1
        $x_1_3 = "password" ascii //weight: 1
        $x_1_4 = "hostname" ascii //weight: 1
        $x_1_5 = "userAgent" ascii //weight: 1
        $x_1_6 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_7 = "@uac-bypass" ascii //weight: 1
        $x_1_8 = "@persist-spe" ascii //weight: 1
        $x_1_9 = "@persist-run" ascii //weight: 1
        $x_1_10 = "@screenshot" ascii //weight: 1
        $x_1_11 = "@clipboard" ascii //weight: 1
        $x_1_12 = "@upload" ascii //weight: 1
        $x_1_13 = "@download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

