rule VirTool_Win32_Shrub_A_2147757121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shrub.A!MTB"
        threat_id = "2147757121"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shrub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gorsh/internal/sshocks" ascii //weight: 1
        $x_1_2 = "flattenfloat32float64gctracegorsh" ascii //weight: 1
        $x_1_3 = "gorsh.c2" ascii //weight: 1
        $x_1_4 = "HoleySocks/pkg/holeysocks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Shrub_A_2147757121_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Shrub.A!MTB"
        threat_id = "2147757121"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Shrub"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gorsh/internal/cmds" ascii //weight: 1
        $x_1_2 = "gorsh/internal/enum" ascii //weight: 1
        $x_1_3 = "gorsh/internal/myconn" ascii //weight: 1
        $x_1_4 = "gorsh/internal/fetch._downloadFile" ascii //weight: 1
        $x_1_5 = "gorsh/internal/enum.Sherlock" ascii //weight: 1
        $x_1_6 = "audibleblink/gorsh/internal/enum.WinPeas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

