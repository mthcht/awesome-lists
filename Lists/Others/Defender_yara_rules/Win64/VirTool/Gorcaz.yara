rule VirTool_Win64_Gorcaz_A_2147844468_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Gorcaz.A!MTB"
        threat_id = "2147844468"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Gorcaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cli/controller" ascii //weight: 1
        $x_1_2 = "cli/cmdopt/smbopt" ascii //weight: 1
        $x_1_3 = "github.com/Binject/" ascii //weight: 1
        $x_1_4 = "stager/connect.go" ascii //weight: 1
        $x_1_5 = "stager/register.go" ascii //weight: 1
        $x_1_6 = "stager/settlemsg.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

