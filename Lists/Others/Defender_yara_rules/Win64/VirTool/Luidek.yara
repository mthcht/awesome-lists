rule VirTool_Win64_Luidek_A_2147808500_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Luidek.A!MTB"
        threat_id = "2147808500"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Luidek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 6c 24 ?? 48 8d [0-16] 48 89 ?? 24 [0-32] e8 [0-5] 48 8b [0-5] 48 89 ?? 24 48 c7 ?? 24 08 00 00 00 00 48 8b ?? 24 ?? 48 89 ?? 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "lupo/lupo-client/cmd.Response" ascii //weight: 1
        $x_1_3 = "lupo/lupo-client/core" ascii //weight: 1
        $x_1_4 = "lupo-server/core.Sessions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_Win64_Luidek_B_2147947264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Luidek.B"
        threat_id = "2147947264"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Luidek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lupo/lupo-client/cmd.Response" ascii //weight: 1
        $x_1_2 = "lupo/lupo-client/core" ascii //weight: 1
        $x_1_3 = "lupobackexecshowkillloadr" ascii //weight: 1
        $x_1_4 = "mattn/go-shellwords" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

