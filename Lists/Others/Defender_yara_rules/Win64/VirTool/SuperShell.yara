rule VirTool_Win64_SuperShell_A_2147903135_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SuperShell.A"
        threat_id = "2147903135"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SuperShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "agent\\main.cc" ascii //weight: 1
        $x_1_2 = "agent\\Terminal.cc" ascii //weight: 1
        $x_1_3 = "/reverse_ssh/" ascii //weight: 1
        $x_1_4 = "Agent::Agent entered" ascii //weight: 1
        $x_1_5 = "winpty_agent_process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

