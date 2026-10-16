rule VirTool_Win32_Tetanus_A_2147816254_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tetanus.A!MTB"
        threat_id = "2147816254"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tetanus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cargo/registry/src/" ascii //weight: 1
        $x_1_2 = "AgentTaskcommand" ascii //weight: 1
        $x_1_3 = "background_tasks" ascii //weight: 1
        $x_1_4 = "killable" ascii //weight: 1
        $x_1_5 = "user_outputcompleted" ascii //weight: 1
        $x_1_6 = "enc_keydec_key" ascii //weight: 1
        $x_1_7 = "MythicFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Tetanus_B_2147980471_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tetanus.B"
        threat_id = "2147980471"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tetanus"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AgentTaskcommand" ascii //weight: 1
        $x_1_2 = "user_outputcompleted" ascii //weight: 1
        $x_1_3 = "enc_keydec_key" ascii //weight: 1
        $x_1_4 = "MythicFile" ascii //weight: 1
        $x_1_5 = "KillJob" ascii //weight: 1
        $x_1_6 = "intervaljitter" ascii //weight: 1
        $x_1_7 = "CheckinResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

