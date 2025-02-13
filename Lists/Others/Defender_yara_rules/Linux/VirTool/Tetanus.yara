rule VirTool_Linux_Tetanus_B_2147817462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Linux/Tetanus.B!MTB"
        threat_id = "2147817462"
        type = "VirTool"
        platform = "Linux: Linux platform"
        family = "Tetanus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".cargo/registry/src/github.com-1ecc6299db9ec823" ascii //weight: 1
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

