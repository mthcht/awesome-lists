rule VirTool_MacOS_MythicMerlin_A_2147852468_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/MythicMerlin.A!MTB"
        threat_id = "2147852468"
        type = "VirTool"
        platform = "MacOS: "
        family = "MythicMerlin"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ne0nd0g/merlin-agent/clients.(*MerlinClient).Auth" ascii //weight: 1
        $x_1_2 = "merlin-agent/commands.miniDump" ascii //weight: 1
        $x_1_3 = "Ne0nd0g/merlin/pkg/messages.Base" ascii //weight: 1
        $x_1_4 = "merlin-agent/commands.ExecuteShellcodeQueueUserAPC" ascii //weight: 1
        $x_1_5 = "merlin/pkg/jobs.Shellcode" ascii //weight: 1
        $x_1_6 = "merlin/pkg/core.RandStringBytesMaskImprSrc" ascii //weight: 1
        $x_1_7 = "MerlinClient" ascii //weight: 1
        $x_1_8 = "Ne0nd0g/merlin-agent/socks.sendToSOCKSServer" ascii //weight: 1
        $x_1_9 = "merlin-agent/commands/execute.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

