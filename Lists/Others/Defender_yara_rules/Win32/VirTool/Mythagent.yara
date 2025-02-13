rule VirTool_Win32_Mythagent_A_2147794105_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Mythagent.A"
        threat_id = "2147794105"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mythagent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "self.getTaskings(" ascii //weight: 1
        $x_1_2 = "self.processTaskings(" ascii //weight: 1
        $x_1_3 = "self.postResponses(" ascii //weight: 1
        $x_1_4 = "self.agent_config" ascii //weight: 1
        $x_1_5 = "\"Jitter\":" ascii //weight: 1
        $x_1_6 = "\"PayloadUUID\":" ascii //weight: 1
        $x_1_7 = "task[\"task_id\"]" ascii //weight: 1
        $x_1_8 = "file_browser[\"files\"]" ascii //weight: 1
        $x_1_9 = "self.postMessageAndRetrieveResponse" ascii //weight: 1
        $x_1_10 = ".CreateRemoteThread(" ascii //weight: 1
        $x_1_11 = "passedKilldate(" ascii //weight: 1
        $x_1_12 = "\"ProxyHost\":" ascii //weight: 1
        $x_1_13 = "self.agentSleep()" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

