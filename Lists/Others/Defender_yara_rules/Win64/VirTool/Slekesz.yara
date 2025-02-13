rule VirTool_Win64_Slekesz_A_2147907205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Slekesz.A!MTB"
        threat_id = "2147907205"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Slekesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".keylog" ascii //weight: 1
        $x_1_2 = "slack.Upload" ascii //weight: 1
        $x_1_3 = ").RemoteAddr" ascii //weight: 1
        $x_1_4 = "Slackor/pkg/command.GetCommand" ascii //weight: 1
        $x_1_5 = "Slackor/agent.go" ascii //weight: 1
        $x_1_6 = ".encrypt" ascii //weight: 1
        $x_1_7 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_8 = ".socksAuthMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

