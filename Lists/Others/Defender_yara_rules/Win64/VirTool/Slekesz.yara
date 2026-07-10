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

rule VirTool_Win64_Slekesz_A_2147973281_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Slekesz.A"
        threat_id = "2147973281"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Slekesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 4c 24 58 48 89 44 24 60 48 8b 44 24 38 48 83 c0 18 48 89 44 24 40 48 8b [0-25] bf 16 00 00 00 ?? ?? ?? ?? ?? 41 b8 01 00 00 00 4d 89 c1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {48 8b 44 24 40 48 8b 00 48 83 c0 20 48 8b 00 48 8b 00 48 8b 00 48 83 c0 20 48 8b 00 44 0f 11 7c 24 48 e8 [0-17] 48 89}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

