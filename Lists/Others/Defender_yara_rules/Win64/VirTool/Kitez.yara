rule VirTool_Win64_Kitez_A_2147838154_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kitez.A!MTB"
        threat_id = "2147838154"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kitez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 89 44 24 36 48 89 4c 24 40 48 89 5c 24 38 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 c7 00 00 00 00 00 48 8b 5c 24 40 48 8d ?? ?? ?? ?? ?? 48 89 c7}  //weight: 1, accuracy: Low
        $x_1_2 = {48 89 d9 48 89 c3 48 8b 84 24 00 01 00 00 e8 ?? ?? ?? ?? 66 89 44 24 2c 44 0f 11 7c 24 53}  //weight: 1, accuracy: Low
        $x_1_3 = {48 83 ec 08 48 89 2c 24 48 8d 2c 24 e8 ?? ?? ?? ?? 84 c0 75 27 0f 1f 44 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_Kitez_C_2147838155_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Kitez.C!MTB"
        threat_id = "2147838155"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Kitez"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd/util.NewTask" ascii //weight: 1
        $x_1_2 = "cmd/malwareUtil.Connect" ascii //weight: 1
        $x_1_3 = "cmd/util.MalConf" ascii //weight: 1
        $x_1_4 = "cmd/util.(*InitialChecks).SetPid" ascii //weight: 1
        $x_1_5 = "cmd/malwareUtil.postRequest" ascii //weight: 1
        $x_1_6 = "cmd/malwareUtil/malwareUtil.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

