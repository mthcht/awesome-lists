rule VirTool_Win64_Godosesz_A_2147904476_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Godosesz.A!MTB"
        threat_id = "2147904476"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Godosesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "domain" ascii //weight: 1
        $x_1_2 = ").Hostname" ascii //weight: 1
        $x_1_3 = ".Cookies" ascii //weight: 1
        $x_1_4 = "SetSessionTicket" ascii //weight: 1
        $x_1_5 = ".socksauthmethod" ascii //weight: 1
        $x_1_6 = "useragent" ascii //weight: 1
        $x_1_7 = "shutdown" ascii //weight: 1
        $x_1_8 = "CaptureScreen" ascii //weight: 1
        $x_1_9 = "GetClipboard" ascii //weight: 1
        $x_1_10 = "namedpipe" ascii //weight: 1
        $x_1_11 = "net/http.persistConnWriter.Write" ascii //weight: 1
        $x_1_12 = "ChannelFileSend" ascii //weight: 1
        $x_1_13 = "addConn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

