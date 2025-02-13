rule VirTool_Win64_Cheselesz_A_2147919852_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Cheselesz.A!MTB"
        threat_id = "2147919852"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Cheselesz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/exec/exec_windows.go" ascii //weight: 1
        $x_1_2 = ".sendDNSQuery" ascii //weight: 1
        $x_1_3 = ".shutdown" ascii //weight: 1
        $x_1_4 = "cmd/shell/chashell.go" ascii //weight: 1
        $x_1_5 = ").RemoteAddr" ascii //weight: 1
        $x_1_6 = ".sendInfoPacket" ascii //weight: 1
        $x_1_7 = ").GetHostname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

