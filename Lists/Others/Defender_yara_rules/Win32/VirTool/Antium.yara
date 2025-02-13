rule VirTool_Win32_Antium_A_2147823375_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Antium.A!MTB"
        threat_id = "2147823375"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Antium"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "antnium/pkg/client." ascii //weight: 1
        $x_1_2 = "antnium/pkg/wingman.MakeWingman" ascii //weight: 1
        $x_1_3 = "UpstreamWs).Connect" ascii //weight: 1
        $x_1_4 = "UpstreamManager).ReconnectWebsocket" ascii //weight: 1
        $x_1_5 = "DownstreamLocaltcp).ListenAddr" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

