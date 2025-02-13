rule VirTool_Win32_Dakdosc_A_2147778716_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Dakdosc.A!MTB"
        threat_id = "2147778716"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Dakdosc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DaaC2/cmd/agent" ascii //weight: 1
        $x_1_2 = "DaaC2/pkg/c2agent/execwindows" ascii //weight: 1
        $x_1_3 = "bwmarrin/discordgo" ascii //weight: 1
        $x_1_4 = "discordgo.EventHandler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

