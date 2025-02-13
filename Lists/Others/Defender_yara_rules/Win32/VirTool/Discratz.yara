rule VirTool_Win32_Discratz_A_2147848030_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Discratz.A!MTB"
        threat_id = "2147848030"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Discratz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "github.com/bwmarrin/discordgo" ascii //weight: 1
        $x_1_2 = "github.com/codeuk/discord-rat" ascii //weight: 1
        $x_1_3 = "github.com/gorilla/websocket" ascii //weight: 1
        $x_1_4 = "api.ipify.org" ascii //weight: 1
        $x_1_5 = "cdn.discordapp.com" ascii //weight: 1
        $x_1_6 = "os/exec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

