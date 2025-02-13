rule VirTool_MacOS_DiscordGo_B_2147888111_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MacOS/DiscordGo.B!MTB"
        threat_id = "2147888111"
        type = "VirTool"
        platform = "MacOS: "
        family = "DiscordGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "discordgo.User" ascii //weight: 1
        $x_1_2 = "discordgo.Intent" ascii //weight: 1
        $x_1_3 = "UserAvatarDecode" ascii //weight: 1
        $x_1_4 = "github.com/bwmarrin/discordgo" ascii //weight: 1
        $x_1_5 = "os/exec" ascii //weight: 1
        $x_1_6 = "DiscordGo/pkg/agent" ascii //weight: 1
        $x_1_7 = "github.com/gorilla/websocket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

