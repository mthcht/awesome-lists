rule HackTool_MSIL_DiscordStealz_A_2147925003_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/DiscordStealz.A!MTB"
        threat_id = "2147925003"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordStealz"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "remote_admin_server.frm_discord.resources" ascii //weight: 1
        $x_1_2 = "file_manager" ascii //weight: 1
        $x_1_3 = "domain" ascii //weight: 1
        $x_1_4 = "System.Net.Sockets" ascii //weight: 1
        $x_1_5 = "files_client_to_server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

