rule HackTool_MacOS_Gost_A_2147921857_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Gost.A!MTB"
        threat_id = "2147921857"
        type = "HackTool"
        platform = "MacOS: "
        family = "Gost"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gost.http2Conn" ascii //weight: 1
        $x_1_2 = "gost.h2Transporter" ascii //weight: 1
        $x_1_3 = "main.parseBypass" ascii //weight: 1
        $x_1_4 = "gost.Bypass" ascii //weight: 1
        $x_1_5 = "gost.sshRemoteForwardConnector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule HackTool_MacOS_Gost_B_2147943309_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Gost.B!MTB"
        threat_id = "2147943309"
        type = "HackTool"
        platform = "MacOS: "
        family = "Gost"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "go-gost/core/logger.Logger]).IsRegistered" ascii //weight: 1
        $x_1_2 = "main.buildAPIService.AccessLogOption.func2" ascii //weight: 1
        $x_1_3 = "gost/x/handler/tunnel.parseTunnelID" ascii //weight: 1
        $x_1_4 = "go-gost/relay.NewPrivateTunnelID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

