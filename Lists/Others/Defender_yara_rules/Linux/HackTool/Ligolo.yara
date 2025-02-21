rule HackTool_Linux_Ligolo_A_2147890467_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ligolo.A!MTB"
        threat_id = "2147890467"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ligolo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "protocol.LigoloDecoder" ascii //weight: 1
        $x_1_2 = "/nicocha30/ligolo-ng/pkg/protocol" ascii //weight: 1
        $x_1_3 = "nicocha30/ligolo-ng/cmd/agent" ascii //weight: 1
        $x_1_4 = "nicocha30/ligolo-ng/pkg/relay" ascii //weight: 1
        $x_1_5 = "ListenAndServe" ascii //weight: 1
        $x_1_6 = "maxPayloadSizeForWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule HackTool_Linux_Ligolo_B_2147931813_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ligolo.B!MTB"
        threat_id = "2147931813"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ligolo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/nicocha30/ligolo-ng/cmd/proxy/app" ascii //weight: 1
        $x_1_2 = "/proxy.(*LigoloTunnel).HandleSession" ascii //weight: 1
        $x_1_3 = "/protocol.(*LigoloDecoder).Decode" ascii //weight: 1
        $x_1_4 = "/ligolo-ng/cmd/proxy/app.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Ligolo_C_2147934092_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ligolo.C!MTB"
        threat_id = "2147934092"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ligolo"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ligolo-ng/pkg/agent.NewUDPListener" ascii //weight: 1
        $x_1_2 = "(*LigoloDecoder).Decode" ascii //weight: 1
        $x_1_3 = "exploit/ligolo/ligolo-ng/cmd/agent/main.go" ascii //weight: 1
        $x_1_4 = "ligolo-ng/pkg/agent.(*Listener).ListenAndServe" ascii //weight: 1
        $x_1_5 = "smartping.CommandPinger" ascii //weight: 1
        $x_1_6 = "ligolo-ng/pkg/relay.StartRelay" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

