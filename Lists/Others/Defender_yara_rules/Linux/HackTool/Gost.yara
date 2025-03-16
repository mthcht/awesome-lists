rule HackTool_Linux_Gost_A_2147896538_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Gost.A!MTB"
        threat_id = "2147896538"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Gost"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gost.Bypass" ascii //weight: 1
        $x_1_2 = "gost.sshConn" ascii //weight: 1
        $x_5_3 = "/go-gost/gosocks" ascii //weight: 5
        $x_5_4 = "/go-gost/tls-dissector" ascii //weight: 5
        $x_1_5 = "gost.h2Transporter" ascii //weight: 1
        $x_1_6 = "gost.Filter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule HackTool_Linux_Gost_B_2147928877_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Gost.B!MTB"
        threat_id = "2147928877"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Gost"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bypass.ParseBypass" ascii //weight: 1
        $x_1_2 = "sshd.RemoteForwardConn" ascii //weight: 1
        $x_1_3 = "/bypass/proto/bypass_grpc.pb.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Gost_C_2147936164_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Gost.C!MTB"
        threat_id = "2147936164"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Gost"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/home/ginuerzh/code/src/ginuerzh/gost/bypass.go" ascii //weight: 1
        $x_1_2 = "gost.udpTunnelConn.SetWriteDeadline" ascii //weight: 1
        $x_1_3 = "gost.quicCipherConn.WriteToUDP" ascii //weight: 1
        $x_1_4 = "main.parseBypass" ascii //weight: 1
        $x_1_5 = "main.parseIPRoutes" ascii //weight: 1
        $x_1_6 = "gost/cmd/gost/main.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

