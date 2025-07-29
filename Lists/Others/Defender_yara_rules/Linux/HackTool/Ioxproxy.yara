rule HackTool_Linux_Ioxproxy_A_2147947810_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Ioxproxy.A!MTB"
        threat_id = "2147947810"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Ioxproxy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iox/netio.ForwardUDP" ascii //weight: 1
        $x_1_2 = "iox/operate.local2LocalUDP" ascii //weight: 1
        $x_1_3 = "iox/operate.remote2remoteTCP" ascii //weight: 1
        $x_1_4 = "iox/netio.ForwardUnconnectedUDP" ascii //weight: 1
        $x_1_5 = "iox/operate.serverHandshake" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

