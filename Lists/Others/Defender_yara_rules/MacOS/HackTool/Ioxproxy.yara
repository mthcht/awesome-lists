rule HackTool_MacOS_Ioxproxy_A_2147947811_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Ioxproxy.A!MTB"
        threat_id = "2147947811"
        type = "HackTool"
        platform = "MacOS: "
        family = "Ioxproxy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
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

