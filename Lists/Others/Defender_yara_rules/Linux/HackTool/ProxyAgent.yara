rule HackTool_Linux_ProxyAgent_A_2147922948_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ProxyAgent.A!MTB"
        threat_id = "2147922948"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ProxyAgent"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "main.hideProxyPID" ascii //weight: 2
        $x_1_2 = "main.checkPassword" ascii //weight: 1
        $x_1_3 = "main.isPortInUse" ascii //weight: 1
        $x_1_4 = "openPort" ascii //weight: 1
        $x_1_5 = "proxyForURL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

