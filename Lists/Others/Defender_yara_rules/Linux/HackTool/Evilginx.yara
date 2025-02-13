rule HackTool_Linux_Evilginx_A_2147907542_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Evilginx.A!MTB"
        threat_id = "2147907542"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Evilginx"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kgretzky/evilginx" ascii //weight: 1
        $x_1_2 = "handlePhishlets" ascii //weight: 1
        $x_1_3 = "PhishLure" ascii //weight: 1
        $x_1_4 = "GetPhishHosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

