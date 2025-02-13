rule HackTool_MacOS_GsNetcat_A_2147918090_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/GsNetcat.A!MTB"
        threat_id = "2147918090"
        type = "HackTool"
        platform = "MacOS: "
        family = "GsNetcat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_gs-netcat.c" ascii //weight: 1
        $x_1_2 = "GSOCKET_SOCKS_IP" ascii //weight: 1
        $x_1_3 = "filetransfer.c" ascii //weight: 1
        $x_1_4 = "GS_daemonize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

