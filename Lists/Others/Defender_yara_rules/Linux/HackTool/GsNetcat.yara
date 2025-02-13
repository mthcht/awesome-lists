rule HackTool_Linux_GsNetcat_A_2147918089_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/GsNetcat.A!MTB"
        threat_id = "2147918089"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "GsNetcat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_gs-netcat.c" ascii //weight: 1
        $x_1_2 = "GSOCKET_SOCKS_IP" ascii //weight: 1
        $x_1_3 = "jailshell" ascii //weight: 1
        $x_1_4 = "filetransfer.c" ascii //weight: 1
        $x_1_5 = "GS_daemonize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

