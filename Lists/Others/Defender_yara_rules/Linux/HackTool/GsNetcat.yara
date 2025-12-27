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

rule HackTool_Linux_GsNetcat_SR3_2147953958_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/GsNetcat.SR3"
        threat_id = "2147953958"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "GsNetcat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "reverse shell" ascii //weight: 2
        $x_2_2 = "backdoor " ascii //weight: 2
        $x_2_3 = "backshell" ascii //weight: 2
        $x_2_4 = "/bin/sh" ascii //weight: 2
        $x_2_5 = "/bin/bash" ascii //weight: 2
        $x_2_6 = "gs-netcat -" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

