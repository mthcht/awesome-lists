rule HackTool_Linux_MSFPerlShell_A_2147766170_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPerlShell.A"
        threat_id = "2147766170"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPerlShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "perl" wide //weight: 1
        $x_1_2 = "=new IO::Socket::INET" wide //weight: 1
        $x_1_3 = "STDIN->fdopen" wide //weight: 1
        $x_1_4 = "$~->fdopen(" wide //weight: 1
        $x_1_5 = "if($_=~ /(.*)/){system $1;" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_MSFPerlShell_B_2147766171_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MSFPerlShell.B"
        threat_id = "2147766171"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MSFPerlShell"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "perl" wide //weight: 1
        $x_1_2 = "use IO::Socket::SSL;" wide //weight: 1
        $x_1_3 = "=fork;exit,if(" wide //weight: 1
        $x_1_4 = "while(sysread($c,$i,8192)){syswrite(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

