rule HackTool_Linux_Prtscan_A_2147756873_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Prtscan.A!MTB"
        threat_id = "2147756873"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Prtscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src/smack1.c" ascii //weight: 1
        $x_1_2 = "SSL[HEARTBLEED]" ascii //weight: 1
        $x_1_3 = "masscan --nmap" ascii //weight: 1
        $x_1_4 = "/etc/masscan/masscan.conf" ascii //weight: 1
        $x_1_5 = "github.com/robertdavidgraham/masscan" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule HackTool_Linux_Prtscan_B_2147834366_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Prtscan.B!MTB"
        threat_id = "2147834366"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Prtscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {77 77 77 2e 6c 79 73 61 74 6f 72 2e 6c 69 75 2e 73 65 2f 7e 70 65 6e 2f 70 6e 73 63 61 6e [0-16] 43 6f 6d 6d 61 6e 64 20 6c 69 6e 65}  //weight: 1, accuracy: Low
        $x_1_2 = "PNScan, version %s - %s %s" ascii //weight: 1
        $x_1_3 = "TCP port scanner" ascii //weight: 1
        $x_1_4 = "Lookup and print hostnames" ascii //weight: 1
        $x_1_5 = "gethostbyname" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

