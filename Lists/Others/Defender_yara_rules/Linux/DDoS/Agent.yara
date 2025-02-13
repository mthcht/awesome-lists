rule DDoS_Linux_Agent_A_2147818791_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Agent.A!xp"
        threat_id = "2147818791"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Agent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gethostbyname" ascii //weight: 1
        $x_1_2 = "FAST_Flood" ascii //weight: 1
        $x_1_3 = "CmdShell" ascii //weight: 1
        $x_1_4 = "Admin_ServerConnectCliv" ascii //weight: 1
        $x_1_5 = "ICMP_Flood" ascii //weight: 1
        $x_1_6 = "SetDNSHeadPcS_i" ascii //weight: 1
        $x_1_7 = "SYN_Flood" ascii //weight: 1
        $x_1_8 = "UDP_Flood" ascii //weight: 1
        $x_1_9 = "TCP_Flood" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

