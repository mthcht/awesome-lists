rule HackTool_MacOS_Dnscat_A_2147927642_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MacOS/Dnscat.A!MTB"
        threat_id = "2147927642"
        type = "HackTool"
        platform = "MacOS: "
        family = "Dnscat"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "driver_dns.c" ascii //weight: 1
        $x_1_2 = "dns_to_packet" ascii //weight: 1
        $x_1_3 = "tunnel_drivers/driver_dns.c" ascii //weight: 1
        $x_1_4 = "drivers/command/command_packet.c" ascii //weight: 1
        $x_1_5 = "_controller_kill_all_sessions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

