rule HackTool_Linux_PortScan_A_2147818626_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/PortScan.A!xp"
        threat_id = "2147818626"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "PortScan"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Usage: %s <b-block> <port> [c-block]" ascii //weight: 1
        $x_1_2 = "%s.%d.* (Totalu: %d)" ascii //weight: 1
        $x_1_3 = "pscan2.c" ascii //weight: 1
        $x_1_4 = "scan.log" ascii //weight: 1
        $x_1_5 = "Invalid IP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

