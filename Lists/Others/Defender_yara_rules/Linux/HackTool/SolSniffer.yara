rule HackTool_Linux_SolSniffer_A_2147836690_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/SolSniffer.A"
        threat_id = "2147836690"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "SolSniffer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "-- TCP/IP LOG -- TM: %s --" ascii //weight: 5
        $x_5_2 = "STAT: %s, %d pkts, %d bytes [%s]" ascii //weight: 5
        $x_5_3 = "Usage: %s [-d x] [-s] [-f] [-l] [-t] [-i interface] [-o file]" ascii //weight: 5
        $x_5_4 = "DL_PROMISC_PHYS" ascii //weight: 5
        $x_5_5 = "dlbindack:  DL_OK_ACK was not M_PCPROTO" ascii //weight: 5
        $x_5_6 = "filtering out telnet connections." ascii //weight: 5
        $x_5_7 = "filtering out rsh/rlogin connections." ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

