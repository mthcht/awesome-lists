rule HackTool_Linux_Nmap_Gen_2147799441_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Nmap.Gen"
        threat_id = "2147799441"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Nmap"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nmap scan report for %s" ascii //weight: 1
        $x_1_2 = "Some probes failed to send so results incomplete" ascii //weight: 1
        $x_1_3 = "receive UDP response. Please try again with -sSU" ascii //weight: 1
        $x_1_4 = "FingerPrintResultsIPv6" ascii //weight: 1
        $x_1_5 = "Starting IPv6 OS Scan..." ascii //weight: 1
        $x_1_6 = "Unable to obtain an Nsock pool" ascii //weight: 1
        $x_1_7 = "udp->protocol_id() == HEADER_TYPE_UDP" ascii //weight: 1
        $x_1_8 = "Unexpected Nsock event in response_reception_handler()" ascii //weight: 1
        $x_1_9 = "response_reception_handler(): Unknown status code %d" ascii //weight: 1
        $x_1_10 = "[%s] Retransmitting timed probes (rcvd_before=%u, rcvd_now=%u tim" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

