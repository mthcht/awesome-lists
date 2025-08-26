rule Trojan_Linux_Hidersock_SR9_2147950249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Hidersock.SR9"
        threat_id = "2147950249"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Hidersock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "socket" ascii //weight: 1
        $x_1_2 = "ioctl" ascii //weight: 1
        $x_2_3 = "Dropping to root shell" ascii //weight: 2
        $x_2_4 = "Hiding PID %u" ascii //weight: 2
        $x_2_5 = "Hiding TCPv4 port %hu" ascii //weight: 2
        $x_2_6 = "Hiding TCPv6 port %hu" ascii //weight: 2
        $x_2_7 = "Hiding UDPv4 port %hu" ascii //weight: 2
        $x_2_8 = "Hiding UDPv6 port %hu" ascii //weight: 2
        $x_2_9 = "Hiding file/dir %s" ascii //weight: 2
        $x_2_10 = "Hiding network PROMISC flag" ascii //weight: 2
        $x_2_11 = "Silently prohibiting module loading" ascii //weight: 2
        $x_2_12 = "killable Process %hu" ascii //weight: 2
        $x_2_13 = "Hide Module" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

