rule DDoS_Win32_UDPFlood_2147496579_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/UDPFlood"
        threat_id = "2147496579"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "UDPFlood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "%d.%d.%d.%d.in-addr.arpa." ascii //weight: 1
        $x_1_2 = "DhcpNameServer" ascii //weight: 1
        $x_1_3 = "IcmpSendEcho" ascii //weight: 1
        $x_1_4 = {bb 00 7d 00 00 8d ?? ?? 8d ?? ?? 6a 01 6a 1c 51 50 6a 00 6a 00 ff 75 ?? ff 75 ?? ff 55 ?? 4b 75 e4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

