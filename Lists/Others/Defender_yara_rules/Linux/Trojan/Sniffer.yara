rule Trojan_Linux_Sniffer_X_2147849904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Sniffer.X"
        threat_id = "2147849904"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Sniffer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/bin/sh" ascii //weight: 1
        $x_1_2 = "pcap_setfilter" ascii //weight: 1
        $x_1_3 = "pcap_open_live" ascii //weight: 1
        $x_1_4 = "libpcap.so" ascii //weight: 1
        $x_1_5 = {49 89 c8 41 0f b6 14 ?? 41 83 e0 03 42 32 14 03 80 ea 65 74 09 83 c0 01 88 14 37 48 63 f0 48 83 c1 01 48 83 f9 40 75 d8}  //weight: 1, accuracy: Low
        $x_1_6 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

