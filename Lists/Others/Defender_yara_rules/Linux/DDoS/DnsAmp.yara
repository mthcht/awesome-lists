rule DDoS_Linux_DnsAmp_A_2147818624_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/DnsAmp.A!xp"
        threat_id = "2147818624"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "DnsAmp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "tcp stop" ascii //weight: 2
        $x_2_2 = "DNS_FLOOD" ascii //weight: 2
        $x_1_3 = "RENT_FLOOD" ascii //weight: 1
        $x_1_4 = "TCP1_FLOOD" ascii //weight: 1
        $x_1_5 = "dns_server_count" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule DDoS_Linux_DnsAmp_B_2147825978_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/DnsAmp.B!xp"
        threat_id = "2147825978"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "DnsAmp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {30 a0 b1 0f 00 00 ba 00 30 85 e0 01 30 43 e2 00 00 84 e0 02 c0 a0 e1 00 20 d3 e5 01 30 43 e2 2e 00 52 e3 00 c0 c0 05 00 20 c0 15 00 c0 a0 03 01 c0 8c 12 01 10 51}  //weight: 1, accuracy: High
        $x_1_2 = {11 01 30 a0 e3 00 30 c4 e5 10 40 bd e8 1e ff 2f e1 b8 f9 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

