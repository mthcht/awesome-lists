rule Backdoor_Linux_cd00r_A_2147836890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/cd00r.A"
        threat_id = "2147836890"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "cd00r"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "cdr_open_door" ascii //weight: 5
        $x_5_2 = "cdr_noise" ascii //weight: 5
        $x_5_3 = "pcap.h" ascii //weight: 5
        $x_5_4 = "bpf.h" ascii //weight: 5
        $x_5_5 = "Sender mismatch" ascii //weight: 5
        $x_5_6 = "Port %d is good as code part %d" ascii //weight: 5
        $x_5_7 = "pcap_lookupnet: %s" ascii //weight: 5
        $x_5_8 = "pcap_open_live: %s" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

