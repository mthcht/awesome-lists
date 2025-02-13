rule Backdoor_Linux_XorDDoSRootkit_A_2147818256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/XorDDoSRootkit.A"
        threat_id = "2147818256"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "XorDDoSRootkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "firewall_acceptip" ascii //weight: 1
        $x_1_2 = "firewall_dropip" ascii //weight: 1
        $x_1_3 = "unfirewall_dropip" ascii //weight: 1
        $x_1_4 = "unfirewall_acceptip" ascii //weight: 1
        $x_1_5 = "unhide_udp6_port" ascii //weight: 1
        $x_1_6 = "hide_udp4_port" ascii //weight: 1
        $x_1_7 = "hide_udp6_port" ascii //weight: 1
        $x_1_8 = "hide_tcp4_port" ascii //weight: 1
        $x_1_9 = "hide_tcp6_port" ascii //weight: 1
        $x_1_10 = "hidden_tcp6_ports" ascii //weight: 1
        $x_1_11 = "hide_file" ascii //weight: 1
        $x_2_12 = "kO_copy_from_user" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

