rule Backdoor_Linux_Agent_E_2147816105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Agent.E!xp"
        threat_id = "2147816105"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Agent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sendicmp.c" ascii //weight: 1
        $x_1_2 = "opencall.c" ascii //weight: 1
        $x_1_3 = "icmp_sid" ascii //weight: 1
        $x_1_4 = "icmp-backdoor %s, starting server..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

