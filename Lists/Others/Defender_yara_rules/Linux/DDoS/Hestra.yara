rule DDoS_Linux_Hestra_A_2147818617_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Hestra.A!xp"
        threat_id = "2147818617"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Hestra"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hestra.c" ascii //weight: 2
        $x_1_2 = "Usage: <hestra> <host> <port>" ascii //weight: 1
        $x_1_3 = "Extremely Dangerous tool" ascii //weight: 1
        $x_1_4 = "Fux0ring %s on port %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

