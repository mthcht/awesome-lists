rule DDoS_Linux_Trigemini_A_2147827555_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Trigemini.A!xp"
        threat_id = "2147827555"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Trigemini"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inject_iphdr" ascii //weight: 1
        $x_1_2 = "T:UINs:h:d:p:q:l:t:" ascii //weight: 1
        $x_1_3 = "trigemini.c" ascii //weight: 1
        $x_1_4 = "TCP Attack" ascii //weight: 1
        $x_1_5 = "TriGemini. [TCP/UDP/ICMP Packet flooder]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

