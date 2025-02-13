rule DDoS_Linux_Silly_A_2147833153_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Silly.A!xp"
        threat_id = "2147833153"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Silly"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "angry Vadims" ascii //weight: 1
        $x_1_2 = "Syntax: %s <host> <port> <spoof>" ascii //weight: 1
        $x_1_3 = "vadim.c" ascii //weight: 1
        $x_1_4 = "port %d spoofed as %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

