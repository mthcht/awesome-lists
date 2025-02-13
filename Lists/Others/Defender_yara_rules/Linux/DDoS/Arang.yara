rule DDoS_Linux_Arang_A_2147827558_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Arang.A!xp"
        threat_id = "2147827558"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Arang"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DoS by ArchAng3" ascii //weight: 2
        $x_1_2 = "inetd_DoS.c" ascii //weight: 1
        $x_1_3 = "0f Death - Member" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

