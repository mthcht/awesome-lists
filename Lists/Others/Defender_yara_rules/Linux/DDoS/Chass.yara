rule DDoS_Linux_Chass_A_2147813594_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Chass.A!xp"
        threat_id = "2147813594"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Chass"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Beginning attack on chassis %s [%d packets]" ascii //weight: 2
        $x_1_2 = "Attack complete." ascii //weight: 1
        $x_1_3 = "Syntax: %s <chassis name> <num of packets>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

