rule DDoS_Linux_Rose_A_2147830769_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Rose.A!xp"
        threat_id = "2147830769"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Rose"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rose attack" ascii //weight: 1
        $x_1_2 = "NewDawn2.c" ascii //weight: 1
        $x_1_3 = "ICMP fragments" ascii //weight: 1
        $x_1_4 = "<victim> [source]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

