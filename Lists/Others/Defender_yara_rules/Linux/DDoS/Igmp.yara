rule DDoS_Linux_Igmp_A_2147822421_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Igmp.A!xp"
        threat_id = "2147822421"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Igmp"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spoofing attack" ascii //weight: 2
        $x_1_2 = "<got root" ascii //weight: 1
        $x_1_3 = "igmp-8+frag attacks" ascii //weight: 1
        $x_1_4 = "<spoof host> <target host> <number>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

