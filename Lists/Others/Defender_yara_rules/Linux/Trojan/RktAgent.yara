rule Trojan_Linux_RktAgent_A_2147798893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/RktAgent.A!xp"
        threat_id = "2147798893"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "RktAgent"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/dev/proc/fuckit/config/rports" ascii //weight: 1
        $x_1_2 = "(H)idden programs configuration" ascii //weight: 1
        $x_1_3 = "(B)ackdoor password" ascii //weight: 1
        $x_1_4 = "FucKit RK by Cyrax" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

