rule DDoS_Linux_Flushot_A_2147817854_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Flushot.A!xp"
        threat_id = "2147817854"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Flushot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Remote Flushot" ascii //weight: 2
        $x_2_2 = "The Flu Hacking Group" ascii //weight: 2
        $x_2_3 = "usage:./flushot [Spoofed IP] [Destination IP] [of FLushot to Send]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

