rule HackTool_Linux_Midav_A_2147826929_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Midav.A!xp"
        threat_id = "2147826929"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Midav"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Vadim on port %d spoofed as %s" ascii //weight: 1
        $x_1_2 = "Syntax: %s <host> <port> <size> <packets>" ascii //weight: 1
        $x_1_3 = "Syntax: %s <host> <port> <spoof>" ascii //weight: 1
        $x_1_4 = "Flooding" ascii //weight: 1
        $x_2_5 = "Vadim v" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

