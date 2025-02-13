rule HackTool_Linux_Wingate_A_2147820330_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Wingate.A!xp"
        threat_id = "2147820330"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Wingate"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "wgate.c" ascii //weight: 2
        $x_1_2 = "Wingate found: %s" ascii //weight: 1
        $x_1_3 = "Wingate Seeker by KByte" ascii //weight: 1
        $x_1_4 = "Netproxy>" ascii //weight: 1
        $x_1_5 = "use: %s infile outfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

