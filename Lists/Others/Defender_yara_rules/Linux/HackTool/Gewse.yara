rule HackTool_Linux_Gewse_A_2147824648_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Gewse.A!xp"
        threat_id = "2147824648"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Gewse"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gewse.c" ascii //weight: 2
        $x_1_2 = "usage: %s <host> <of connex>" ascii //weight: 1
        $x_1_3 = "Flooding %s identd %d times" ascii //weight: 1
        $x_1_4 = "Killing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

