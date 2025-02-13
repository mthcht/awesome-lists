rule HackTool_Linux_Demonul_A_2147824981_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Demonul.A!xp"
        threat_id = "2147824981"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Demonul"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pornim demonul" ascii //weight: 2
        $x_1_2 = "ready pid is: %d" ascii //weight: 1
        $x_1_3 = "anacrond.c" ascii //weight: 1
        $x_1_4 = "NU poci, bye!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

