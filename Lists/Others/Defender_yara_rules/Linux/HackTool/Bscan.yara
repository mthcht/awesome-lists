rule HackTool_Linux_Bscan_A_2147826932_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Bscan.A!xp"
        threat_id = "2147826932"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Bscan"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "starting bscan" ascii //weight: 1
        $x_1_2 = "BSCAN EXITING ON SIGNAL %d" ascii //weight: 1
        $x_1_3 = "output -> %s.bscan%s" ascii //weight: 1
        $x_1_4 = "bscan forked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

