rule HackTool_Linux_ElfPatcher_A_2147816094_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/ElfPatcher.A!xp"
        threat_id = "2147816094"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "ElfPatcher"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "infect_me_baby()) : %s" ascii //weight: 2
        $x_1_2 = "Infecting host file at offset" ascii //weight: 1
        $x_1_3 = "cyneox.tmp" ascii //weight: 1
        $x_1_4 = "usage:%s file_to_infect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

