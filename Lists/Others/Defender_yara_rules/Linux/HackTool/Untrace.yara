rule HackTool_Linux_Untrace_A_2147826928_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Untrace.A!xp"
        threat_id = "2147826928"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Untrace"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/var/log/wtmp" ascii //weight: 1
        $x_1_2 = "/var/run/utmp" ascii //weight: 1
        $x_1_3 = "records from utmp/wtmp" ascii //weight: 1
        $x_1_4 = "Untrace by SeCToR-X" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

