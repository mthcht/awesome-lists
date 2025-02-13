rule HackTool_Linux_Jolt_A_2147833154_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Jolt.A!xp"
        threat_id = "2147833154"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Jolt"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jolt.c" ascii //weight: 1
        $x_1_2 = "usage: %s <dstaddr> <saddr> [number]" ascii //weight: 1
        $x_1_3 = "Jolt v1.0" ascii //weight: 1
        $x_1_4 = "spoofing from" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

