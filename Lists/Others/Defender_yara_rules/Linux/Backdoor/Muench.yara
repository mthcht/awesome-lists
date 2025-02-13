rule Backdoor_Linux_Muench_A_2147823254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Muench.A!xp"
        threat_id = "2147823254"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Muench"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Muench" ascii //weight: 1
        $x_1_2 = "backdoor.c" ascii //weight: 1
        $x_1_3 = "commands followed" ascii //weight: 1
        $x_1_4 = "/bin/sh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

