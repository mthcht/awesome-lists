rule Backdoor_Linux_Adore_A_2147813592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Adore.A!xp"
        threat_id = "2147813592"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Adore"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "adore_hidefile" ascii //weight: 1
        $x_1_2 = "adore_makeroot" ascii //weight: 1
        $x_1_3 = "No luck, no adore" ascii //weight: 1
        $x_1_4 = "/proc/hide-%d" ascii //weight: 1
        $x_1_5 = "adore_hideproc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

