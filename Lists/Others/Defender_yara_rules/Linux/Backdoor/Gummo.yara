rule Backdoor_Linux_Gummo_A_2147817852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Gummo.A!xp"
        threat_id = "2147817852"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Gummo"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "gummo backdoor" ascii //weight: 2
        $x_2_2 = "Welcome To Gummo Backdoor Server" ascii //weight: 2
        $x_1_3 = "rewt" ascii //weight: 1
        $x_1_4 = "wipeout" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

